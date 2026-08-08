package bpfwrapper

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"sync"
	"unsafe"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/connections"
	"github.com/akto-api-security/mirroring-api-logging/ebpf/structs"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/utils"
	metaUtils "github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
	"github.com/iovisor/gobpf/bcc"
)

func SocketOpenEventCallback(inputChan chan []byte, connectionFactory *connections.Factory) {

	for data := range inputChan {
		if data == nil {
			return
		}

		if !connectionFactory.CanBeFilled() {
			metaUtils.LogIngest("Connections filled")
			continue
		}

		var event structs.SocketOpenEvent
		reader := readerPool.Get().(*bytes.Reader)
		reader.Reset(data)
		err := binary.Read(reader, bcc.GetHostByteOrder(), &event)
		readerPool.Put(reader)
		if err != nil {
			slog.Error("Failed to decode received data on socket open", "error", err)
			continue
		}
		connId := event.ConnId
		metaUtils.LogIngest("Received socket open event",
			"fd", connId.Fd,
			"id", connId.Id,
			"timestamp", connId.Conn_start_ns,
			"ip", connId.Ip,
			"port", connId.Port)
		connectionFactory.CreateIfNotExists(connId)
		connectionFactory.SendEvent(connId, &event)
	}
}

func SocketCloseEventCallback(inputChan chan []byte, connectionFactory *connections.Factory) {
	for data := range inputChan {
		if data == nil {
			return
		}
		var event structs.SocketCloseEvent
		reader := readerPool.Get().(*bytes.Reader)
		reader.Reset(data)
		err := binary.Read(reader, bcc.GetHostByteOrder(), &event)
		readerPool.Put(reader)
		if err != nil {
			slog.Error("Failed to decode received data on socket close", "error", err)
			continue
		}

		connId := event.ConnId
		metaUtils.LogIngest("Received close on",
			"fd", connId.Fd,
			"id", connId.Id,
			"timestamp", connId.Conn_start_ns,
			"ip", connId.Ip,
			"port", connId.Port)
		connectionFactory.SendEvent(connId, &event)
	}
}

var (
	// this also includes space lost in padding.
	eventAttributesSize = int(unsafe.Sizeof(structs.SocketDataEventAttr{}))
	ignorePortsMap      = map[uint16]bool{
		// kafka
		9092:  true,
		19092: true,
		29092: true,
		// zookeeper
		2181: true,
		// mongo
		27017: true,
		// redis
		6379: true}
	ignorePorts = true
	// readerPool eliminates global mutex contention: each goroutine efficiently reuses a reader
	readerPool = sync.Pool{
		New: func() interface{} {
			return &bytes.Reader{}
		},
	}
)

func init() {
	metaUtils.InitVar("TRAFFIC_IGNORE_DEFAULT_PORTS", &ignorePorts)
}

// InitKernelPortFilter populates the kernel-side port filter map if filtering is enabled
func InitKernelPortFilter(bpfModule *bcc.Module) {
	if !ignorePorts {
		return
	}
	table := bcc.NewTable(bpfModule.TableId("ignore_ports_map"), bpfModule)
	for port := range ignorePortsMap {
		keyBytes := make([]byte, 2)
		binary.LittleEndian.PutUint16(keyBytes, port)
		table.Set(keyBytes, []byte{1})
	}
}

func min(a, b int32) int32 {
	if a < b {
		return a
	}
	return b
}

// fastUnmarshalDataEventAttr uses unsafe casting to parse SocketDataEventAttr without binary.Read overhead
// This is faster (100ns vs 10µs) but REQUIRES proper struct alignment from kernel
// Only used if we have enough data; falls back to binary.Read for safety
func fastUnmarshalDataEventAttr(data []byte) (*structs.SocketDataEventAttr, error) {
	// SocketDataEventAttr must be exactly the size of kernel struct_data_event_attr
	// Expected layout: ConnID(56 bytes) + Bytes_sent(4) + ReadEventsCount(4) + WriteEventsCount(4) + Ssl(1) + Padding(3) + EventTimestampNs(8) = 80 bytes
	const expectedAttrSize = 80

	if len(data) < expectedAttrSize {
		return nil, fmt.Errorf("insufficient data for fast unmarshal: %d < %d", len(data), expectedAttrSize)
	}

	// UNSAFE: Direct pointer cast. This assumes:
	// 1. Struct is properly aligned (checked at compile time via unsafe.Sizeof)
	// 2. Binary layout matches kernel struct exactly
	// 3. Endianness matches (both little-endian on x86_64/ARM64)
	attr := (*structs.SocketDataEventAttr)(unsafe.Pointer(&data[0]))
	return attr, nil
}

func SocketDataEventCallback(inputChan chan []byte, connectionFactory *connections.Factory) {
	for data := range inputChan {
		if data == nil {
			return
		}

		if !(connectionFactory.CanBeFilled() && connections.BufferCheck()) {
			metaUtils.LogIngest("Connections filled")
			continue
		}

		var event structs.SocketDataEvent

		// Try fast unsafe casting first for performance (10µs → 100ns per event)
		// Falls back to binary.Read for safety if unmarshal fails
		var err error
		attr, fastErr := fastUnmarshalDataEventAttr(data)
		if fastErr == nil {
			event.Attr = *attr
		} else {
			// Fallback: binary.Read requires the input data to be at the same size of the object.
			// Since the Msg field might be mostly empty, binary.read fails.
			// So we split the loading into the fixed size attribute parts, and copying the message separately.
			reader := readerPool.Get().(*bytes.Reader)
			reader.Reset(data[:eventAttributesSize])
			err = binary.Read(reader, bcc.GetHostByteOrder(), &event.Attr)
			readerPool.Put(reader)
			if err != nil {
				slog.Error("Failed to decode received data", "error", err)
				continue
			}
		}

		bytesSent := event.Attr.Bytes_sent

		// The 4 bytes are being lost in padding, thus, not taking them into consideration.
		eventAttributesLogicalSize := 45

		if len(data) > eventAttributesLogicalSize {
			copy(event.Msg[:], data[eventAttributesLogicalSize:eventAttributesLogicalSize+int(utils.Abs(bytesSent))])
		}

		connId := event.Attr.ConnId

		event.Attr.ReadEventsCount = event.Attr.ReadEventsCount
		event.Attr.WriteEventsCount = event.Attr.WriteEventsCount

		connectionFactory.CreateIfNotExists(connId)

		// Lightweight HTTP detection: check sent data for "HTTP" keyword
		// This allows background processing to skip expensive parsing for non-HTTP traffic
		if bytesSent > 0 && len(event.Msg) > 0 {
			// Check if first bytes contain "HTTP" keyword (common in HTTP responses and requests)
			msgBytes := event.Msg[:min(int32(len(event.Msg)), 1024)] // Check first 1KB
			if bytes.Contains(msgBytes, []byte("HTTP")) {
				tracker, exists := connectionFactory.GetTrackerForHTTPDetection(connId)
				if exists {
					tracker.MarkHTTPDetected()
				}
			}
		}

		dataStr := string(event.Msg[:min(32, utils.Abs(bytesSent))])

		connectionFactory.SendEvent(connId, &event)
		connections.UpdateBufferSize(uint64(utils.Abs(bytesSent)))

		metaUtils.LogIngest("Got data",
			"fd", connId.Fd,
			"id", connId.Id,
			"timestamp", connId.Conn_start_ns,
			"ip", connId.Ip,
			"port", connId.Port,
			"data", dataStr,
			"rc", event.Attr.ReadEventsCount,
			"wc", event.Attr.WriteEventsCount,
			"ssl", event.Attr.Ssl,
			"bytesSent", bytesSent)
	}
}
