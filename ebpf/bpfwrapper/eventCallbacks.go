package bpfwrapper

import (
	"bytes"
	"encoding/binary"
	"log/slog"
	"time"
	"unsafe"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/connections"
	"github.com/akto-api-security/mirroring-api-logging/ebpf/structs"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/utils"
	metaUtils "github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

var (
	logSocketDataUserspace   = false
	socketDataInboundCount   uint64
	socketDataInboundLastLog time.Time
	captureLoopback          = false
)

const socketDataUserspaceLogInterval = 10 * time.Second

// noteSocketDataInboundBeforeSend counts decoded socket_data records handed to the connection
// factory (same goroutine as the socket_data ringbuf reader — no lock.)
func noteSocketDataInboundBeforeSend() {
	if !logSocketDataUserspace {
		return
	}
	socketDataInboundCount++
	now := time.Now()
	if socketDataInboundLastLog.IsZero() {
		socketDataInboundLastLog = now
		return
	}
	d := now.Sub(socketDataInboundLastLog)
	if d < socketDataUserspaceLogInterval {
		return
	}
	slog.Warn("socket_data events reaching userspace (before SendEvent)",
		"countInWindow", socketDataInboundCount,
		"window", d.String())
	socketDataInboundCount = 0
	socketDataInboundLastLog = now
}

func SocketOpenEventCallback(inputChan chan []byte, connectionFactory *connections.Factory) {
	reader := &bytes.Reader{}

	for data := range inputChan {
		if data == nil {
			return
		}

		if !connectionFactory.CanBeFilled() {
			slog.Warn("Connections filled")
			continue
		}

		var event structs.SocketOpenEvent
		reader.Reset(data)
		err := binary.Read(reader, binary.NativeEndian, &event)
		if err != nil {
			slog.Error("Failed to decode received data on socket open", "error", err)
			continue
		}
		connId := event.ConnId

		if !captureLoopback && isLoopbackIP(connId.Ip) {
			metaUtils.LogIngest("Skipping loopback socket open",
				"fd", connId.Fd, "id", connId.Id, "ip", connId.Ip)
			continue
		}

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
	reader := &bytes.Reader{}

	for data := range inputChan {
		if data == nil {
			return
		}
		var event structs.SocketCloseEvent
		reader.Reset(data)
		err := binary.Read(reader, binary.NativeEndian, &event)
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
)

func init() {
	metaUtils.InitVar("TRAFFIC_IGNORE_DEFAULT_PORTS", &ignorePorts)
	metaUtils.InitVar("TRAFFIC_LOG_SOCKET_DATA_USERSPACE", &logSocketDataUserspace)
	metaUtils.InitVar("TRAFFIC_CAPTURE_LOOPBACK", &captureLoopback)
}

// isLoopbackIP returns true when the IP (stored as a u32 in network byte order
// read on a little-endian host) falls in 127.0.0.0/8.
func isLoopbackIP(ip uint32) bool {
	return (ip & 0xFF) == 0x7F
}

func min(a, b int32) int32 {
	if a < b {
		return a
	}
	return b
}

func SocketDataEventCallback(inputChan chan []byte, connectionFactory *connections.Factory) {
	reader := &bytes.Reader{}

	const eventAttributesLogicalSize = 45

	for data := range inputChan {
		if data == nil {
			return
		}

		if !(connectionFactory.CanBeFilled() && connections.BufferCheck()) {
			slog.Warn("Connections filled")
			continue
		}

		var attr structs.SocketDataEventAttr
		reader.Reset(data[:eventAttributesSize])
		if err := binary.Read(reader, binary.NativeEndian, &attr); err != nil {
			slog.Error("Failed to decode received data", "error", err)
			continue
		}

		bytesSent := attr.Bytes_sent
		n := int(utils.Abs(bytesSent))
		connId := attr.ConnId

		if !captureLoopback && isLoopbackIP(connId.Ip) {
			continue
		}

		_, ok := ignorePortsMap[connId.Port]
		if ignorePorts && ok {
			metaUtils.LogIngest("Ignoring data for ignore port",
				"fd", connId.Fd,
				"id", connId.Id,
				"timestamp", connId.Conn_start_ns,
				"rc", attr.ReadEventsCount,
				"wc", attr.WriteEventsCount)
			continue
		}

		var payload []byte
		if n > 0 {
			if len(data) < eventAttributesLogicalSize+n {
				slog.Error("socket data ring record too short", "len", len(data), "need", eventAttributesLogicalSize+n)
				continue
			}
			payload = make([]byte, n)
			copy(payload, data[eventAttributesLogicalSize:eventAttributesLogicalSize+n])
		}

		connectionFactory.CreateIfNotExists(connId)

		noteSocketDataInboundBeforeSend()
		connectionFactory.SendEvent(connId, &structs.SocketDataPayload{Attr: attr, Data: payload})
		connections.UpdateBufferSize(uint64(n))

		if logSocketDataUserspace && n > 0 {
			previewLen := min(32, int32(n))
			slog.Warn("Got data",
				"fd", connId.Fd,
				"id", connId.Id,
				"timestamp", connId.Conn_start_ns,
				"ip", connId.Ip,
				"port", connId.Port,
				"data", string(payload[:previewLen]),
				"rc", attr.ReadEventsCount,
				"wc", attr.WriteEventsCount,
				"ssl", attr.Ssl,
				"bytesSent", bytesSent)
		}
	}
}
