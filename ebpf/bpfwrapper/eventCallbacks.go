package bpfwrapper

import (
	"bytes"
	"encoding/binary"
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

		var ev structs.SocketOpenEvent
		err := func() error {
			globalReaderLock.Lock()
			defer globalReaderLock.Unlock()
			globalReader.Reset(data)
			return binary.Read(globalReader, bcc.GetHostByteOrder(), &ev)
		}()
		if err != nil {
			slog.Error("Failed to decode received data on socket open", "error", err)
			continue
		}
		connId := ev.ConnId
		metaUtils.LogIngest("Received socket open event",
			"fd", connId.Fd,
			"id", connId.Id,
			"timestamp", connId.Conn_start_ns,
			"ip", connId.Ip,
			"port", connId.Port)
		connectionFactory.CreateIfNotExists(connId)
		connectionFactory.SendEvent(connId, ev)
	}
}

func SocketCloseEventCallback(inputChan chan []byte, connectionFactory *connections.Factory) {
	for data := range inputChan {
		if data == nil {
			return
		}
		var ev structs.SocketCloseEvent
		err := func() error {
			globalReaderLock.Lock()
			defer globalReaderLock.Unlock()
			globalReader.Reset(data)
			return binary.Read(globalReader, bcc.GetHostByteOrder(), &ev)
		}()
		if err != nil {
			slog.Error("Failed to decode received data on socket close", "error", err)
			continue
		}

		connId := ev.ConnId
		metaUtils.LogIngest("Received close on",
			"fd", connId.Fd,
			"id", connId.Id,
			"timestamp", connId.Conn_start_ns,
			"ip", connId.Ip,
			"port", connId.Port)
		connectionFactory.SendEvent(connId, ev)
	}
}

var (
	eventAttributesSize = int(unsafe.Sizeof(structs.SocketDataEventAttr{}))
	ignorePortsMap      = map[uint16]bool{
		9092:  true,
		19092: true,
		29092: true,
		2181:  true,
		27017: true,
		6379:  true}
	ignorePorts      = true
	globalReader     = &bytes.Reader{}
	globalReaderLock sync.Mutex
)

func init() {
	metaUtils.InitVar("TRAFFIC_IGNORE_DEFAULT_PORTS", &ignorePorts)
}

func min(a, b int32) int32 {
	if a < b {
		return a
	}
	return b
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

		var attr structs.SocketDataEventAttr
		if err := func() error {
			globalReaderLock.Lock()
			defer globalReaderLock.Unlock()
			globalReader.Reset(data[:eventAttributesSize])
			return binary.Read(globalReader, bcc.GetHostByteOrder(), &attr)
		}(); err != nil {
			slog.Error("Failed to decode received data", "error", err)
			continue
		}

		n := int(utils.Abs(attr.Bytes_sent))
		msgOff := int(unsafe.Offsetof(structs.SocketDataEvent{}.Msg))
		var payload []byte
		if n > 0 {
			if len(data) < msgOff+n {
				slog.Error("socket data perf record too short", "len", len(data), "need", msgOff+n)
				continue
			}
			// Single copy from perf ring into owned memory; tracker holds this slice until flush
			// (no extra copy into a fixed [30720]byte Msg field).
			payload = make([]byte, n)
			copy(payload, data[msgOff:msgOff+n])
		}

		connId := attr.ConnId

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

		connectionFactory.CreateIfNotExists(connId)

		if metaUtils.IngestLogsEnabled() && n > 0 {
			previewLen := min(32, int32(n))
			metaUtils.LogIngest("Got data",
				"fd", connId.Fd,
				"id", connId.Id,
				"timestamp", connId.Conn_start_ns,
				"ip", connId.Ip,
				"port", connId.Port,
				"data", string(payload[:previewLen]),
				"rc", attr.ReadEventsCount,
				"wc", attr.WriteEventsCount,
				"ssl", attr.Ssl,
				"bytesSent", attr.Bytes_sent)
		}

		connectionFactory.SendEvent(connId, &connections.SocketDataPayload{Attr: attr, Data: payload})
		connections.UpdateBufferSize(uint64(n))
	}
}
