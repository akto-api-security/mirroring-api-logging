package bpfwrapper

import (
	"bytes"
	"encoding/binary"
	"log/slog"
	"sync"
	"time"
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

		if metaUtils.SystemCPUIngestPaused() {
			continue
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

		if metaUtils.SystemCPUIngestPaused() {
			continue
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
	ignorePorts              = true
	globalReader             = &bytes.Reader{}
	globalReaderLock         sync.Mutex
	logSocketDataSubmitStats bool
)

func init() {
	metaUtils.InitVar("TRAFFIC_IGNORE_DEFAULT_PORTS", &ignorePorts)
	metaUtils.InitVar("TRAFFIC_LOG_BPF_SOCKET_DATA_SUBMITS", &logSocketDataSubmitStats)
}

func min(a, b int32) int32 {
	if a < b {
		return a
	}
	return b
}

const socketDataInboundLogInterval = 10 * time.Second

// SocketDataEventCallback runs one goroutine per perf map (see ProbeChannel.Start); these
// fields are only touched from that goroutine — no lock on the hot path.
var (
	socketDataInboundCount   uint64
	socketDataInboundLastLog time.Time // zero until first event arms the window
)

// noteSocketDataInboundBeforeSend counts socket_data perf records that are about to be
// handed to the connection factory (after decode, port filter, and payload copy).
func noteSocketDataInboundBeforeSend() {

	if !logSocketDataSubmitStats {
		return
	}

	socketDataInboundCount++
	now := time.Now()
	if socketDataInboundLastLog.IsZero() {
		socketDataInboundLastLog = now
		return
	}
	d := now.Sub(socketDataInboundLastLog)
	if d < socketDataInboundLogInterval {
		return
	}
	slog.Warn("socket_data events reaching eventCallback",
		"countInWindow", socketDataInboundCount,
		"window", d.String())
	socketDataInboundCount = 0
	socketDataInboundLastLog = now
}

func SocketDataEventCallback(inputChan chan []byte, connectionFactory *connections.Factory) {
	for data := range inputChan {
		if data == nil {
			return
		}

		if metaUtils.SystemCPUIngestPaused() {
			continue
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

		bytesSent := attr.Bytes_sent
		n := int(utils.Abs(bytesSent))

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

		// Perf layout: attr then raw msg; must match BPF struct layout (see SocketDataEventAttr).
		const eventAttributesLogicalSize = 45
		msgOff := eventAttributesLogicalSize
		var payload []byte
		if n > 0 {
			if len(data) < msgOff+n {
				slog.Error("socket data perf record too short", "len", len(data), "need", msgOff+n)
				continue
			}
			payload = make([]byte, n)
			copy(payload, data[msgOff:msgOff+n])
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
				"bytesSent", bytesSent)
		}

		// This is a debug log, so only log if the log level is debug
		//noteSocketDataInboundBeforeSend()
		connectionFactory.SendEvent(connId, &structs.SocketDataPayload{Attr: attr, Data: payload})
		connections.UpdateBufferSize(uint64(n))
	}
}
