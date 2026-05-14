package bpfwrapper

import (
	"log/slog"
	"time"
	"unsafe"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/connections"
	"github.com/akto-api-security/mirroring-api-logging/ebpf/structs"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/utils"
	metaUtils "github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

var (
	openEventSize  = int(unsafe.Sizeof(structs.SocketOpenEvent{}))
	closeEventSize = int(unsafe.Sizeof(structs.SocketCloseEvent{}))
	// Go struct size (48) — includes 3 bytes of trailing padding after Ssl.
	// The C struct sends at least this many bytes for every data event.
	eventAttributesSize = int(unsafe.Sizeof(structs.SocketDataEventAttr{}))

	ignorePortsMap = map[uint16]bool{
		9092: true, 19092: true, 29092: true, // kafka
		2181:  true, // zookeeper
		27017: true, // mongo
		6379:  true, // redis
	}
	ignorePorts bool = true
)

func init() {
	metaUtils.InitVar("TRAFFIC_IGNORE_DEFAULT_PORTS", &ignorePorts)
	metaUtils.InitVar("TRAFFIC_LOG_BPF_SOCKET_DATA_SUBMITS", &logSocketDataSubmitStats)
}

func SocketOpenEventCallback(data []byte, connectionFactory *connections.Factory) {
	if !connectionFactory.CanBeFilled() {
		metaUtils.LogIngest("Connections filled")
		return
	}

	if len(data) < openEventSize {
		slog.Error("socket open event too short", "len", len(data), "need", openEventSize)
		return
	}

	ev := *(*structs.SocketOpenEvent)(unsafe.Pointer(&data[0]))
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

func SocketCloseEventCallback(data []byte, connectionFactory *connections.Factory) {
	if len(data) < closeEventSize {
		slog.Error("socket close event too short", "len", len(data), "need", closeEventSize)
		return
	}

	ev := *(*structs.SocketCloseEvent)(unsafe.Pointer(&data[0]))
	connId := ev.ConnId
	metaUtils.LogIngest("Received close on",
		"fd", connId.Fd,
		"id", connId.Id,
		"timestamp", connId.Conn_start_ns,
		"ip", connId.Ip,
		"port", connId.Port)
	connectionFactory.SendEvent(connId, ev)
}

const socketDataInboundLogInterval = 10 * time.Second

var (
	socketDataInboundCount   uint64
	socketDataInboundLastLog time.Time
	logSocketDataSubmitStats = true
)

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

// eventAttributesLogicalSize is the C-side offset of the msg field in socket_data_event_t.
// It equals 45 bytes (the struct fields before msg[], without Go's trailing alignment padding).
const eventAttributesLogicalSize = 45

func SocketDataEventCallback(data []byte, connectionFactory *connections.Factory) {
	if metaUtils.SystemCPUIngestPaused() {
		return
	}

	if !(connectionFactory.CanBeFilled() && connections.BufferCheck()) {
		metaUtils.LogIngest("Connections filled")
		return
	}

	if len(data) < eventAttributesSize {
		slog.Error("socket data event too short", "len", len(data), "need", eventAttributesSize)
		return
	}

	attr := *(*structs.SocketDataEventAttr)(unsafe.Pointer(&data[0]))

	bytesSent := attr.Bytes_sent
	n := int(utils.Abs(bytesSent))

	connId := attr.ConnId
	_, ok := ignorePortsMap[connId.Port]
	if ignorePorts && ok {
		if metaUtils.IngestLogsEnabled() {
			metaUtils.LogIngest("Ignoring data for ignore port",
				"fd", connId.Fd,
				"id", connId.Id,
				"timestamp", connId.Conn_start_ns,
				"rc", attr.ReadEventsCount,
				"wc", attr.WriteEventsCount)
		}
		return
	}

	msgOff := eventAttributesLogicalSize
	var payload []byte
	if n > 0 {
		if len(data) < msgOff+n {
			slog.Error("socket data ring record too short", "len", len(data), "need", msgOff+n)
			return
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

	noteSocketDataInboundBeforeSend()
	connectionFactory.SendEvent(connId, &structs.SocketDataPayload{Attr: attr, Data: payload})
	connections.UpdateBufferSize(uint64(n))
}
