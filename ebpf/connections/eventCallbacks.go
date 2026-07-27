package connections

import (
	"log/slog"
	"unsafe"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/structs"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/utils"
	metaUtils "github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

// These callbacks were moved out of the bcc-bound bpfwrapper package: they use
// only unsafe.Pointer casts (no bcc), so living here lets them — and the
// per-event pipeline they drive — be exercised directly in tests without CGo.
// bpfwrapper wires them into its ProbeChannels as the event-loop handlers.

var (
	// this also includes space lost in padding.
	eventAttributesSize = int(unsafe.Sizeof(structs.SocketDataEventAttr{}))
	openEventSize       = int(unsafe.Sizeof(structs.SocketOpenEvent{}))
	closeEventSize      = int(unsafe.Sizeof(structs.SocketCloseEvent{}))
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
}

func SocketOpenEventCallback(inputChan chan []byte, connectionFactory *Factory) {

	for data := range inputChan {
		if data == nil {
			return
		}

		if !connectionFactory.CanBeFilled() {
			metaUtils.LogIngest("Connections filled")
			continue
		}

		if len(data) < openEventSize {
			slog.Error("Received data smaller than socket open event", "len", len(data), "want", openEventSize)
			continue
		}
		// Pointer cast into data[] — no reflection, no lock, and crucially NO
		// struct copy. event aliases the raw record; the pointer keeps data[]
		// alive until the worker reads it.
		event := (*structs.SocketOpenEvent)(unsafe.Pointer(&data[0]))
		connId := event.ConnId
		if metaUtils.IsIngestLogsEnabled() {
			metaUtils.LogIngest("Received socket open event",
				"fd", connId.Fd,
				"id", connId.Id,
				"timestamp", connId.Conn_start_ns,
				"raddr", connId.Raddr,
				"rport", connId.Rport)
		}
		connectionFactory.CreateIfNotExists(connId)
		connectionFactory.SendEvent(connId, event)
	}
}

func SocketCloseEventCallback(inputChan chan []byte, connectionFactory *Factory) {
	for data := range inputChan {
		if data == nil {
			return
		}
		if len(data) < closeEventSize {
			slog.Error("Received data smaller than socket close event", "len", len(data), "want", closeEventSize)
			continue
		}
		event := (*structs.SocketCloseEvent)(unsafe.Pointer(&data[0]))
		connId := event.ConnId
		if metaUtils.IsIngestLogsEnabled() {
			metaUtils.LogIngest("Received close on",
				"fd", connId.Fd,
				"id", connId.Id,
				"timestamp", connId.Conn_start_ns,
				"raddr", connId.Raddr,
				"rport", connId.Rport)
		}
		connectionFactory.SendEvent(connId, event)
	}
}

func SocketDataEventCallback(inputChan chan []byte, connectionFactory *Factory) {
	metaUtils.Pipeline.InputChanCap.Store(int64(cap(inputChan)))
	var eventCount int64
	for data := range inputChan {
		if data == nil {
			return
		}

		if !(connectionFactory.CanBeFilled()) {
			metaUtils.LogIngest("Connections filled")
			continue
		}

		// The kernel always submits at least the fixed attribute region
		// (sizeof(struct)-MAX_MSG_SIZE == eventAttributesSize == 72 bytes on
		// both sides, host byte order), so we read Attr with a direct memory
		// cast instead of binary.Read: no lock, no reflection, no copy. The Msg
		// payload is NOT copied here — the raw data[] slice is handed to the
		// worker as-is and the payload is retained by reference downstream.
		if len(data) < eventAttributesSize {
			slog.Error("Received data smaller than event attributes", "len", len(data), "want", eventAttributesSize)
			continue
		}
		attr := (*structs.SocketDataEventAttr)(unsafe.Pointer(&data[0]))

		bytesSent := attr.Bytes_sent
		connId := attr.ConnId

		_, ok := ignorePortsMap[connId.Rport]
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

		if metaUtils.IsIngestLogsEnabled() {
			var dataStr string
			if n := int(utils.Abs(bytesSent)); structs.MsgOffset < len(data) {
				end := structs.MsgOffset + int(min(32, int32(n)))
				if end > len(data) {
					end = len(data)
				}
				dataStr = string(data[structs.MsgOffset:end])
			}
			metaUtils.LogIngest("Got data",
				"fd", connId.Fd,
				"id", connId.Id,
				"timestamp", connId.Conn_start_ns,
				"msg_seq", attr.MsgSeq,
				"rc", attr.ReadEventsCount,
				"wc", attr.WriteEventsCount,
				"raddr", connId.Raddr,
				"rport", connId.Rport,
				"data", dataStr,
				"ssl", attr.Ssl,
				"bytesSent", bytesSent)
		}

		metaUtils.Pipeline.EventsReceived.Add(1)
		eventCount++
		if eventCount%1000 == 0 {
			metaUtils.Pipeline.InputChanLen.Store(int64(len(inputChan)))
		}
		connectionFactory.SendDataEvent(connId, &data)
	}
}
