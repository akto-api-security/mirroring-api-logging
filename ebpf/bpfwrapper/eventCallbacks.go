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

		var event structs.SocketOpenEvent
		err := func() error {
			globalReaderLock.Lock()
			defer globalReaderLock.Unlock()
			globalReader.Reset(data)
			return binary.Read(globalReader, bcc.GetHostByteOrder(), &event)
		}()
		if err != nil {
			slog.Error("Failed to decode received data on socket open", "error", err)
			continue
		}
		connId := event.ConnId
		metaUtils.LogIngest("Received socket open event",
			"fd", connId.Fd,
			"id", connId.Id,
			"timestamp", connId.Conn_start_ns,
			"raddr", connId.Raddr,
			"rport", connId.Rport)
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
		err := func() error {
			globalReaderLock.Lock()
			defer globalReaderLock.Unlock()
			globalReader.Reset(data)
			return binary.Read(globalReader, bcc.GetHostByteOrder(), &event)
		}()
		if err != nil {
			slog.Error("Failed to decode received data on socket close", "error", err)
			continue
		}

		connId := event.ConnId
		metaUtils.LogIngest("Received close on",
			"fd", connId.Fd,
			"id", connId.Id,
			"timestamp", connId.Conn_start_ns,
			"raddr", connId.Raddr,
			"rport", connId.Rport)
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

		event := structs.GetSocketDataEvent()

		// The kernel always submits at least the fixed attribute region
		// (sizeof(struct)-MAX_MSG_SIZE == eventAttributesSize == 72 bytes on
		// both sides, host byte order), so we decode Attr with a direct memory
		// cast instead of binary.Read: no lock, no reflection, just a copy. The
		// Msg payload (which may be mostly empty) is copied separately below.
		if len(data) < eventAttributesSize {
			slog.Error("Received data smaller than event attributes", "len", len(data), "want", eventAttributesSize)
			structs.ReleaseSocketDataEvent(event)
			continue
		}
		event.Attr = *(*structs.SocketDataEventAttr)(unsafe.Pointer(&data[0]))

		bytesSent := event.Attr.Bytes_sent

		// The 3 bytes are being lost in padding, thus, not taking them into consideration.
		// msg_seq (u32=4 bytes) added after direction shifts msg[] offset by 4
		eventAttributesLogicalSize := 68

		if len(data) > eventAttributesLogicalSize {
			copy(event.Msg[:], data[eventAttributesLogicalSize:eventAttributesLogicalSize+int(utils.Abs(bytesSent))])
		}

		connId := event.Attr.ConnId

		_, ok := ignorePortsMap[connId.Rport]
		if ignorePorts && ok {
			metaUtils.LogIngest("Ignoring data for ignore port",
				"fd", connId.Fd,
				"id", connId.Id,
				"timestamp", connId.Conn_start_ns,
				"rc", event.Attr.ReadEventsCount,
				"wc", event.Attr.WriteEventsCount)
			continue
		}

		event.Attr.ReadEventsCount = event.Attr.ReadEventsCount
		event.Attr.WriteEventsCount = event.Attr.WriteEventsCount

		connectionFactory.CreateIfNotExists(connId)

		if metaUtils.IsIngestLogsEnabled() {
			dataStr := string(event.Msg[:min(32, utils.Abs(bytesSent))])
			metaUtils.LogIngest("Got data",
				"fd", connId.Fd,
				"id", connId.Id,
				"timestamp", connId.Conn_start_ns,
				"msg_seq", event.Attr.MsgSeq,
				"rc", event.Attr.ReadEventsCount,
				"wc", event.Attr.WriteEventsCount,
				"raddr", connId.Raddr,
				"rport", connId.Rport,
				"data", dataStr,
				"ssl", event.Attr.Ssl,
				"bytesSent", bytesSent)
		}

		metaUtils.Pipeline.EventsReceived.Add(1)
		eventCount++
		if eventCount%1000 == 0 {
			metaUtils.Pipeline.InputChanLen.Store(int64(len(inputChan)))
		}
		connectionFactory.SendEvent(connId, event)
	}
}
