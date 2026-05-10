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
	for data := range inputChan {
		if data == nil {
			return
		}

		if !(connectionFactory.CanBeFilled() && connections.BufferCheck()) {
			metaUtils.LogIngest("Connections filled")
			continue
		}

		ev := connections.AcquireSocketDataEvent()
		if err := func() error {
			globalReaderLock.Lock()
			defer globalReaderLock.Unlock()
			globalReader.Reset(data[:eventAttributesSize])
			return binary.Read(globalReader, bcc.GetHostByteOrder(), &ev.Attr)
		}(); err != nil {
			slog.Error("Failed to decode received data", "error", err)
			connections.ReleaseSocketDataEvent(ev)
			continue
		}

		bytesSent := ev.Attr.Bytes_sent

		eventAttributesLogicalSize := 45

		if len(data) > eventAttributesLogicalSize {
			copy(ev.Msg[:], data[eventAttributesLogicalSize:eventAttributesLogicalSize+int(utils.Abs(bytesSent))])
		}

		connId := ev.Attr.ConnId

		_, ok := ignorePortsMap[connId.Port]
		if ignorePorts && ok {
			connections.ReleaseSocketDataEvent(ev)
			metaUtils.LogIngest("Ignoring data for ignore port",
				"fd", connId.Fd,
				"id", connId.Id,
				"timestamp", connId.Conn_start_ns,
				"rc", ev.Attr.ReadEventsCount,
				"wc", ev.Attr.WriteEventsCount)
			continue
		}

		connectionFactory.CreateIfNotExists(connId)

		if metaUtils.IngestLogsEnabled() {
			previewLen := min(32, utils.Abs(bytesSent))
			metaUtils.LogIngest("Got data",
				"fd", connId.Fd,
				"id", connId.Id,
				"timestamp", connId.Conn_start_ns,
				"ip", connId.Ip,
				"port", connId.Port,
				"data", string(ev.Msg[:previewLen]),
				"rc", ev.Attr.ReadEventsCount,
				"wc", ev.Attr.WriteEventsCount,
				"ssl", ev.Attr.Ssl,
				"bytesSent", bytesSent)
		}

		connectionFactory.SendEvent(connId, ev)
		connections.UpdateBufferSize(uint64(utils.Abs(bytesSent)))
	}
}
