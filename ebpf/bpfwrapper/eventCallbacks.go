package bpfwrapper

import (
	"bytes"
	"encoding/binary"
	"log"
	"unsafe"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/connections"
	"github.com/akto-api-security/mirroring-api-logging/ebpf/structs"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/utils"
	"github.com/iovisor/gobpf/bcc"
)

func SocketOpenEventCallback(inputChan chan []byte, connectionFactory *connections.Factory) {

	for data := range inputChan {
		if data == nil {
			return
		}

		if !connectionFactory.CanBeFilled() {
			utils.LogIngest("Connections filled")
			continue
		}

		var event structs.SocketOpenEvent
		if err := binary.Read(bytes.NewReader(data), bcc.GetHostByteOrder(), &event); err != nil {
			log.Printf("Failed to decode received data on socket open: %+v", err)
			continue
		}
		connId := event.ConnId
		utils.LogIngest("Received open fd: %v id: %v ts: %v ip: %v port: %v\n", connId.Fd, connId.Id, connId.Conn_start_ns, connId.Ip, connId.Port)
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
		if err := binary.Read(bytes.NewReader(data), bcc.GetHostByteOrder(), &event); err != nil {
			log.Printf("Failed to decode received data on socket close: %+v", err)
			continue
		}

		connId := event.ConnId
		utils.LogIngest("Received close on: fd: %v id: %v ts: %v ip: %v port: %v\n", connId.Fd, connId.Id, connId.Conn_start_ns, connId.Ip, connId.Port)
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
)

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
			utils.LogIngest("Connections filled")
			continue
		}

		var event structs.SocketDataEvent

		// binary.Read require the input data to be at the same size of the object.
		// Since the Msg field might be mostly empty, binary.read fails.
		// So we split the loading into the fixed size attribute parts, and copying the message separately.

		// fmt.Printf("data: %v\n", data)

		if err := binary.Read(bytes.NewReader(data[:eventAttributesSize]), bcc.GetHostByteOrder(), &event.Attr); err != nil {
			utils.LogIngest("Failed to decode received data: %+v", err)
			continue
		}

		bytesSent := event.Attr.Bytes_sent

		// The 4 bytes are being lost in padding, thus, not taking them into consideration.
		eventAttributesLogicalSize := 45

		if len(data) > eventAttributesLogicalSize {
			copy(event.Msg[:], data[eventAttributesLogicalSize:eventAttributesLogicalSize+int(utils.Abs(bytesSent))])
		}

		connId := event.Attr.ConnId

		_, ok := ignorePortsMap[connId.Port]
		if ok {
			utils.LogIngest("Ignoring data for ignore port fd: %v id: %v ts: %v rc: %v wc: %v\n", connId.Fd, connId.Id, connId.Conn_start_ns, event.Attr.ReadEventsCount, event.Attr.WriteEventsCount)
			continue
		}

		event.Attr.ReadEventsCount = event.Attr.ReadEventsCount
		event.Attr.WriteEventsCount = event.Attr.WriteEventsCount

		connectionFactory.CreateIfNotExists(connId)

		dataStr := string(event.Msg[:min(32, utils.Abs(bytesSent))])

		connectionFactory.SendEvent(connId, &event)
		connections.UpdateBufferSize(uint64(utils.Abs(bytesSent)))

		utils.LogIngest("Got data fd: %v id: %v ts: %v ip: %v port: %v data: %v rc: %v wc: %v ssl: %v\n", connId.Fd, connId.Id, connId.Conn_start_ns, connId.Ip, connId.Port, dataStr, event.Attr.ReadEventsCount, event.Attr.WriteEventsCount, event.Attr.Ssl)
	}
}
