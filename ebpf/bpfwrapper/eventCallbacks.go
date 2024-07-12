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
			continue
		}

		var event structs.SocketOpenEvent
		if err := binary.Read(bytes.NewReader(data), bcc.GetHostByteOrder(), &event); err != nil {
			log.Printf("Failed to decode received data on socket open: %+v", err)
			continue
		}
		connId := event.ConnId
		utils.LogIngest("Received open on: %v %v\n", connId.Fd, connId.Id)
		connectionFactory.GetOrCreate(connId).AddOpenEvent(event)

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
		tracker := connectionFactory.Get(connId)
		if tracker == nil {
			continue
		}
		utils.LogIngest("Received close on: %v %v\n", connId.Fd, connId.Id)
		tracker.AddCloseEvent(event)
	}
}

var (
	// this also includes space lost in padding.
	eventAttributesSize = int(unsafe.Sizeof(structs.SocketDataEventAttr{}))
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

		if err := binary.Read(bytes.NewReader(data[:eventAttributesSize]), bcc.GetHostByteOrder(), &event.Attr); err != nil {
			utils.LogIngest("Failed to decode received data: %+v", err)
			continue
		}

		bytesSent := event.Attr.Bytes_sent

		// The 4 bytes are being lost in padding, thus, not taking them into consideration.
		eventAttributesLogicalSize := 44

		if len(data) > eventAttributesLogicalSize {
			copy(event.Msg[:], data[eventAttributesLogicalSize:eventAttributesLogicalSize+int(utils.Abs(bytesSent))])
		}

		connId := event.Attr.ConnId

		event.Attr.ReadEventsCount = event.Attr.ReadEventsCount
		event.Attr.WriteEventsCount = event.Attr.WriteEventsCount

		tracker := connectionFactory.GetOrCreate(connId)

		dataStr := string(event.Msg[:min(32, utils.Abs(bytesSent))])

		if tracker == nil {
			utils.LogIngest("Ignoring data fd: %v id: %v data: %v ts: %v rc: %v wc: %v\n", connId.Fd, connId.Id, dataStr, connId.Conn_start_ns, event.Attr.ReadEventsCount, event.Attr.WriteEventsCount)
			continue
		}

		tracker.AddDataEvent(event)

		connections.UpdateBufferSize(uint64(utils.Abs(bytesSent)))

		utils.LogIngest("Got data fd: %v id: %v data: %v ts: %v rc: %v wc: %v\n", connId.Fd, connId.Id, dataStr, connId.Conn_start_ns, event.Attr.ReadEventsCount, event.Attr.WriteEventsCount)
	}
}
