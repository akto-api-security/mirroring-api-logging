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
			return
		}

		var event structs.SocketOpenEvent
		if err := binary.Read(bytes.NewReader(data), bcc.GetHostByteOrder(), &event); err != nil {
			log.Printf("Failed to decode received data on socket open: %+v", err)
			continue
		}

		// utils.Debugf("Got data with IP %v, on port: %v", event.ConnId.Ip, event.ConnId.Port)
		connId := event.ConnId
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
		tracker.AddCloseEvent(event)
	}
}

var (
	// this also includes space lost in padding.
	eventAttributesSize = int(unsafe.Sizeof(structs.SocketDataEventAttr{}))
)

func SocketDataEventCallback(inputChan chan []byte, connectionFactory *connections.Factory) {
	for data := range inputChan {
		if data == nil {
			return
		}

		if !connectionFactory.CanBeFilled() {
			return
		}

		var event structs.SocketDataEvent

		// binary.Read require the input data to be at the same size of the object.
		// Since the Msg field might be mostly empty, binary.read fails.
		// So we split the loading into the fixed size attribute parts, and copying the message separately.

		if err := binary.Read(bytes.NewReader(data[:eventAttributesSize]), bcc.GetHostByteOrder(), &event.Attr); err != nil {
			log.Printf("Failed to decode received data: %+v", err)
			continue
		}

		// the first 16 bits are relevant, but since we get more data, we use bitwise operation to extract the first 16 bits.
		bytesSent := (event.Attr.Bytes_sent >> 32) >> 16

		// The 4 bytes are being lost in padding, thus, not taking them into consideration.
		eventAttributesLogicalSize := 36

		if len(data) > eventAttributesLogicalSize {
			copy(event.Msg[:], data[eventAttributesLogicalSize:eventAttributesLogicalSize+int(utils.Abs(bytesSent))])
		}

		connId := event.Attr.ConnId
		connectionFactory.GetOrCreate(connId).AddDataEvent(event)

		connectionFactory.UpdateBufferSize(uint64(utils.Abs(bytesSent)))

		// utils.Debugf("<------------")
		// utils.Debugf("Got data event of size %v, with data: %s", event.Attr.Bytes_sent, event.Msg[:utils.Abs(bytesSent)])
		// utils.Debugf("------------>")
	}
}
