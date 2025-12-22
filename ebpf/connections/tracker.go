package connections

import (
	"sync"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/structs"
	"github.com/akto-api-security/mirroring-api-logging/ebpf/utils"
	metaUtils "github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

type Tracker struct {
	connID structs.ConnID

	openTimestamp       uint64
	closeTimestamp      uint64
	lastAccessTimestamp uint64

	// Indicates the tracker stopped tracking due to closing the session.
	sentBytes uint64
	recvBytes uint64

	recvBuf map[int][]byte
	sentBuf map[int][]byte
	mutex   sync.RWMutex
	ssl     bool

	// source IP-Port / local IP-Port
	srcIp   uint32
	srcPort uint16

	foundHTTP bool
	protocol  string // "http1", "http2", or "unknown"
}

func NewTracker(connID structs.ConnID) *Tracker {
	return &Tracker{
		connID:    connID,
		recvBuf:   make(map[int][]byte),
		sentBuf:   make(map[int][]byte),
		mutex:     sync.RWMutex{},
		ssl:       false,
		foundHTTP: false,
		protocol:  protocolUnknown,
	}
}

func (conn *Tracker) IsComplete() bool {
	conn.mutex.RLock()
	defer conn.mutex.RUnlock()
	complete := conn.closeTimestamp != 0 &&
		uint64(time.Now().UnixNano()) >= conn.closeTimestamp
	if complete {
		metaUtils.LogProcessing("Connection closed", "fd", conn.connID.Fd, "id", conn.connID.Id, "closeTimestamp", conn.closeTimestamp, "currentTimestamp", uint64(time.Now().UnixNano()))
	}
	return complete
}

func (conn *Tracker) AddDataEvent(event structs.SocketDataEvent, protocol string) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	if conn.protocol == protocolUnknown && protocol != protocolUnknown {
		conn.protocol = protocol
		metaUtils.LogIngest("Protocol detected", "fd", conn.connID.Fd, "id", conn.connID.Id, "protocol", protocol)
	}

	if !conn.ssl && event.Attr.Ssl {
		for k := range conn.sentBuf {
			conn.sentBuf[k] = []byte{}
		}
		for k := range conn.recvBuf {
			conn.recvBuf[k] = []byte{}
		}
		conn.sentBytes = 0
		conn.recvBytes = 0
		conn.ssl = event.Attr.Ssl
	}

	if conn.ssl != event.Attr.Ssl {
		return
	}

	bytesSent := event.Attr.Bytes_sent

	if bytesSent > 0 {
		conn.sentBuf[int(event.Attr.WriteEventsCount)] = append(conn.sentBuf[int(event.Attr.WriteEventsCount)], event.Msg[:utils.Abs(bytesSent)]...)
		conn.sentBytes += uint64(utils.Abs(bytesSent))
	} else {
		conn.recvBuf[int(event.Attr.ReadEventsCount)] = append(conn.recvBuf[int(event.Attr.ReadEventsCount)], event.Msg[:utils.Abs(bytesSent)]...)
		conn.recvBytes += uint64(utils.Abs(bytesSent))
	}

	conn.lastAccessTimestamp = uint64(time.Now().UnixNano())
}

func (conn *Tracker) GetProtocol() string {
	conn.mutex.RLock()
	defer conn.mutex.RUnlock()
	return conn.protocol
}

func (conn *Tracker) AddOpenEvent(event structs.SocketOpenEvent) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	now := uint64(time.Now().UnixNano())
	if conn.openTimestamp != 0 {
		metaUtils.LogIngest("Changing conn open timestamp", "current", conn.openTimestamp, "new", now)
	}
	conn.openTimestamp = now
	conn.lastAccessTimestamp = now
	conn.srcIp = event.SrcIp
	conn.srcPort = event.SrcPort

	protocolBytes := event.Protocol[:]
	nullIndex := -1
	for i, b := range protocolBytes {
		if b == 0 {
			nullIndex = i
			break
		}
	}
	if nullIndex > 0 {
		protocolStr := string(protocolBytes[:nullIndex])
		switch protocolStr {
		case protocolhttp1:
			conn.protocol = protocolhttp1
		case protocolhttp2:
			conn.protocol = protocolhttp2
		default:
			conn.protocol = protocolUnknown
		}
		metaUtils.LogIngest("Protocol set from eBPF", "fd", conn.connID.Fd, "id", conn.connID.Id, "protocol", conn.protocol, "raw", protocolStr)
	}
}

func (conn *Tracker) AddCloseEvent(event structs.SocketCloseEvent) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	conn.closeTimestamp = uint64(time.Now().UnixNano())
	conn.lastAccessTimestamp = uint64(time.Now().UnixNano())
}
