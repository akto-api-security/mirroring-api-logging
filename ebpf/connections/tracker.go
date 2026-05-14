package connections

import (
	"sync"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/structs"
	metaUtils "github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

type Tracker struct {
	connID structs.ConnID

	openTimestamp       uint64
	closeTimestamp      uint64
	lastAccessTimestamp uint64

	sentBytes uint64
	recvBytes uint64

	// Per read/write sequence key: payload chunks (each []byte is one ring buffer event).
	recvParts map[int][][]byte
	sentParts map[int][][]byte
	mutex     sync.RWMutex
	ssl       bool

	// source IP-Port / local IP-Port
	srcIp   uint32
	srcPort uint16
}

func NewTracker(connID structs.ConnID) *Tracker {
	return &Tracker{
		connID:    connID,
		recvParts: make(map[int][][]byte),
		sentParts: make(map[int][][]byte),
		mutex:     sync.RWMutex{},
		ssl:       false,
	}
}

func (conn *Tracker) IsComplete() bool {
	conn.mutex.RLock()
	defer conn.mutex.RUnlock()
	complete := conn.closeTimestamp != 0 &&
		uint64(time.Now().UnixNano()) >= conn.closeTimestamp
	if complete && metaUtils.ProcessLogsEnabled() {
		metaUtils.LogProcessing("Connection closed", append(structs.ConnIDLogArgs(conn.connID), "closeTimestamp", conn.closeTimestamp, "currentTimestamp", uint64(time.Now().UnixNano()))...)
	}
	return complete
}

func (conn *Tracker) AddDataPayload(p *structs.SocketDataPayload) {
	if p == nil {
		return
	}
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	attr := &p.Attr
	data := p.Data
	n := len(data)

	if !conn.ssl && attr.Ssl {
		for k := range conn.sentParts {
			conn.sentParts[k] = nil
		}
		for k := range conn.recvParts {
			conn.recvParts[k] = nil
		}
		conn.sentParts = make(map[int][][]byte)
		conn.recvParts = make(map[int][][]byte)
		conn.sentBytes = 0
		conn.recvBytes = 0
		conn.ssl = attr.Ssl
	}

	if conn.ssl != attr.Ssl {
		return
	}

	bytesSent := attr.Bytes_sent
	if bytesSent > 0 {
		wc := int(attr.WriteEventsCount)
		conn.sentParts[wc] = append(conn.sentParts[wc], data)
		conn.sentBytes += uint64(n)
	} else {
		rc := int(attr.ReadEventsCount)
		conn.recvParts[rc] = append(conn.recvParts[rc], data)
		conn.recvBytes += uint64(n)
	}

	conn.lastAccessTimestamp = uint64(time.Now().UnixNano())
}

func (conn *Tracker) AddOpenEvent(event structs.SocketOpenEvent) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	now := uint64(time.Now().UnixNano())
	if conn.openTimestamp != 0 && metaUtils.IngestLogsEnabled() {
		metaUtils.LogIngest("Changing conn open timestamp", "current", conn.openTimestamp, "new", now)
	}
	conn.openTimestamp = now
	conn.lastAccessTimestamp = now
	conn.srcIp = event.SrcIp
	conn.srcPort = event.SrcPort
}

func (conn *Tracker) AddCloseEvent(event structs.SocketCloseEvent) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	conn.closeTimestamp = uint64(time.Now().UnixNano())
	conn.lastAccessTimestamp = uint64(time.Now().UnixNano())
}

func (conn *Tracker) GetSentBytes() uint64 {
	return conn.sentBytes
}

func (conn *Tracker) GetRecvBytes() uint64 {
	return conn.recvBytes
}
