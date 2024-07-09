package connections

import (
	"sync"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/structs"
	"github.com/akto-api-security/mirroring-api-logging/ebpf/utils"
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
}

func NewTracker(connID structs.ConnID) *Tracker {
	return &Tracker{
		connID:  connID,
		recvBuf: make(map[int][]byte),
		sentBuf: make(map[int][]byte),
		mutex:   sync.RWMutex{},
		ssl:     false,
	}
}

func (conn *Tracker) IsComplete() bool {
	conn.mutex.RLock()
	defer conn.mutex.RUnlock()
	complete := conn.closeTimestamp != 0 &&
		uint64(time.Now().UnixNano()) >= conn.closeTimestamp
	if complete {
		utils.LogProcessing("closed: %v %v ts: %v %v\n", conn.connID.Fd, conn.connID.Id, conn.closeTimestamp, uint64(time.Now().UnixNano()))
	}
	return complete
}

/*
This preemptively processes the stream after a certain time threshold.
Any more data in this stream will be ignored.
*/
func (conn *Tracker) MarkInactive(duration time.Duration) bool {
	conn.mutex.RLock()
	defer conn.mutex.RUnlock()
	inactive := conn.openTimestamp != 0 &&
		uint64(time.Now().UnixNano())-conn.openTimestamp > uint64(duration.Nanoseconds())
	if inactive {
		utils.LogProcessing("marking inactive: %v %v , ts: %v %v\n", conn.connID.Fd, conn.connID.Id, conn.openTimestamp, uint64(time.Now().UnixNano()))
	}
	return inactive
}

func (conn *Tracker) AddSsl(event structs.SocketDataEvent) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	if !conn.ssl && event.Attr.Ssl {
		conn.sentBuf = make(map[int][]byte)
		conn.recvBuf = make(map[int][]byte)
		conn.sentBytes = 0
		conn.recvBytes = 0
		conn.ssl = event.Attr.Ssl
	}
}

func (conn *Tracker) AddDataEvent(event structs.SocketDataEvent) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	if conn.ssl != event.Attr.Ssl {
		return
	}

	bytesSent := (event.Attr.Bytes_sent >> 32) >> 16

	if bytesSent > 0 {
		conn.sentBuf[int(event.Attr.WriteEventsCount)] = append(conn.sentBuf[int(event.Attr.WriteEventsCount)], event.Msg[:utils.Abs(bytesSent)]...)
		conn.sentBytes += uint64(utils.Abs(bytesSent))
	} else {
		conn.recvBuf[int(event.Attr.ReadEventsCount)] = append(conn.recvBuf[int(event.Attr.ReadEventsCount)], event.Msg[:utils.Abs(bytesSent)]...)
		conn.recvBytes += uint64(utils.Abs(bytesSent))
	}

	conn.lastAccessTimestamp = uint64(time.Now().UnixNano())
}

func (conn *Tracker) AddOpenEvent(event structs.SocketOpenEvent) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	now := uint64(time.Now().UnixNano())
	if conn.openTimestamp != 0 {
		utils.LogIngest("Changing conn open timestamp from %v to %v\n", conn.openTimestamp, now)
	}
	conn.openTimestamp = now
	conn.lastAccessTimestamp = now
}

func (conn *Tracker) AddCloseEvent(event structs.SocketCloseEvent) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	conn.closeTimestamp = uint64(time.Now().UnixNano())
	conn.lastAccessTimestamp = uint64(time.Now().UnixNano())
}
