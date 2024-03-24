package connections

import (
	"log"
	"sync"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/structs"
	"github.com/akto-api-security/mirroring-api-logging/ebpf/utils"
)

const (
	maxBufferSize = 40 * 1024
	/*
		30KB limit defined in C++ probe code, per data event, taking some extra here.
		this is used to create the initial user space buffer,
		which is dynamically increased by go when required.
	*/
)

type Tracker struct {
	connID structs.ConnID

	openTimestamp       uint64
	closeTimestamp      uint64
	lastAccessTimestamp uint64

	// Indicates the tracker stopped tracking due to closing the session.
	sentBytes uint64
	recvBytes uint64

	recvBuf []byte
	sentBuf []byte
	mutex   sync.RWMutex
}

func NewTracker(connID structs.ConnID) *Tracker {
	return &Tracker{
		connID:  connID,
		recvBuf: make([]byte, 0, maxBufferSize),
		sentBuf: make([]byte, 0, maxBufferSize),
		mutex:   sync.RWMutex{},
	}
}

// We process a tracker after atleast 15 seconds, and delete it after 30 seconds of connection close.

func (conn *Tracker) IsComplete(duration time.Duration) bool {
	conn.mutex.RLock()
	defer conn.mutex.RUnlock()
	return conn.closeTimestamp != 0 && uint64(time.Now().UnixNano())-conn.closeTimestamp > uint64(duration.Nanoseconds())
}

func (conn *Tracker) IsBufferOverflow(maxBufferPerTracker int) bool {
	conn.mutex.RLock()
	defer conn.mutex.RUnlock()

	totalBufferSize := len(conn.recvBuf) + len(conn.sentBuf)

	return totalBufferSize >= maxBufferPerTracker
}

func (conn *Tracker) IsInactive(duration time.Duration) bool {
	conn.mutex.RLock()
	defer conn.mutex.RUnlock()
	return conn.lastAccessTimestamp != 0 && uint64(time.Now().UnixNano())-conn.lastAccessTimestamp > uint64(duration.Nanoseconds())
}

func (conn *Tracker) AddDataEvent(event structs.SocketDataEvent) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	bytesSent := (event.Attr.Bytes_sent >> 32) >> 16

	if bytesSent > 0 {
		conn.sentBuf = append(conn.sentBuf, event.Msg[:utils.Abs(bytesSent)]...)
		conn.sentBytes += uint64(utils.Abs(bytesSent))
	} else {
		conn.recvBuf = append(conn.recvBuf, event.Msg[:utils.Abs(bytesSent)]...)
		conn.recvBytes += uint64(utils.Abs(bytesSent))
	}

	conn.lastAccessTimestamp = uint64(time.Now().UnixNano())
}

func (conn *Tracker) AddOpenEvent(event structs.SocketOpenEvent) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	if conn.openTimestamp != 0 && conn.openTimestamp != event.ConnId.Conn_start_ns {
		log.Printf("Changed open info timestamp from %v to %v", conn.openTimestamp, event.ConnId.Conn_start_ns)
	}
	conn.openTimestamp = event.ConnId.Conn_start_ns
	conn.lastAccessTimestamp = uint64(time.Now().UnixNano())
}

func (conn *Tracker) AddCloseEvent(event structs.SocketCloseEvent) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	conn.closeTimestamp = uint64(time.Now().UnixNano())
	conn.lastAccessTimestamp = uint64(time.Now().UnixNano())
}
