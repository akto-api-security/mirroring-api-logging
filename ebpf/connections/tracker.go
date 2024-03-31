package connections

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/structs"
	"github.com/akto-api-security/mirroring-api-logging/ebpf/utils"
	trafficUtils "github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

var (
	MaxBufferSize = 20
)

func init() {
	trafficUtils.InitVar("TRAFFIC_MAX_BUFFER_PER_TRACKER", &MaxBufferSize)
}

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
}

func NewTracker(connID structs.ConnID) *Tracker {
	return &Tracker{
		connID:  connID,
		recvBuf: make(map[int][]byte),
		sentBuf: make(map[int][]byte),
		mutex:   sync.RWMutex{},
	}
}

func (conn *Tracker) IsComplete(duration time.Duration) bool {
	conn.mutex.RLock()
	defer conn.mutex.RUnlock()
	if conn.closeTimestamp > 0 {
		utils.Debugf("now: %v, close: %v\n", uint64(time.Now().UnixNano()), conn.closeTimestamp)
	}
	return conn.closeTimestamp != 0 && uint64(time.Now().UnixNano())-conn.closeTimestamp >= uint64(duration.Nanoseconds())
}

func (conn *Tracker) IsBufferOverflow() bool {
	conn.mutex.RLock()
	defer conn.mutex.RUnlock()

	totalBufferSize := int(max(len(conn.recvBuf), len(conn.sentBuf)))
	if totalBufferSize >= MaxBufferSize {
		fmt.Printf("Marking overflow Total buffer size: %v , process: %v\n", totalBufferSize, totalBufferSize >= MaxBufferSize)
	}
	return totalBufferSize >= MaxBufferSize
}

func (conn *Tracker) IsInactive(duration time.Duration) bool {
	conn.mutex.RLock()
	defer conn.mutex.RUnlock()
	return conn.lastAccessTimestamp != 0 && uint64(time.Now().UnixNano())-conn.lastAccessTimestamp > uint64(duration.Nanoseconds())
}

func (conn *Tracker) AddDataEvent(event structs.SocketDataEvent) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	totalBufferSize := int(max(len(conn.recvBuf), len(conn.sentBuf)))
	if totalBufferSize >= MaxBufferSize {
		fmt.Printf("Skipping because overflow Total buffer size: %v , process: %v\n", totalBufferSize, totalBufferSize >= MaxBufferSize)
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
