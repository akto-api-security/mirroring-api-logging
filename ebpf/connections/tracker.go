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

	// Pre-allocated arrays for chunks (256 max chunks per connection)
	// Each chunk is allocated with 8KB initial capacity to eliminate reallocation during growth
	recvBuf [256][]byte
	sentBuf [256][]byte
	mutex   sync.RWMutex
	ssl     bool
	// Track max position reached in each buffer to handle SSL clearing
	recvBufInitialized [256]bool
	sentBufInitialized [256]bool
	// Position tracking for each buffer chunk to avoid append() overhead
	recvPos [256]int
	sentPos [256]int

	// source IP-Port / local IP-Port
	srcIp   uint32
	srcPort uint16

	foundHTTP bool
}

func NewTracker(connID structs.ConnID) *Tracker {
	return &Tracker{
		connID:    connID,
		mutex:     sync.RWMutex{},
		ssl:       false,
		foundHTTP: false,
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

func (conn *Tracker) MarkHTTPDetected() {
	conn.foundHTTP = true
}

func (conn *Tracker) AddDataEvent(event structs.SocketDataEvent) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	if !conn.ssl && event.Attr.Ssl {
		for i := range conn.sentBuf {
			conn.sentBuf[i] = nil
			conn.sentBufInitialized[i] = false
			conn.sentPos[i] = 0
		}
		for i := range conn.recvBuf {
			conn.recvBuf[i] = nil
			conn.recvBufInitialized[i] = false
			conn.recvPos[i] = 0
		}
		conn.sentBytes = 0
		conn.recvBytes = 0
		conn.ssl = event.Attr.Ssl
	}

	if conn.ssl != event.Attr.Ssl {
		return
	}

	bytesSent := event.Attr.Bytes_sent
	bytesAbs := utils.Abs(bytesSent)
	bytesAbsInt := int(bytesAbs)

	if bytesSent > 0 {
		idx := int(event.Attr.WriteEventsCount)
		// Pre-allocate 8KB capacity on first use to avoid reallocation during append growth
		if idx > 255{
			//fmt.Println("returning from write index > 255: %d IP: %d, Port: %d", idx, event.Attr.ConnId.Ip, event.Attr.ConnId.Port);
			return
		}

		if !conn.sentBufInitialized[idx] {
			conn.sentBuf[idx] = make([]byte, 8192)
			conn.sentBufInitialized[idx] = true
			conn.sentPos[idx] = 0
		}
		// Use position-based copy instead of append to avoid bounds checks and reallocation
		pos := conn.sentPos[idx]
		if pos+bytesAbsInt <= len(conn.sentBuf[idx]) {
			copy(conn.sentBuf[idx][pos:pos+bytesAbsInt], event.Msg[:bytesAbsInt])
			conn.sentPos[idx] = pos + bytesAbsInt
			conn.sentBytes += uint64(bytesAbs)
		} else {
			// Buffer full, fall back to append for overflow (rare case)
			conn.sentBuf[idx] = append(conn.sentBuf[idx][:pos], event.Msg[:bytesAbsInt]...)
			conn.sentPos[idx] = pos + bytesAbsInt
			conn.sentBytes += uint64(bytesAbs)
		}
	} else {
		idx := int(event.Attr.ReadEventsCount)
		if idx > 255{
			//fmt.Println("returning from write index > 255: %d IP: %d, Port: %d", idx, event.Attr.ConnId.Ip, event.Attr.ConnId.Port);
			return
		}
		// Pre-allocate 8KB capacity on first use to avoid reallocation during append growth
		if !conn.recvBufInitialized[idx] {
			conn.recvBuf[idx] = make([]byte, 8192)
			conn.recvBufInitialized[idx] = true
			conn.recvPos[idx] = 0
		}
		// Use position-based copy instead of append to avoid bounds checks and reallocation
		pos := conn.recvPos[idx]
		if pos+bytesAbsInt <= len(conn.recvBuf[idx]) {
			copy(conn.recvBuf[idx][pos:pos+bytesAbsInt], event.Msg[:bytesAbsInt])
			conn.recvPos[idx] = pos + bytesAbsInt
			conn.recvBytes += uint64(bytesAbs)
		} else {
			// Buffer full, fall back to append for overflow (rare case)
			conn.recvBuf[idx] = append(conn.recvBuf[idx][:pos], event.Msg[:bytesAbsInt]...)
			conn.recvPos[idx] = pos + bytesAbsInt
			conn.recvBytes += uint64(bytesAbs)
		}
	}

	// Use kernel timestamp from event instead of syscall
	if event.Attr.EventTimestampNs > 0 {
		conn.lastAccessTimestamp = event.Attr.EventTimestampNs
	}
}

// addDataEventLocked is called with mutex already held by caller (for batch processing)
func (conn *Tracker) addDataEventLocked(event structs.SocketDataEvent) {
	if !conn.ssl && event.Attr.Ssl {
		for i := range conn.sentBuf {
			conn.sentBuf[i] = nil
			conn.sentBufInitialized[i] = false
			conn.sentPos[i] = 0
		}
		for i := range conn.recvBuf {
			conn.recvBuf[i] = nil
			conn.recvBufInitialized[i] = false
			conn.recvPos[i] = 0
		}
		conn.sentBytes = 0
		conn.recvBytes = 0
		conn.ssl = event.Attr.Ssl
	}

	if conn.ssl != event.Attr.Ssl {
		return
	}

	bytesSent := event.Attr.Bytes_sent
	bytesAbs := utils.Abs(bytesSent)
	bytesAbsInt := int(bytesAbs)

	if bytesSent > 0 {
		idx := int(event.Attr.WriteEventsCount)
		if idx > 255 {
			//fmt.Printf("returning from read index > 255: %d IP=%d Port=%d", idx, event.Attr.ConnId.Ip, event.Attr.ConnId.Port);
			return
		}
		// Pre-allocate 8KB capacity on first use to avoid reallocation during append growth
		if !conn.sentBufInitialized[idx] {
			conn.sentBuf[idx] = make([]byte, 8192)
			conn.sentBufInitialized[idx] = true
			conn.sentPos[idx] = 0
		}
		// Use position-based copy instead of append to avoid bounds checks and reallocation
		pos := conn.sentPos[idx]
		if pos+bytesAbsInt <= len(conn.sentBuf[idx]) {
			copy(conn.sentBuf[idx][pos:pos+bytesAbsInt], event.Msg[:bytesAbsInt])
			conn.sentPos[idx] = pos + bytesAbsInt
			conn.sentBytes += uint64(bytesAbs)
		} else {
			// Buffer full, fall back to append for overflow (rare case)
			conn.sentBuf[idx] = append(conn.sentBuf[idx][:pos], event.Msg[:bytesAbsInt]...)
			conn.sentPos[idx] = pos + bytesAbsInt
			conn.sentBytes += uint64(bytesAbs)
		}
	} else {
		idx := int(event.Attr.ReadEventsCount)
		if idx > 255 {
			//fmt.Println("returning from read index > 255: %d IP=%d Port=%d", idx, event.Attr.ConnId.Ip, event.Attr.ConnId.Port);
			return
		}
		// Pre-allocate 8KB capacity on first use to avoid reallocation during append growth
		if !conn.recvBufInitialized[idx] {
			conn.recvBuf[idx] = make([]byte, 8192)
			conn.recvBufInitialized[idx] = true
			conn.recvPos[idx] = 0
		}
		// Use position-based copy instead of append to avoid bounds checks and reallocation
		pos := conn.recvPos[idx]
		if pos+bytesAbsInt <= len(conn.recvBuf[idx]) {
			copy(conn.recvBuf[idx][pos:pos+bytesAbsInt], event.Msg[:bytesAbsInt])
			conn.recvPos[idx] = pos + bytesAbsInt
			conn.recvBytes += uint64(bytesAbs)
		} else {
			// Buffer full, fall back to append for overflow (rare case)
			conn.recvBuf[idx] = append(conn.recvBuf[idx][:pos], event.Msg[:bytesAbsInt]...)
			conn.recvPos[idx] = pos + bytesAbsInt
			conn.recvBytes += uint64(bytesAbs)
		}
	}

	// Use kernel timestamp from event instead of syscall
	if event.Attr.EventTimestampNs > 0 {
		conn.lastAccessTimestamp = event.Attr.EventTimestampNs
	}
}

func (conn *Tracker) AddOpenEvent(event structs.SocketOpenEvent) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	// Use kernel timestamp from event instead of syscall
	now := event.Socket_open_ns
	if now == 0 {
		now = uint64(time.Now().UnixNano()) // fallback if kernel time unavailable
	}
	if conn.openTimestamp != 0 {
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
