package connections

import (
	"log/slog"
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
}

func NewTracker(connID structs.ConnID) *Tracker {
	return &Tracker{
		connID:    connID,
		recvBuf:   make(map[int][]byte),
		sentBuf:   make(map[int][]byte),
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

func (conn *Tracker) AddDataEvent(event structs.SocketDataEvent) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	if !conn.ssl && event.Attr.Ssl {
		slog.Info("SSL uprobe took over connection, clearing encrypted socket buffers",
			"fd", conn.connID.Fd,
			"id", conn.connID.Id,
			"port", conn.connID.Port,
			"clearedSentChunks", len(conn.sentBuf),
			"clearedRecvChunks", len(conn.recvBuf),
			"clearedSentBytes", conn.sentBytes,
			"clearedRecvBytes", conn.recvBytes,
		)
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
		metaUtils.LogProcessing("Dropping data event due to SSL mode mismatch",
			"fd", conn.connID.Fd,
			"id", conn.connID.Id,
			"trackerSsl", conn.ssl,
			"eventSsl", event.Attr.Ssl,
			"bytesSent", event.Attr.Bytes_sent,
			"readCount", event.Attr.ReadEventsCount,
			"writeCount", event.Attr.WriteEventsCount,
		)
		return
	}

	bytesSent := event.Attr.Bytes_sent
	chunkSize := utils.Abs(bytesSent)

	if bytesSent > 0 {
		conn.sentBuf[int(event.Attr.WriteEventsCount)] = append(conn.sentBuf[int(event.Attr.WriteEventsCount)], event.Msg[:chunkSize]...)
		conn.sentBytes += uint64(chunkSize)
	} else {
		conn.recvBuf[int(event.Attr.ReadEventsCount)] = append(conn.recvBuf[int(event.Attr.ReadEventsCount)], event.Msg[:chunkSize]...)
		conn.recvBytes += uint64(chunkSize)
	}

	metaUtils.LogProcessing("Tracker data event accumulated",
		"fd", conn.connID.Fd,
		"id", conn.connID.Id,
		"ssl", conn.ssl,
		"isSend", bytesSent > 0,
		"chunkBytes", chunkSize,
		"totalSentBytes", conn.sentBytes,
		"totalRecvBytes", conn.recvBytes,
		"sentChunks", len(conn.sentBuf),
		"recvChunks", len(conn.recvBuf),
	)

	conn.lastAccessTimestamp = uint64(time.Now().UnixNano())
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