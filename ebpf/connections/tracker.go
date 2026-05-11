package connections

import (
	"bytes"
	"sort"
	"sync"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/structs"
	trafficUtils "github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

func previewBytes(b []byte, max int) string {
	if len(b) == 0 {
		return ""
	}
	if len(b) > max {
		return string(b[:max])
	}
	return string(b)
}

type Tracker struct {
	connID structs.ConnID

	openTimestamp       uint64
	closeTimestamp      uint64
	lastAccessTimestamp uint64

	sentBytes uint64
	recvBytes uint64

	// Per read/write sequence key: ordered payload chunks (each []byte is one perf event).
	recvParts map[int][][]byte
	sentParts map[int][][]byte
	mutex     sync.RWMutex
	ssl       bool

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
	if complete {
		trafficUtils.LogProcessing("Connection closed", "fd", conn.connID.Fd, "id", conn.connID.Id, "closeTimestamp", conn.closeTimestamp, "currentTimestamp", uint64(time.Now().UnixNano()))
	}
	return complete
}

func (conn *Tracker) AddDataPayload(p *SocketDataPayload) {
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
	if conn.openTimestamp != 0 {
		trafficUtils.LogIngest("Changing conn open timestamp", "current", conn.openTimestamp, "new", now)
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

// joinPartsMap merges [][]byte per sequence key like convertToSingleByteArr did for []byte.
func joinPartsMap(partsMap map[int][][]byte) []byte {
	if len(partsMap) == 0 {
		return make([]byte, 0)
	}

	var keys []int
	for k := range partsMap {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	var combined []byte
	kPrev := -1
	for _, k := range keys {
		if kPrev == -1 {
			if !sequenceCheckSkip && k != 1 {
				first := partsMap[k]
				preview := ""
				if len(first) > 0 && len(first[0]) > 0 {
					preview = previewBytes(first[0], 64)
				}
				trafficUtils.LogProcessing("Bad start sequence", "key", k, "value", preview)
				break
			}
			kPrev = k
		} else {
			if kPrev+1 != k {
				first := partsMap[k]
				preview := ""
				if len(first) > 0 && len(first[0]) > 0 {
					preview = previewBytes(first[0], 64)
				}
				prevFirst := partsMap[kPrev]
				prevPreview := ""
				if len(prevFirst) > 0 && len(prevFirst[0]) > 0 {
					prevPreview = previewBytes(prevFirst[0], 64)
				}
				trafficUtils.LogProcessing("Missing sequence", "prev", kPrev, "current", k, "value", preview, "prevValue", prevPreview)
				break
			}
			kPrev = k
		}
		perKey := bytes.Join(partsMap[k], nil)
		combined = append(combined, perKey...)
	}

	return combined
}
