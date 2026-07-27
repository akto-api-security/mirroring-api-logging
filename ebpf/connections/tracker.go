package connections

import (
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"
	"unsafe"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/structs"
	"github.com/akto-api-security/mirroring-api-logging/ebpf/utils"
	metaUtils "github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

func getChunkKeys(chunks map[int][]byte) string {
	keys := make([]int, 0, len(chunks))
	for k := range chunks {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return fmt.Sprint(keys)
}

type msgSeqGroup struct {
	msgSeq    uint32
	direction uint32         // kEgress=0, kIngress=1
	chunks    map[int][]byte // key: rc (if ingress) or wc (if egress)
}

type MsgSeqPair struct {
	ReqGroup  *msgSeqGroup
	RespGroup *msgSeqGroup
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
	ssl     bool

	// local IP-Port
	laddr uint32
	lport uint16

	role uint32 // 0=unknown, 1=client, 2=server

	foundHTTP bool

	// msg_seq based buffering for incremental pair flushing
	msgGroups        map[uint32]*msgSeqGroup
	highestMsgSeq    uint32
	lowestPendingSeq uint32
	// seenMsgSeqs tracks every msg_seq ever buffered on this connection so
	// GroupsCreated counts each unique msg_seq exactly once, even when a group
	// is deleted (paired/orphaned/stranded) and later re-created by a late chunk.
	seenMsgSeqs map[uint32]struct{}
}

func NewTracker(connID structs.ConnID) *Tracker {
	return &Tracker{
		connID:    connID,
		recvBuf:   make(map[int][]byte),
		sentBuf:   make(map[int][]byte),
		mutex:     sync.RWMutex{},
		ssl:       false,
		foundHTTP:   false,
		msgGroups:   make(map[uint32]*msgSeqGroup),
		seenMsgSeqs: make(map[uint32]struct{}),
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

// AddDataEvent buffers one raw data-event record. dataPtr points at the raw
// kernel slice (attr region + payload); the attr is read via an in-place unsafe
// cast and the payload is stored BY REFERENCE (a sub-slice of the raw record),
// so no payload bytes are copied here. The raw slice is a unique per-event
// allocation that nothing recycles, so retained sub-slices can never be
// clobbered. Returns the record's msg_seq for the worker's inactivity timer.
func (conn *Tracker) AddDataEvent(dataPtr *[]byte) uint32 {
	data := *dataPtr
	attr := (*structs.SocketDataEventAttr)(unsafe.Pointer(&data[0]))

	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	if attr.Laddr != 0 {
		conn.laddr = attr.Laddr
		conn.lport = attr.Lport
	}
	if attr.Role != 0 && conn.role == 0 {
		conn.role = attr.Role
	}

	if !conn.ssl && attr.Ssl {
		for k := range conn.sentBuf {
			conn.sentBuf[k] = []byte{}
		}
		for k := range conn.recvBuf {
			conn.recvBuf[k] = []byte{}
		}
		conn.sentBytes = 0
		conn.recvBytes = 0
		conn.ssl = attr.Ssl
	}

	if conn.ssl != attr.Ssl {
		return attr.MsgSeq
	}

	bytesSent := attr.Bytes_sent
	absBytes := utils.Abs(bytesSent)

	// Payload is data[MsgOffset : MsgOffset+absBytes], stored by reference.
	// Guard against a truncated record so the slice bound can't panic.
	if structs.MsgOffset+int(absBytes) > len(data) {
		return attr.MsgSeq
	}
	payload := data[structs.MsgOffset : structs.MsgOffset+int(absBytes)]

	if UseMsgSeqFlush {
		// msg_seq based buffering for incremental pair flushing
		msgSeq := attr.MsgSeq
		if msgSeq > 0 {
			group, exists := conn.msgGroups[msgSeq]
			if !exists {
				if msgSeq < conn.lowestPendingSeq {
					metaUtils.Pipeline.LateArrivals.Add(1)
					metaUtils.Pipeline.LateArrivalDist.Observe(conn.highestMsgSeq - msgSeq)
					if metaUtils.IsMsgSeqLogsEnabled() {
						slog.Warn("msg_seq: late arrival below lowestPendingSeq (already flushed)",
							"fd", conn.connID.Fd,
							"msg_seq", msgSeq,
							"lowestPendingSeq", conn.lowestPendingSeq)
					}
				} else if msgSeq < conn.highestMsgSeq {
					metaUtils.Pipeline.OutOfOrderArrivals.Add(1)
					metaUtils.Pipeline.OutOfOrderDist.Observe(conn.highestMsgSeq - msgSeq)
					if metaUtils.IsMsgSeqLogsEnabled() {
						slog.Warn("msg_seq: out-of-order group arrival",
							"fd", conn.connID.Fd,
							"msg_seq", msgSeq,
							"highestMsgSeq", conn.highestMsgSeq)
					}
				}
				group = &msgSeqGroup{
					msgSeq:    msgSeq,
					direction: attr.Direction,
					chunks:    make(map[int][]byte),
				}
				conn.msgGroups[msgSeq] = group
				// Count each unique msg_seq once, even if this group was
				// previously flushed/orphaned/stranded and is now re-created
				// by a late-arriving chunk.
				if _, seen := conn.seenMsgSeqs[msgSeq]; !seen {
					conn.seenMsgSeqs[msgSeq] = struct{}{}
					metaUtils.Pipeline.GroupsCreated.Add(1)
				}
			}

			var chunkKey int
			if group.direction == 0 { // kEgress
				chunkKey = int(attr.WriteEventsCount)
			} else { // kIngress
				chunkKey = int(attr.ReadEventsCount)
			}
			// chunkKey (rc/wc) is monotonic and unique per event, so each key is
			// written exactly once — store the payload slice directly, no copy.
			group.chunks[chunkKey] = payload

			if msgSeq > conn.highestMsgSeq {
				conn.highestMsgSeq = msgSeq
			}

			if metaUtils.IsMsgSeqLogsEnabled() {
				slog.Debug("msg_seq: chunk added",
					"fd", conn.connID.Fd,
					"msg_seq", msgSeq,
					"direction", group.direction,
					"chunk_key", chunkKey,
					"chunk_bytes", absBytes,
					"total_chunks", len(group.chunks),
					"highest_msg_seq", conn.highestMsgSeq,
					"pending_groups", len(conn.msgGroups))
			}
		}
	} else {
		// Old flat buffer path. rc/wc is unique per event, so assign the payload
		// slice directly rather than appending (which would copy the bytes).
		if bytesSent > 0 {
			conn.sentBuf[int(attr.WriteEventsCount)] = payload
			conn.sentBytes += uint64(absBytes)
		} else {
			conn.recvBuf[int(attr.ReadEventsCount)] = payload
			conn.recvBytes += uint64(absBytes)
		}
	}

	conn.lastAccessTimestamp = uint64(time.Now().UnixNano())
	return attr.MsgSeq
}

// AddOpenEvent takes *SocketOpenEvent by pointer to avoid a 48-byte struct copy
// at the call boundary (this fires once per connection, hot under connection
// churn). Manual Unlock (no defer) and a gated log keep the critical section lean.
func (conn *Tracker) AddOpenEvent(event *structs.SocketOpenEvent) {
	now := uint64(time.Now().UnixNano())
	conn.mutex.Lock()
	if conn.openTimestamp != 0 && metaUtils.IsIngestLogsEnabled() {
		metaUtils.LogIngest("Changing conn open timestamp", "current", conn.openTimestamp, "new", now)
	}
	conn.openTimestamp = now
	conn.lastAccessTimestamp = now
	conn.laddr = event.Laddr
	conn.lport = event.Lport
	conn.mutex.Unlock()
}

// AddCloseEvent ignores the event payload entirely (only timestamps matter), so
// it takes a pointer to skip the 40-byte copy. time.Now() is read once and reused
// for both fields, and the read happens before the lock to shrink the hold time.
func (conn *Tracker) AddCloseEvent(_ *structs.SocketCloseEvent) {
	now := uint64(time.Now().UnixNano())
	conn.mutex.Lock()
	conn.closeTimestamp = now
	conn.lastAccessTimestamp = now
	conn.mutex.Unlock()
}

// GetFlushablePairs returns complete request-response pairs that are safe to flush.
// A pair (N, N+1) is complete when msg_seq N+2 exists (next direction change started).
// Caller must NOT hold conn.mutex — this method acquires it.
func (conn *Tracker) GetFlushablePairs() []MsgSeqPair {
	lockStart := time.Now()
	conn.mutex.Lock()
	lockWait := time.Since(lockStart)
	holdStart := time.Now()
	defer func() {
		holdTime := time.Since(holdStart)
		if (lockWait > 1*time.Millisecond || holdTime > 1*time.Millisecond) && metaUtils.IsMsgSeqLogsEnabled() {
			slog.Warn("msg_seq: GetFlushablePairs mutex timing",
				"fd", conn.connID.Fd,
				"wait_ms", lockWait.Milliseconds(),
				"hold_ms", holdTime.Milliseconds(),
				"groups", len(conn.msgGroups))
		}
		conn.mutex.Unlock()
	}()

	if len(conn.msgGroups) < 3 {
		return nil
	}

	pairs, seq := conn.drainPairs(conn.lowestPendingSeq, func(seq uint32) bool {
		return seq+2 <= conn.highestMsgSeq
	})

	conn.lowestPendingSeq = seq

	if len(pairs) == 0 && metaUtils.IsMsgSeqLogsEnabled() {
		slog.Debug("msg_seq: no flushable pairs",
			"fd", conn.connID.Fd,
			"lowest_pending", conn.lowestPendingSeq,
			"highest", conn.highestMsgSeq,
			"pending_groups", len(conn.msgGroups))
	}

	return pairs
}

// FlushRemainingPairs returns all remaining msg_seq groups as pairs.
// Used on inactivity/close when no N+2 trigger is coming.
// Caller must NOT hold conn.mutex.
func (conn *Tracker) FlushRemainingPairs() []MsgSeqPair {
	lockStart := time.Now()
	conn.mutex.Lock()
	lockWait := time.Since(lockStart)
	holdStart := time.Now()
	defer func() {
		holdTime := time.Since(holdStart)
		if (lockWait > 1*time.Millisecond || holdTime > 1*time.Millisecond) && metaUtils.IsMsgSeqLogsEnabled() {
			slog.Warn("msg_seq: FlushRemainingPairs mutex timing",
				"fd", conn.connID.Fd,
				"wait_ms", lockWait.Milliseconds(),
				"hold_ms", holdTime.Milliseconds(),
				"groups", len(conn.msgGroups))
		}
		conn.mutex.Unlock()
	}()

	if len(conn.msgGroups) == 0 {
		return nil
	}

	pairs, seq := conn.drainPairs(conn.lowestPendingSeq, func(seq uint32) bool {
		return len(conn.msgGroups) > 0 && seq <= conn.highestMsgSeq
	})

	conn.lowestPendingSeq = seq

	// Clean up any stranded entries that drainPairs couldn't reach
	// (late arrivals below lowestPendingSeq that were written back into msgGroups).
	for k, g := range conn.msgGroups {
		metaUtils.Pipeline.GroupsStranded.Add(1)
		if metaUtils.IsMsgSeqLogsEnabled() {
			slog.Warn("msg_seq: stranded group discarded at final flush",
				"fd", conn.connID.Fd,
				"msg_seq", k,
				"direction", g.direction,
				"chunks", len(g.chunks))
		}
		delete(conn.msgGroups, k)
	}

	return pairs
}

// drainPairs walks msgGroups from lowestPendingSeq, pairing consecutive odd+even seqs.
// Gaps are discarded as orphans. The seal func controls when to stop.
// Caller must hold conn.mutex.
func (conn *Tracker) drainPairs(startSeq uint32, sealed func(seq uint32) bool) ([]MsgSeqPair, uint32) {
	seq := startSeq
	if seq == 0 {
		for k := range conn.msgGroups {
			if k%2 == 1 && (seq == 0 || k < seq) {
				seq = k
			}
		}
	}

	var pairs []MsgSeqPair
	for sealed(seq) {
		g1, ok1 := conn.msgGroups[seq]
		g2, ok2 := conn.msgGroups[seq+1]

		if !ok1 || !ok2 {
			skippedSeq := seq
			if ok1 {
				metaUtils.Pipeline.GroupsOrphaned.Add(1)
				if metaUtils.IsMsgSeqLogsEnabled() {
					slog.Warn("msg_seq: orphaned group (partner missing)",
						"fd", conn.connID.Fd,
						"msg_seq", seq,
						"direction", g1.direction,
						"chunks", len(g1.chunks))
				}
				delete(conn.msgGroups, seq)
			}
			if ok2 {
				metaUtils.Pipeline.GroupsOrphaned.Add(1)
				if metaUtils.IsMsgSeqLogsEnabled() {
					slog.Warn("msg_seq: orphaned group (partner missing)",
						"fd", conn.connID.Fd,
						"msg_seq", seq+1,
						"direction", g2.direction,
						"chunks", len(g2.chunks))
				}
				delete(conn.msgGroups, seq+1)
			}
			if seq%2 == 0 {
				seq++
			} else {
				seq += 2
			}
			metaUtils.Pipeline.GapSkipsFired.Add(1)
			metaUtils.Pipeline.GapSkipSeqsLost.Add(int64(seq - skippedSeq))
			if metaUtils.IsMsgSeqLogsEnabled() {
				slog.Warn("msg_seq: gap-skip",
					"fd", conn.connID.Fd,
					"skipped_from", skippedSeq,
					"lowestPendingSeq_after", seq,
					"highestMsgSeq", conn.highestMsgSeq)
			}
			continue
		}

		if metaUtils.IsMsgSeqLogsEnabled() {
			slog.Info("msg_seq: flushing pair",
				"fd", conn.connID.Fd,
				"req_msg_seq", g1.msgSeq,
				"resp_msg_seq", g2.msgSeq,
				"req_chunks", len(g1.chunks),
				"resp_chunks", len(g2.chunks),
				"remaining_groups", len(conn.msgGroups)-2)
		}

		pairs = append(pairs, MsgSeqPair{ReqGroup: g1, RespGroup: g2})
		delete(conn.msgGroups, seq)
		delete(conn.msgGroups, seq+1)
		seq += 2
	}
	return pairs, seq
}

func (conn *Tracker) GetSentBytes() uint64 {
	return conn.sentBytes
}

func (conn *Tracker) GetRecvBytes() uint64 {
	return conn.recvBytes
}