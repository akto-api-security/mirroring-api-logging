package connections

import (
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

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
}

func NewTracker(connID structs.ConnID) *Tracker {
	return &Tracker{
		connID:    connID,
		recvBuf:   make(map[int][]byte),
		sentBuf:   make(map[int][]byte),
		mutex:     sync.RWMutex{},
		ssl:       false,
		foundHTTP: false,
		msgGroups: make(map[uint32]*msgSeqGroup),
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

func (conn *Tracker) AddDataEvent(event *structs.SocketDataEvent) {
	lockStart := time.Now()
	conn.mutex.Lock()
	lockWait := time.Since(lockStart)
	if lockWait > 1*time.Millisecond && metaUtils.IsMsgSeqLogsEnabled() {
		slog.Warn("msg_seq: AddDataEvent mutex wait",
			"fd", conn.connID.Fd,
			"wait_ms", lockWait.Milliseconds())
	}
	defer conn.mutex.Unlock()

	if event.Attr.Laddr != 0 {
		conn.laddr = event.Attr.Laddr
		conn.lport = event.Attr.Lport
	}
	if event.Attr.Role != 0 && conn.role == 0 {
		conn.role = event.Attr.Role
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
	absBytes := utils.Abs(bytesSent)

	if UseMsgSeqFlush {
		// msg_seq based buffering for incremental pair flushing
		msgSeq := event.Attr.MsgSeq
		if msgSeq > 0 {
			group, exists := conn.msgGroups[msgSeq]
			if !exists {
				if msgSeq < conn.lowestPendingSeq {
					metaUtils.Pipeline.LateArrivals.Add(1)
					if metaUtils.IsMsgSeqLogsEnabled() {
						slog.Warn("msg_seq: late arrival below lowestPendingSeq (already flushed)",
							"fd", conn.connID.Fd,
							"msg_seq", msgSeq,
							"lowestPendingSeq", conn.lowestPendingSeq)
					}
				} else if msgSeq < conn.highestMsgSeq {
					metaUtils.Pipeline.OutOfOrderArrivals.Add(1)
					if metaUtils.IsMsgSeqLogsEnabled() {
						slog.Warn("msg_seq: out-of-order group arrival",
							"fd", conn.connID.Fd,
							"msg_seq", msgSeq,
							"highestMsgSeq", conn.highestMsgSeq)
					}
				}
				group = &msgSeqGroup{
					msgSeq:    msgSeq,
					direction: event.Attr.Direction,
					chunks:    make(map[int][]byte),
				}
				conn.msgGroups[msgSeq] = group
				metaUtils.Pipeline.GroupsCreated.Add(1)
			}

			var chunkKey int
			if group.direction == 0 { // kEgress
				chunkKey = int(event.Attr.WriteEventsCount)
			} else { // kIngress
				chunkKey = int(event.Attr.ReadEventsCount)
			}
			group.chunks[chunkKey] = append(group.chunks[chunkKey], event.Msg[:absBytes]...)

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
		// Old flat buffer path
		if bytesSent > 0 {
			conn.sentBuf[int(event.Attr.WriteEventsCount)] = append(conn.sentBuf[int(event.Attr.WriteEventsCount)], event.Msg[:absBytes]...)
			conn.sentBytes += uint64(absBytes)
		} else {
			conn.recvBuf[int(event.Attr.ReadEventsCount)] = append(conn.recvBuf[int(event.Attr.ReadEventsCount)], event.Msg[:absBytes]...)
			conn.recvBytes += uint64(absBytes)
		}
	}

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
	conn.laddr = event.Laddr
	conn.lport = event.Lport
}

func (conn *Tracker) AddCloseEvent(event structs.SocketCloseEvent) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	conn.closeTimestamp = uint64(time.Now().UnixNano())
	conn.lastAccessTimestamp = uint64(time.Now().UnixNano())
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