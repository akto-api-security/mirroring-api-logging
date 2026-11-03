package connections

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/structs"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
	"github.com/google/uuid"
)

var (
	disableEgress        = true
	maxActiveConnections = 4096
	inactivityThreshold  = 7 * time.Second
	bufferMemThreshold   = 400 // MB of Go heap; above it buffered bytes are dropped
	memCheckInterval     = 500 // ms

	uniqueDaemonsetId = uuid.New().String()

	sampleBufferPerMin       = -1
	currentTotalBuffer int64 = 0
	bufferMutex              = sync.Mutex{}
	lastReset                = time.Now()
)

// Server ports whose traffic is never HTTP (and is often Akto's own: Kafka,
// Mongo). TRAFFIC_IGNORE_DEFAULT_PORTS=false turns this off.
var (
	ignorePorts    = true
	ignorePortsSet = map[uint16]bool{
		9092: true, 19092: true, 29092: true, // kafka
		2181:  true, // zookeeper
		27017: true, // mongo
		6379:  true, // redis
	}
)

func ignoredServerPort(p uint16) bool { return ignorePorts && ignorePortsSet[p] }

func init() {
	utils.InitVar("TRAFFIC_IGNORE_DEFAULT_PORTS", &ignorePorts)
	utils.InitVar("TRAFFIC_DISABLE_EGRESS", &disableEgress)
	utils.InitVar("TRAFFIC_MAX_ACTIVE_CONN", &maxActiveConnections)
	utils.InitVar("TRAFFIC_INACTIVITY_THRESHOLD", &inactivityThreshold)
	utils.InitVar("TRAFFIC_BUFFER_THRESHOLD", &bufferMemThreshold)
	utils.InitVar("AKTO_MEM_SOFT_LIMIT", &bufferMemThreshold)
	utils.InitVar("TRAFFIC_SAMPLE_BUFFER_PER_MINUTE", &sampleBufferPerMin)
	utils.InitVar("MODULE_MEM_CHECK_INTERVAL", &memCheckInterval)
}

// headerRoom is what a message may hold beyond the body cap (start line + headers).
const headerRoom = 64 << 10

// bodyCap is the most body bytes kept per message (SOCKET_DATA_EVENT_BYTES_THRESHOLD).
func bodyCap() int {
	if n := utils.SocketDataEventBytesThreshold; n > 0 {
		return n
	}
	return 10 << 20
}

// groupCap is the most bytes buffered for one message.
func groupCap() int { return bodyCap() + headerRoom }

var (
	activeConns atomic.Int64
	heldBytes   atomic.Int64
	wipeEpoch   atomic.Uint64
)

// Factory owns one Shard per kernel ring buffer shard.
type Factory struct {
	shards []*Shard
}

func NewFactory(nShards int) *Factory {
	f := &Factory{shards: make([]*Shard, nShards)}
	for i := range f.shards {
		f.shards[i] = &Shard{conns: make(map[structs.ConnID]*conn)}
	}
	startMemoryWatch()
	return f
}

func (f *Factory) Shard(i int) *Shard { return f.shards[i] }

// Shard holds the connections whose records arrive on one ring buffer. It is
// owned by that ring's single reader goroutine and is not safe for concurrent
// use.
type Shard struct {
	conns     map[structs.ConnID]*conn
	lastSweep time.Time
	epoch     uint64
}

// SweepInterval is how often the reader calls Sweep when the ring is idle.
func SweepInterval() time.Duration {
	d := inactivityThreshold / 4
	if d < 100*time.Millisecond {
		d = 100 * time.Millisecond
	}
	if d > time.Second {
		d = time.Second
	}
	return d
}

func (s *Shard) get(id structs.ConnID, create bool, now int64) *conn {
	key := id.Key()
	c := s.conns[key]
	if c == nil && create {
		if activeConns.Load() >= int64(maxActiveConnections) {
			return nil
		}
		c = &conn{id: key}
		s.conns[key] = c
		activeConns.Add(1)
	}
	if c != nil {
		c.lastSeen = now
	}
	return c
}

func (s *Shard) remove(c *conn) {
	if _, ok := s.conns[c.id]; ok {
		delete(s.conns, c.id)
		activeConns.Add(-1)
	}
}

var (
	openEventSize  = int(unsafe.Sizeof(structs.SocketOpenEvent{}))
	closeEventSize = int(unsafe.Sizeof(structs.SocketCloseEvent{}))
)

// HandleRecord processes one ring record. data is only valid during the call.
func (s *Shard) HandleRecord(data []byte, now time.Time) {
	if len(data) < 16 {
		return
	}
	nowNs := now.UnixNano()
	switch binary.LittleEndian.Uint32(data[12:16]) {
	case structs.EventData:
		if len(data) < structs.MsgPayloadOffset {
			return
		}
		attr, n, ok := dataAttr(data)
		if !ok {
			return
		}
		if c := s.get(attr.ConnId, true, nowNs); c != nil {
			c.onData(&attr, data[structs.MsgPayloadOffset:structs.MsgPayloadOffset+n])
		}
	case structs.EventOpen:
		if len(data) < openEventSize {
			return
		}
		ev := (*structs.SocketOpenEvent)(unsafe.Pointer(&data[0]))
		if c := s.get(ev.ConnId, true, nowNs); c != nil {
			c.laddr, c.lport, c.ctx = ev.SrcIp, ev.SrcPort, nil
			c.opened = true
		}
	case structs.EventClose:
		if len(data) < closeEventSize {
			return
		}
		ev := (*structs.SocketCloseEvent)(unsafe.Pointer(&data[0]))
		if c := s.get(ev.ConnId, false, nowNs); c != nil {
			c.onClose(ev.LostRead, ev.LostWrite)
			s.remove(c)
		}
	}
	if now.Sub(s.lastSweep) >= SweepInterval() {
		s.Sweep(now)
	}
}

func dataAttr(data []byte) (attr structs.SocketDataEventAttr, n int, ok bool) {
	if len(data) < structs.MsgPayloadOffset {
		return attr, 0, false
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&attr)), unsafe.Sizeof(attr)), data[:structs.MsgPayloadOffset])
	n = int(attr.Bytes_sent)
	if n < 0 {
		n = -n
	}
	return attr, n, n > 0 && len(data) >= structs.MsgPayloadOffset+n
}

// DropData discards a data record (ingest filters) while keeping the
// connection's byte accounting exact: the next chunk carries the hole.
func (s *Shard) DropData(data []byte) {
	attr, n, ok := dataAttr(data)
	if !ok {
		return
	}
	if c := s.conns[attr.ConnId.Key()]; c != nil {
		c.dropData(&attr, n)
	}
}

// Sweep finishes idle connections and applies memory pressure.
func (s *Shard) Sweep(now time.Time) {
	s.lastSweep = now
	wipe := false
	if e := wipeEpoch.Load(); e != s.epoch {
		s.epoch = e
		wipe = true
	}
	idleBefore := now.Add(-inactivityThreshold).UnixNano()
	for _, c := range s.conns {
		if c.lastSeen < idleBefore {
			c.finish()
			s.remove(c)
			continue
		}
		if wipe {
			c.wipe()
		}
	}
}

var memWatchOnce sync.Once

// startMemoryWatch bumps wipeEpoch when the heap passes the soft limit; every
// shard then drops everything it has buffered on its next sweep.
func startMemoryWatch() {
	memWatchOnce.Do(func() {
		go func() {
			t := time.NewTicker(time.Duration(memCheckInterval) * time.Millisecond)
			defer t.Stop()
			for range t.C {
				if utils.LogMemoryStats() >= bufferMemThreshold {
					wipeEpoch.Add(1)
				}
			}
		}()
	})
}

// BufferCheck applies TRAFFIC_SAMPLE_BUFFER_PER_MINUTE.
func BufferCheck() bool {
	if sampleBufferPerMin == -1 {
		return true
	}
	bufferMutex.Lock()
	defer bufferMutex.Unlock()
	if time.Since(lastReset) > time.Minute {
		lastReset = time.Now()
		currentTotalBuffer = 0
	}
	return currentTotalBuffer < int64(sampleBufferPerMin*1024*1024)
}

func UpdateBufferSize(bufferSize uint64) {
	if sampleBufferPerMin == -1 {
		return
	}
	bufferMutex.Lock()
	currentTotalBuffer += int64(bufferSize)
	bufferMutex.Unlock()
}

// CanBeFilled reports whether a new connection may be tracked.
func CanBeFilled() bool {
	return activeConns.Load() < int64(maxActiveConnections)
}

// ---------------------------------------------------------------------------
// Capture counters. main.go appends StatsArgs to its periodic
// "BPF ringbuf submit stats" line; each call reports the window since the last.

var (
	pairsEmitted        atomic.Uint64
	http2Streams        atomic.Uint64
	http2ConnFailed     atomic.Uint64
	lostBytes           atomic.Uint64
	desyncs             atomic.Uint64
	desyncedConns       atomic.Uint64
	orphanMessages      atomic.Uint64
	truncatedPairs      atomic.Uint64
	cappedMessages      atomic.Uint64
	pipelinedConns      atomic.Uint64
	memWipes            atomic.Uint64
	ignoredConns        atomic.Uint64
	ignoredUnknown      atomic.Uint64
	unansweredAtEnd     atomic.Uint64
	tlsWithoutPlaintext atomic.Uint64
)

// StatsArgs returns the capture counters as slog key/value pairs and resets them.
func StatsArgs() []any {
	return []any{
		"connections", activeConns.Load(),
		"held_kb", heldBytes.Load() / 1024,
		"pairs", pairsEmitted.Swap(0),
		"h2_streams", http2Streams.Swap(0),
		"h2_conn_failed", http2ConnFailed.Swap(0),
		"lost_bytes", lostBytes.Swap(0),
		"desyncs", desyncs.Swap(0),
		"pipelined_desync_drops", desyncedConns.Swap(0),
		"orphans", orphanMessages.Swap(0),
		"truncated_pairs", truncatedPairs.Swap(0),
		"capped_messages", cappedMessages.Swap(0),
		"pipelined_conns", pipelinedConns.Swap(0),
		"mem_wiped_conns", memWipes.Swap(0),
		"ignored_conns", ignoredConns.Swap(0),
		"ignored_unclassified", ignoredUnknown.Swap(0),
		"unanswered_at_end", unansweredAtEnd.Swap(0),
		"tls_without_plaintext", tlsWithoutPlaintext.Swap(0),
	}
}
