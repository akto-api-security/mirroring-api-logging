package connections

// Per-stage throughput/cost benchmarks for the ingest->tracker->flush pipeline,
// mirroring trafficUtil/fastparser's parser/encoder benchmarks (same
// b.SetBytes+b.ReportAllocs idiom) so all stages report comparable
// ns/op, B/op, allocs/op, and MB/s — enough to derive "cores needed for
// 1 GiB/s" and "bytes allocated per GiB/s" per stage. 4kb payload only
// (matches the rate-sweep harness's primary fixture); see fastparser's own
// benchmarks for the 256b..64kb size curve on parse/encode specifically.
//
// Stages NOT covered here (parse + encode) already have benchmarks in
// trafficUtil/fastparser/httpparser_test.go (BenchmarkParseRequest/Response)
// and trafficUtil/fastparser/jsonEncoder_test.go (BenchmarkJSONEncode) — reuse
// those rather than duplicating.

import (
	"os"
	"testing"
	"unsafe"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/structs"
	kafka "github.com/akto-api-security/mirroring-api-logging/trafficUtil/kafkaUtil"
	metaUtils "github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

// TestMain enables the msg_seq path for the whole package's benchmark run:
// AddDataEvent only populates msgGroups (vs. the old flat sentBuf/recvBuf map)
// when FastIngestion is true — without this, GetFlushablePairs/fragmentsToBytes
// benchmarks below would silently see an empty Tracker and no-op.
//
// KafkaDisabled/ThreatEnabled=false mirror callback_ratesweep_test.go's setup:
// BenchmarkSocketDataEventCallback spawns a real Factory/Worker, which (since
// FastIngestion=true) spawns a real background flush routine — its 500ms
// ticker will find genuinely flushable pairs during the benchmark and call
// all the way through to ProduceStr/the threat-Produce path, which panics on
// a nil Kafka writer if not disabled.
func TestMain(m *testing.M) {
	metaUtils.FastIngestion = true
	kafka.KafkaDisabled = true
	metaUtils.ThreatEnabled = false
	m.Run()
}

// pbLoad mirrors rsLoad (callback_ratesweep_test.go) but takes testing.TB so
// it works from benchmarks too (rsLoad is *testing.T-only).
func pbLoad(b *testing.B, name string) []byte {
	buf, err := os.ReadFile("../../testdata/" + name)
	if err != nil {
		b.Fatalf("read fixture %s: %v", name, err)
	}
	return buf
}

// pbFixtures are the 4kb fixtures also used by callback_ratesweep_test.go.
func pbFixtures(b *testing.B) (reqBytes, respBytes []byte) {
	return pbLoad(b, "req-4kb.bin"), pbLoad(b, "resp-4kb.bin")
}

// pbEvents pre-splits req+resp into the chunk-events a real kernel would emit
// for one HTTP request-response pair (same chunking rsEmit does), so the
// benchmarked stage does exactly the per-event work production would.
func pbEvents(connID uint64, fd uint32, msgSeqBase uint32, reqBytes, respBytes []byte) [][]byte {
	var events [][]byte
	collect := func(e []byte) { events = append(events, e) }
	rsEmit(collect, connID, fd, msgSeqBase, 1, reqBytes)   // ingress = request
	rsEmit(collect, connID, fd, msgSeqBase+1, 0, respBytes) // egress = response
	return events
}

// --- Stage 1: SocketDataEventCallback (ingest boundary) ---
//
// Benchmarks the full callback: port-filter, CreateIfNotExists, SendDataEvent.
// Uses a real Factory + a background drain of the per-connection channel (via
// a real Worker) so SendDataEvent never blocks/drops on a full channel, which
// would otherwise understate the callback's own per-event cost.
func BenchmarkSocketDataEventCallback(b *testing.B) {
	reqBytes, respBytes := pbFixtures(b)
	totalBytes := int64(len(reqBytes) + len(respBytes))

	factory := NewFactory()
	inputChan := make(chan []byte, 1<<20) // large enough to never block the benchmark loop itself
	connID := structs.ConnID{Id: 1, Fd: 1, Rport: 8888}
	factory.CreateIfNotExists(connID) // spawns a real Worker+flush goroutine on its own internal channel

	// Hijack the per-conn channel mapping so SendDataEvent (called from
	// SocketDataEventCallback below) writes into a channel THIS benchmark
	// drains with a no-op reader, instead of the real Worker's channel. The
	// real Worker/flush goroutine spawned by CreateIfNotExists above is left
	// idling on its own (now unfed) channel — harmless, no CPU cost, it just
	// times out on its 7s inactivity timer eventually.
	//
	// Without this, AddDataEvent/GetFlushablePairs/fragmentsToBytes/parse/
	// encode/Kafka-produce all run concurrently with the timed loop for the
	// whole benchmark duration, and their CPU/GC cost contaminates the
	// profile — those stages already have their own isolated benchmarks
	// above; this one is scoped to SocketDataEventCallback's own code path
	// only (port-filter, CreateIfNotExists' existence-check, SendDataEvent).
	drainChan := make(chan interface{}, 1<<16)
	factory.processor[connID] = drainChan
	go func() {
		for range drainChan {
		}
	}()

	go SocketDataEventCallback(inputChan, factory)

	// Pre-build the two event templates (req + resp; the 4kb fixture is a
	// single chunk each, so pbEvents always returns exactly these two) ONCE,
	// outside the timed loop, so per-call construction never counts against
	// the callback's own cost.
	template := pbEvents(1, 1, 1, reqBytes, respBytes)
	if len(template) != 2 {
		b.Fatalf("expected 2 events (1 req + 1 resp chunk) for the 4kb fixture, got %d", len(template))
	}

	b.ReportAllocs()
	b.SetBytes(totalBytes)
	for i := 0; i < b.N; i++ {
		// Every iteration uses a globally unique msg_seq derived from i
		// (never repeats within this run, so no uint32 wraparound risk at
		// any realistic b.N) — NOT a fixed or pool-recycled value. AddDataEvent
		// appends onto msgGroups[msg_seq].fragments, and the background flush
		// ticker (500ms) is far slower than this tight loop: with a fixed or
		// small-pool-recycled msg_seq, this loop revisits the same group many
		// times before flush ever clears it, so fragments pile up unboundedly
		// and runtime.memmove (slice-growth copying) dominates the profile
		// instead of the callback's real steady-state per-event cost — this
		// is exactly the bug an earlier version of this benchmark had.
		base := uint32(i*2 + 1) // template[0]=request (odd), template[1]=response (base+1, even)
		for j, e := range template {
			// Fresh slice per send, with msg_seq patched in place: the real
			// perf-buffer reader hands off a unique C.GoBytes-backed []byte
			// per event, and reusing the template's bytes directly (without
			// copying) would let the callback observe stale/aliased data
			// once a worker goroutine is genuinely concurrent with this loop.
			cp := make([]byte, len(e))
			copy(cp, e)
			(*structs.SocketDataEventAttr)(unsafe.Pointer(&cp[0])).MsgSeq = base + uint32(j)
			inputChan <- cp
		}
	}
	b.StopTimer()
	close(inputChan)
	close(drainChan)
	// The real Worker/flush goroutine spawned by CreateIfNotExists above
	// never received any events (hijacked away to drainChan) and exits on
	// its own via its 7s inactivity timer — harmless, no cleanup needed here.
}

// --- Stage 2: Tracker.AddDataEvent (per-event tracker ingest) ---
//
// Isolates just the mutex+fragment-append cost, bypassing the callback/channel
// layer entirely — this is the "how expensive is one AddDataEvent call" number.
func BenchmarkAddDataEvent(b *testing.B) {
	reqBytes, respBytes := pbFixtures(b)
	totalBytes := int64(len(reqBytes) + len(respBytes))
	events := pbEvents(1, 1, 1, reqBytes, respBytes)

	b.ReportAllocs()
	b.SetBytes(totalBytes)
	for i := 0; i < b.N; i++ {
		tracker := NewTracker(structs.ConnID{Id: 1, Fd: 1})
		for _, e := range events {
			cp := make([]byte, len(e))
			copy(cp, e)
			tracker.AddDataEvent(&cp)
		}
	}
}

// --- Stage 3: GetFlushablePairs / drainPairs (sequencing) ---
//
// Pre-loads a Tracker with N complete request-response pairs' worth of
// msg_seq groups (as AddDataEvent would leave them), then benchmarks just the
// drain/pair/gap-skip walk — no event-ingest cost included.
func BenchmarkGetFlushablePairs(b *testing.B) {
	reqBytes, respBytes := pbFixtures(b)
	const pairsPerIter = 50 // groups accumulated before one flush call, ~real flush-tick batch size

	b.ReportAllocs()
	b.SetBytes(int64(len(reqBytes)+len(respBytes)) * pairsPerIter)
	for i := 0; i < b.N; i++ {
		tracker := NewTracker(structs.ConnID{Id: 1, Fd: 1})
		msgSeq := uint32(1)
		for p := 0; p < pairsPerIter; p++ {
			for _, e := range pbEvents(1, 1, msgSeq, reqBytes, respBytes) {
				cp := make([]byte, len(e))
				copy(cp, e)
				tracker.AddDataEvent(&cp)
			}
			msgSeq += 2
		}
		// One more group so the last real pair's seq+2 <= highestMsgSeq (GetFlushablePairs'
		// seal condition) and it's actually eligible to flush, not just sequenced.
		for _, e := range pbEvents(1, 1, msgSeq, reqBytes, respBytes) {
			cp := make([]byte, len(e))
			copy(cp, e)
			tracker.AddDataEvent(&cp)
		}

		pairs := tracker.GetFlushablePairs()
		if len(pairs) == 0 {
			b.Fatal("expected flushable pairs, got 0 — benchmark setup drifted from drainPairs' seal condition")
		}
	}
}

// --- Stage 4: fragmentsToBytes (chunk reassembly at flush time) ---
//
// Isolates the sort+join cost on one message's fragments. reqBytes at 4kb
// with MAX_MSG_SIZE=30720 fits in a single fragment (no multi-chunk sort
// needed) — this benchmark therefore measures the single-fragment floor cost
// (mostly the pre-sized allocation + one append), not the sort. See
// fragmentsToBytes' own doc comment for the multi-fragment sort behavior;
// benchmark 64kb-class payloads separately if the sort cost itself needs
// isolating (out of scope for this 4kb pass per current ask).
func BenchmarkFragmentsToBytes(b *testing.B) {
	reqBytes, _ := pbFixtures(b)

	var frags []fragment
	off, seq := 0, 1
	for off < len(reqBytes) {
		end := off + rsMaxMsgChunk
		if end > len(reqBytes) {
			end = len(reqBytes)
		}
		frags = append(frags, fragment{seq: seq, data: reqBytes[off:end]})
		off = end
		seq++
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(reqBytes)))
	for i := 0; i < b.N; i++ {
		// fragmentsToBytes sorts in place; pass a fresh copy of the slice
		// header each iteration (fragment structs are small/cheap to copy,
		// underlying data arrays are shared/untouched by the sort).
		cp := make([]fragment, len(frags))
		copy(cp, frags)
		out := fragmentsToBytes(cp)
		if len(out) != len(reqBytes) {
			b.Fatalf("got %d bytes, want %d", len(out), len(reqBytes))
		}
	}
}

var _ = unsafe.Sizeof(structs.SocketDataEventAttr{}) // silence unused-import if trimmed later
