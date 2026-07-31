package connections

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/structs"
	kafka "github.com/akto-api-security/mirroring-api-logging/trafficUtil/kafkaUtil"
	metaUtils "github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

// Rate-sweep knobs, settable on the command line (after `-args`), e.g.:
//
//	go test -run TestRateSweep ./connections/ -args -testname=myrun -rps=300K -parse=on -gomaxprocs=4
var (
	rsParseFlag = flag.String("parse", "both", "rate-sweep arm(s): on | off | both")
	rsGmpFlag   = flag.Int("gomaxprocs", 4, "GOMAXPROCS for the rate sweep")
	rsTestName  = flag.String("testname", "ratesweep", "output subdir under pprof/ for this run's profiles")
	rsRps       = flag.String("rps", "", "single offered rate e.g. 100K|200K|300K|500K (empty => default sweep)")
	rsWindowFlg = flag.Duration("window", 5*time.Second, "sustained-load duration per cell, e.g. 30s")
	rsEncoder   = flag.String("encoder", "both", "fast-path wire encoder: json | flatbuffers | both")
)

// rsParseRate turns "300K"/"2M"/"50000" into an int events/sec.
func rsParseRate(t *testing.T, s string) int {
	u := strings.ToUpper(strings.TrimSpace(s))
	mult := 1
	switch {
	case strings.HasSuffix(u, "K"):
		mult, u = 1_000, strings.TrimSuffix(u, "K")
	case strings.HasSuffix(u, "M"):
		mult, u = 1_000_000, strings.TrimSuffix(u, "M")
	}
	n, err := strconv.Atoi(u)
	if err != nil {
		t.Fatalf("invalid -rps=%q: %v", s, err)
	}
	return n * mult
}

// rsWriteProfile dumps a named runtime profile ("heap"/"goroutine"/"allocs") or
// the heap to path. Safe to call from any goroutine (no *testing.T use).
func rsWriteProfile(name, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if name == "heap" {
		runtime.GC()
		return pprof.WriteHeapProfile(f)
	}
	p := pprof.Lookup(name)
	if p == nil {
		return fmt.Errorf("no profile %q", name)
	}
	return p.WriteTo(f, 0)
}

// Rate-sweep harness: a producer paced to a fixed events/sec feeds a bounded
// channel; the REAL SocketDataEventCallback drains it into the REAL per-conn
// worker + flush + parse path. We find the rate at which the pipeline stops
// keeping up.
//
//	producer (rate R, non-blocking send) → eventChan(cap=EventChanBuffSize)
//	     → SocketDataEventCallback (real) → SendDataEvent → per-conn worker
//	     → flush routine (500ms) → ProcessSinglePair → parse (KafkaDisabled=true: no produce)
//
// Drop points:
//
//	kernelDrops  — eventChan full: callback can't drain (kernel-drop analog)
//	perConnDrops — per-conn channel full: worker/flush/parse can't drain
//
// Metrics split:
//
//	consumed/s, evChanLen  — captured at window end (sustained-load rate/saturation)
//	cov%, drops            — captured after a quiescence drain (eventual outcome)
//
// Run:  go test -run RateSweep -v ./connections/
const (
	rsMaxMsgChunk = 30720  // MAX_MSG_SIZE — messages larger than this arrive as multiple chunk-events
	rsChanCap     = 100000 // = EVENT_CHAN_BUFF_SIZE (prod default)
	rsConns       = 300
	rsFixture     = "4kb" // one payload size per run
)

func rsLoad(t *testing.T, name string) []byte {
	b, err := os.ReadFile("../../testdata/" + name)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

// rsWrap builds one perf-buffer wire event: [attr region (MsgOffset=68B)][chunk].
func rsWrap(connID uint64, fd uint32, msgSeq, direction, rc, wc uint32, chunk []byte) []byte {
	data := make([]byte, structs.MsgOffset+len(chunk))
	attr := (*structs.SocketDataEventAttr)(unsafe.Pointer(&data[0]))
	attr.ConnId.Id = connID
	attr.ConnId.Fd = fd
	attr.ConnId.Rport = 8888 // not in ignorePortsMap
	attr.Bytes_sent = int32(len(chunk))
	attr.MsgSeq = msgSeq
	attr.Direction = direction // 1=ingress(req), 0=egress(resp)
	attr.ReadEventsCount = rc
	attr.WriteEventsCount = wc
	copy(data[structs.MsgOffset:], chunk)
	return data
}

// rsEmit splits payload into <=MAX_MSG_SIZE chunk-events under one msg_seq
// (faithful to how the kernel chunks a large message), returns events emitted.
func rsEmit(send func([]byte), connID uint64, fd uint32, msgSeq, direction uint32, payload []byte) {
	for off, idx := 0, uint32(1); off < len(payload); idx++ {
		end := off + rsMaxMsgChunk
		if end > len(payload) {
			end = len(payload)
		}
		var rc, wc uint32
		if direction == 1 {
			rc = idx
		} else {
			wc = idx
		}
		send(rsWrap(connID, fd, msgSeq, direction, rc, wc, payload[off:end]))
		off = end
	}
}

// rsComma formats n with US-style thousands separators, e.g. 4499555 -> "4,499,555".
func rsComma(n int64) string {
	s := fmt.Sprintf("%d", n)
	neg := ""
	if strings.HasPrefix(s, "-") {
		neg, s = "-", s[1:]
	}
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	return neg + b.String()
}

// rsRateLabel formats a rate for use as a directory name, e.g. 50000 -> "50k",
// 1000000 -> "1m", 123456 -> "123456" (falls back to the raw number if it
// doesn't divide evenly into K/M).
func rsRateLabel(rate int) string {
	switch {
	case rate != 0 && rate%1_000_000 == 0:
		return fmt.Sprintf("%dm", rate/1_000_000)
	case rate != 0 && rate%1_000 == 0:
		return fmt.Sprintf("%dk", rate/1_000)
	default:
		return fmt.Sprintf("%d", rate)
	}
}

type rsConn struct {
	id     uint64
	fd     uint32
	msgSeq uint32
	isReq  bool
}

// cd /Users/mann/workspace/mirroring-api-logging-2/ebpf
// Flags go AFTER `-args` (else `go test` mis-parses the package path and builds the bcc root pkg).
// Single rate + pprof capture (cpu whole-duration, periodic heap, goroutine, allocs) under pprof/<testname>/<arm>/<rate>/:
//
//	AKTO_MEM_THRESH_RESTART=12000 AKTO_SYS_MEM_HARD_LIMIT=14000 go test -run TestRateSweep -v -count=1 -timeout 400s ./connections/ -args -testname=myrun -rps=300K -parse=on -gomaxprocs=4 2>&1 | grep -vE "level=(WARN|INFO)|logger.go|Setting up|Logger setup|File logging" | tail -12
//
// Omit -rps to run the full 50K..500K sweep (no pprof needed, but still captured per cell).
func TestRateSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("rate sweep is a long-running perf harness; run explicitly with -run RateSweep")
	}

	prev := runtime.GOMAXPROCS(*rsGmpFlag)
	defer runtime.GOMAXPROCS(prev)

	// Enable mutex profiling (off by default). Fraction=1 samples every contention
	// event. NOTE: the mutex profile is cumulative process-wide (no per-cell reset),
	// so with -parse=both the 2nd arm's mutex.prof includes the 1st.
	runtime.SetMutexProfileFraction(1)
	defer runtime.SetMutexProfileFraction(0)

	// -parse selects which arm(s) to sweep. skip=true => parse-off (ingest only).
	var arms []bool
	switch *rsParseFlag {
	case "on":
		arms = []bool{false}
	case "off":
		arms = []bool{true}
	case "both":
		arms = []bool{true, false}
	default:
		t.Fatalf("invalid -parse=%q (want on|off|both)", *rsParseFlag)
	}

	// Test env: no broker (parse runs, produce is a no-op), fast worker teardown.
	// ProduceStr is guarded by KafkaDisabled; the threat Produce path is not, so
	// disable threat too, else it dials a nil Kafka writer and panics.
	kafka.KafkaDisabled = true      // ProduceStr no-ops; parse still runs
	metaUtils.ThreatEnabled = false // threat Produce path is unguarded → would panic on nil writer

	// -encoder selects which fast-path wire encoder(s) to sweep. parse-off never
	// reaches the encoder (SkipPairProcessing returns before fastParseAndProduce),
	// so this only affects the parse-on arm.
	var encoders []string
	switch strings.ToLower(*rsEncoder) {
	case "both":
		encoders = []string{"json", "flatbuffers"}
	case "json", "flatbuffers":
		encoders = []string{strings.ToLower(*rsEncoder)}
	default:
		t.Fatalf("invalid -encoder=%q (want json|flatbuffers|both)", *rsEncoder)
	}

	UseMsgSeqFlush = true
	inactivityThreshold = 1 * time.Second
	PerConnChBufferSize = 200 // per-conn channel depth under test
	maxActiveConnections = rsConns + 10
	// NOTE: the os.Exit memory watchdog (utils.LogMemoryStats, read from env in
	// utils.init()) must be raised at launch — it can't be set from here:
	//   AKTO_MEM_THRESH_RESTART / AKTO_SYS_MEM_HARD_LIMIT

	reqBytes := rsLoad(t, "req-"+rsFixture+".bin")
	respBytes := rsLoad(t, "resp-"+rsFixture+".bin")
	evPerReq := (len(reqBytes)+rsMaxMsgChunk-1)/rsMaxMsgChunk + (len(respBytes)+rsMaxMsgChunk-1)/rsMaxMsgChunk

	// -rps=300K runs a single rate (and captures pprof); empty => the full sweep.
	rates := []int{50_000, 100_000, 200_000, 300_000, 500_000}
	if *rsRps != "" {
		rates = []int{rsParseRate(t, *rsRps)}
	}

	t.Logf("payload=%s  reqBytes=%d respBytes=%d  events/pair=%d  GOMAXPROCS=%d  chanCap=%d  encoders=%v",
		rsFixture, len(reqBytes), len(respBytes), evPerReq, runtime.GOMAXPROCS(0), rsChanCap, encoders)
	t.Logf("%-16s %8s %10s %11s %12s %10s %10s %10s %9s",
		"arm", "rate/s", "offered/s", "kernelDrop%", "perConnDrop%", "evChanLen", "consumed/s", "pairs_ok/s", "cov%")

	for _, skip := range arms {
		kafka.SkipPairProcessing = skip
		arm := "parse-on"
		if skip {
			arm = "parse-off"
		}

		// parse-off never reaches the encoder, so sweep it once (no encoder
		// dimension). parse-on runs the FULL rate sweep for one encoder, then the
		// full rate sweep again for the next — encoder is the outer loop so
		// json's whole sweep completes before flatbuffers starts, keeping every
		// other arg identical for a clean before/after comparison.
		cellEncoders := encoders
		if skip {
			cellEncoders = []string{""}
		}

		for _, encoder := range cellEncoders {
			if !skip {
				// Must be set before the first fastParseAndProduce: encoderPool is
				// a sync.Pool that builds lazily on first Get, reading the encoder
				// kind at that moment. Set once per encoder, before its rate sweep.
				if !kafka.SetFastEncoder(encoder) {
					t.Fatalf("invalid encoder %q", encoder)
				}
			}
			for _, rate := range rates {
				metaUtils.Pipeline.Reset()
				factory := NewFactory()

				// eventChan models the Go event channel the kernel/gobpf delivers into
				// (prod: inputChan, cap=EVENT_CHAN_BUFF_SIZE). A failed non-blocking send
				// here == the kernel perf buffer overflowing == a kernel drop.
				eventChan := make(chan []byte, rsChanCap)
				go SocketDataEventCallback(eventChan, factory)

				conns := make([]*rsConn, rsConns)
				for i := range conns {
					conns[i] = &rsConn{id: uint64(i + 1), fd: uint32(i + 1), isReq: true}
				}

				// ---- pprof capture for this cell (CPU whole-duration + periodic heap) ----
				// Layout: pprof/<testname>/<arm>[/<encoder>]/<rate label>/
				//   e.g. myrun/parse-on/json/50k, myrun/parse-on/flatbuffers/50k, myrun/parse-off/50k
				profDir := fmt.Sprintf("pprof/%s/%s", *rsTestName, arm)
				if !skip {
					profDir = profDir + "/" + encoder
				}
				profDir = profDir + "/" + rsRateLabel(rate)
				armName := arm
				if !skip {
					armName = arm + "/" + encoder
				}
				if err := os.MkdirAll(profDir, 0o755); err != nil {
					t.Fatalf("mkdir %s: %v", profDir, err)
				}
				cpuF, err := os.Create(profDir + "/cpu.prof")
				if err != nil {
					t.Fatalf("create cpu.prof: %v", err)
				}
				if err := pprof.StartCPUProfile(cpuF); err != nil {
					t.Fatalf("start cpu profile: %v", err)
				}
				heapDone := make(chan struct{})
				go func() {
					tick := time.NewTicker(2 * time.Second)
					defer tick.Stop()
					for n := 0; ; {
						select {
						case <-heapDone:
							return
						case <-tick.C:
							_ = rsWriteProfile("heap", fmt.Sprintf("%s/heap-%d.prof", profDir, n))
							n++
						}
					}
				}()

				// offered     = events the "kernel" tried to deliver
				// kernelDrops = offered events that didn't fit in eventChan (kernel-drop analog)
				var offered, kernelDrops int64
				send := func(b []byte) {
					select {
					case eventChan <- b:
					default:
						atomic.AddInt64(&kernelDrops, 1)
					}
					atomic.AddInt64(&offered, 1)
				}

				start := time.Now()
				ci := 0
				var pairsSent int64 // req+resp pairs fully emitted (counted on the resp half)
				for time.Since(start) < *rsWindowFlg {
					should := int64(float64(rate) * time.Since(start).Seconds())
					for atomic.LoadInt64(&offered) < should {
						cs := conns[ci%rsConns]
						ci++
						cs.msgSeq++
						if cs.isReq {
							rsEmit(send, cs.id, cs.fd, cs.msgSeq, 1, reqBytes)
						} else {
							rsEmit(send, cs.id, cs.fd, cs.msgSeq, 0, respBytes)
							pairsSent++
						}
						cs.isReq = !cs.isReq
					}
					time.Sleep(50 * time.Microsecond)
				}
				elapsed := time.Since(start).Seconds()

				// Window-end metrics (sustained-load rate + saturation). Grab evChanLen
				// now — it reads ~0 after the drain below.
				consumed := metaUtils.Pipeline.EventsReceived.Load()
				eventChanLen := metaUtils.Pipeline.InputChanLen.Load()

				// Drain to quiescence for eventual coverage. The callback stays ALIVE so
				// it feeds the backlog (eventChan + per-conn channels) through; per-conn
				// workers final-flush ~inactivityThreshold after they go idle, releasing
				// the last unsealed pairs. Poll pairsOk until it plateaus (unchanged for
				// ~1.5s, clearing the 500ms flush tick and the 1s inactivity flush).
				// Hard cap ~15s so a bug can't hang the test.
				var lastPairs int64 = -1
				stable := 0
				for i := 0; i < 150; i++ {
					time.Sleep(100 * time.Millisecond)
					p := metaUtils.Pipeline.PairsParseSuccess.Load()
					if p == lastPairs {
						stable++
						if stable >= 15 {
							break
						}
					} else {
						stable = 0
						lastPairs = p
					}
				}

				// ---- stop pprof capture (covers window + drain) and dump the rest ----
				close(heapDone)
				pprof.StopCPUProfile()
				cpuF.Close()
				if err := rsWriteProfile("goroutine", profDir+"/goroutine.prof"); err != nil {
					t.Fatalf("write goroutine profile: %v", err)
				}
				if err := rsWriteProfile("allocs", profDir+"/allocs.prof"); err != nil {
					t.Fatalf("write allocs profile: %v", err)
				}
				if err := rsWriteProfile("mutex", profDir+"/mutex.prof"); err != nil {
					t.Fatalf("write mutex profile: %v", err)
				}
				_ = rsWriteProfile("heap", profDir+"/heap-final.prof")

				// Eventual-outcome metrics (of everything offered, where did it end up).
				//   perConnDrops = per-conn channel overflow (worker/flush/parse too slow)
				pairsOk := metaUtils.Pipeline.PairsParseSuccess.Load()
				perConnDrops := metaUtils.Pipeline.EventsDroppedChannelFull.Load()
				eventChan <- nil // now safe to stop the callback

				offeredN := atomic.LoadInt64(&offered)
				kernelDropN := atomic.LoadInt64(&kernelDrops)
				pct := func(n, d int64) float64 {
					if d == 0 {
						return 0
					}
					return 100 * float64(n) / float64(d)
				}
				// eventual coverage: pairs delivered (after drain) vs pairs offered
				offeredPairs := float64(offeredN) / float64(evPerReq)
				cov := 0.0
				if offeredPairs > 0 {
					cov = 100 * float64(pairsOk) / offeredPairs
				}

				t.Logf("%-16s %8d %10.0f %10.1f%% %11.1f%% %12d %10.0f %10.0f %8.1f%%",
					armName, rate, float64(offeredN)/elapsed,
					pct(kernelDropN, offeredN), pct(perConnDrops, offeredN), eventChanLen,
					float64(consumed)/elapsed, float64(pairsOk)/elapsed, cov)
				t.Logf("summary[%s@%s]: totalReq=%s duration=%.1fs req/s=%s conns=%d avgReq/conn=%s",
					armName, rsComma(int64(rate)), rsComma(pairsSent), elapsed,
					rsComma(int64(float64(pairsSent)/elapsed)), rsConns,
					rsComma(int64(float64(pairsSent)/float64(rsConns))))

				// Persist the full pipeline metrics snapshot for this cell alongside its profiles.
				if b, err := json.MarshalIndent(snapshot(), "", "  "); err != nil {
					t.Errorf("marshal metrics snapshot: %v", err)
				} else if err := os.WriteFile(profDir+"/metrics.json", b, 0o644); err != nil {
					t.Errorf("write metrics.json: %v", err)
				}

				time.Sleep(3200 * time.Millisecond) // let workers exit (inactivity=1s) before next cell
			}
		}
	}
}
