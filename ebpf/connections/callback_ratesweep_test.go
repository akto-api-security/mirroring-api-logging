package connections

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof" // side-effect: registers /debug/pprof/* on http.DefaultServeMux
	"os"
	"os/exec"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/structs"
	kafka "github.com/akto-api-security/mirroring-api-logging/trafficUtil/kafkaUtil"
	metaUtils "github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

// Rate-sweep capacity harness for the ebpf-core capture pipeline.
//
// A producer paced to a fixed records/sec plays the kernel: it builds the same
// records module.bpf.c emits (64-byte header + payload chunk ≤ 30 KB), picks the
// ring by the same connection hash (conn_shard), and keeps the same per-connection
// counters and lost-byte accounting. One consumer goroutine per ring plays
// bpfwrapper.ShardReader: it hands each record to the REAL Shard.HandleRecord and
// sweeps on idle, so framing, pairing and (with -parse=on) the real produce path
// all run unmodified.
//
//	producer (rate R) ── ring k = conn_shard(conn) ──► consumer k ──► Shard k
//	   ring full → record dropped, bytes counted as lost          │
//	   and stamped on the next record (as the kernel does)         ▼
//	                                              framing → pairing → emitHTTP1
//	                                              parse-off: verify pair only
//	                                              parse-on:  verify + produceHTTP1
//	                                                 (fast parser + JSON encode,
//	                                                  Kafka write when -kafka=true)
//
// Every request carries a unique X-Request-Id that its response echoes, so every
// emitted pair is checked: pairs_mismatched must stay 0 at every rate, including
// rates where the rings overflow.
//
// Drop points:
//
//	kernelDrops  — ring full (bytes in flight would exceed the ring's size)
//	perConnDrops — always 0: there are no per-connection channels in this design
//	               (kept as a column so reports line up with older sweeps)
//
// Run (flags go AFTER -args):
//
//	cd ebpf
//	AKTO_MEM_THRESH_RESTART=12000 AKTO_SYS_MEM_HARD_LIMIT=14000 \
//	  go test -run TestRateSweep -v -count=1 -timeout 400s ./connections/ \
//	  -args -testname=myrun -rps=300K -parse=on -gomaxprocs=4
//
// Omit -rps for the full 50K..500K sweep. Profiles and metrics.json land in
// connections/pprof/<testname>/<arm>[/json]/<rate>/ (see skills/rate-sweep-baseline).
// The test only runs when selected with -run …RateSweep…; it is skipped by plain
// `go test ./...` and by -short.
var (
	rsParseFlag = flag.String("parse", "both", "rate-sweep arm(s): on | off | both")
	rsGmpFlag   = flag.Int("gomaxprocs", 4, "GOMAXPROCS for the rate sweep")
	rsTestName  = flag.String("testname", "ratesweep", "output subdir under pprof/ for this run's profiles")
	rsRps       = flag.String("rps", "", "single offered rate in records/sec, e.g. 100K|200K|300K|500K (empty => default sweep)")
	rsWindowFlg = flag.Duration("window", 5*time.Second, "sustained-load duration per cell, e.g. 30s")
	rsEncoder   = flag.String("encoder", "json", "fast-path wire encoder: json (the only encoder in ebpf-core; flatbuffers is skipped)")
	rsSize      = flag.String("size", "4kb", "request and response size, e.g. 1kb|4kb|64kb|1mb")
	rsConnsFlg  = flag.Int("conns", 300, "keep-alive connections the load is spread over")
	rsRingMB    = flag.Int("ringmb", 1024, "total ring buffer size in MB, split over 8 rings (TRAFFIC_RINGBUF_DATA_MB)")
	rsKafka     = flag.Bool("kafka", false, "enable REAL Kafka producing via kafka.InitKafka() (default off: the produce path runs up to the write, which is a no-op). "+
		"Requires AKTO_KAFKA_BROKER_URL/_MAL and a reachable broker.")
	rsResetTopic  = flag.Bool("resettopic", true, "with -kafka=true: delete+recreate the target topic before InitKafka. No-op without -kafka=true.")
	rsThreat      = flag.Bool("threat", false, "enable the threat protobuf Produce path (utils.ThreatEnabled). Without -kafka=true the protobuf is built but not written.")
	rsKafkaDocker = flag.String("kafkadocker", "kafka-internal", "docker container name to run kafka-topics in, for -resettopic")
	rsPprofPort   = flag.Int("pprofport", 6061, "port for the live net/http/pprof server (6060 is main.go's; keep them distinct)")
)

// rsKafkaTopic / rsThreatTopic mirror the literals in kafkaUtil/kafka.go.
const (
	rsKafkaTopic  = "akto.api.logs"
	rsThreatTopic = "akto.api.logs2"
)

// Kernel constants mirrored from module.bpf.c.
const (
	rsMaxMsgChunk = 30720 // MAX_MSG_SIZE
	rsChunkLimit  = 4     // CHUNK_SIZE_LIMIT: chunks per syscall; the rest is counted as lost
	rsRings       = 8     // socket_data_events_0 … _7
	rsServerPort  = 8888  // not an ignored port
	rsIDWidth     = 16    // hex digits of X-Request-Id
)

// rsResetKafkaTopic deletes and recreates topic via `docker exec kafka-topics`.
func rsResetKafkaTopic(t *testing.T, container, topic string) {
	del := exec.Command("docker", "exec", container, "kafka-topics",
		"--bootstrap-server", "localhost:9092", "--delete", "--topic", topic)
	if out, err := del.CombinedOutput(); err != nil {
		t.Logf("resettopic: delete %q (ok if the topic doesn't exist yet): %v: %s", topic, err, out)
	}
	time.Sleep(2 * time.Second)
	create := exec.Command("docker", "exec", container, "kafka-topics",
		"--bootstrap-server", "localhost:9092", "--create", "--topic", topic,
		"--partitions", "1", "--replication-factor", "1")
	if out, err := create.CombinedOutput(); err != nil {
		t.Fatalf("resettopic: create %q: %v: %s", topic, err, out)
	}
	t.Logf("resettopic: %q deleted+recreated via %s", topic, container)
}

var rsPprofOnce sync.Once

// rsStartPprofServer starts the net/http/pprof server once. It is the single
// driver of CPU profiling for this test (see rsCaptureCPU): Go allows one active
// CPU profile per process, so a per-cell capture and an external pyroscope
// scrape go through the same endpoint.
func rsStartPprofServer(t *testing.T, port int) {
	rsPprofOnce.Do(func() {
		go func() {
			addr := fmt.Sprintf("localhost:%d", port)
			t.Logf("pprof HTTP server on %s", addr)
			if err := http.ListenAndServe(addr, nil); err != nil {
				t.Logf("pprof HTTP server exited: %v", err)
			}
		}()
	})
}

// rsCaptureCPU fetches a CPU profile of `seconds` through the pprof server.
func rsCaptureCPU(port, seconds int, path string) <-chan error {
	done := make(chan error, 1)
	go func() {
		resp, err := http.Get(fmt.Sprintf("http://localhost:%d/debug/pprof/profile?seconds=%d", port, seconds))
		if err != nil {
			done <- fmt.Errorf("fetch cpu profile: %w", err)
			return
		}
		defer resp.Body.Close()
		f, err := os.Create(path)
		if err != nil {
			done <- fmt.Errorf("create %s: %w", path, err)
			return
		}
		defer f.Close()
		_, err = io.Copy(f, resp.Body)
		done <- err
	}()
	return done
}

// rsWriteProfile dumps a named runtime profile. "heap" forces a GC first (end
// state only); "heap-noforce" doesn't (safe under load); anything else is a
// pprof.Lookup name (goroutine, allocs, mutex, block, …).
func rsWriteProfile(name, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	switch name {
	case "heap":
		runtime.GC()
		return pprof.WriteHeapProfile(f)
	case "heap-noforce":
		return pprof.WriteHeapProfile(f)
	}
	p := pprof.Lookup(name)
	if p == nil {
		return fmt.Errorf("no profile %q", name)
	}
	return p.WriteTo(f, 0)
}

// rsParseRate turns "300K"/"2M"/"50000" into an int.
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
		t.Fatalf("invalid rate %q: %v", s, err)
	}
	return n * mult
}

// rsParseSize turns "4kb"/"64KB"/"1mb"/"500" into bytes.
func rsParseSize(t *testing.T, s string) int {
	u := strings.ToUpper(strings.TrimSpace(s))
	u = strings.TrimSuffix(u, "B")
	return rsParseRate(t, u)
}

// rsComma formats n with thousands separators.
func rsComma(n int64) string {
	s := strconv.FormatInt(n, 10)
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

// rsRateLabel formats a rate as a directory name: 50000 -> "50k", 1000000 -> "1m".
func rsRateLabel(rate int) string {
	switch {
	case rate != 0 && rate%1_000_000 == 0:
		return fmt.Sprintf("%dm", rate/1_000_000)
	case rate != 0 && rate%1_000 == 0:
		return fmt.Sprintf("%dk", rate/1_000)
	default:
		return strconv.Itoa(rate)
	}
}

// rsConnShard is module.bpf.c's conn_shard(tgid_fd).
func rsConnShard(tgidFd uint64) int {
	return int((tgidFd*0x9E3779B97F4A7C15)>>61) & (rsRings - 1)
}

// rsMessage builds an HTTP/1.1 message of about `size` bytes whose X-Request-Id
// sits at a fixed offset (returned) so it can be rewritten per exchange.
func rsMessage(isReq bool, size int) (msg []byte, idOff int) {
	var head string
	if isReq {
		head = "POST /api/items HTTP/1.1\r\nHost: ratesweep.test\r\nContent-Type: application/json\r\nX-Request-Id: "
	} else {
		head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Request-Id: "
	}
	idOff = len(head)
	head += strings.Repeat("0", rsIDWidth) + "\r\nContent-Length: "
	bodyLen := size - len(head) - len("\r\n\r\n") - 8
	if bodyLen < 2 {
		bodyLen = 2
	}
	head += strconv.Itoa(bodyLen) + "\r\n\r\n"
	body := bytes.Repeat([]byte("x"), bodyLen)
	body[0], body[bodyLen-1] = '"', '"'
	return append([]byte(head), body...), idOff
}

// rsIDOf returns the X-Request-Id value of a captured message, or nil.
func rsIDOf(msg []byte) []byte {
	i := bytes.Index(msg, []byte("X-Request-Id: "))
	if i < 0 || i+14+rsIDWidth > len(msg) {
		return nil
	}
	return msg[i+14 : i+14+rsIDWidth]
}

// rsConn is the kernel's per-connection state (conn_info_t) plus the
// producer's own position in the keep-alive exchange.
type rsConn struct {
	id, tgidFd uint64
	startNs    uint64 // conn_start_ns: part of the connection key, same on every record
	fd         uint32
	ring       int
	rc, wc     uint32
	lost       [2]uint32 // [read, write] bytes not delivered since the last delivered chunk
	lostRun    uint32
	runDir     int // 0 none, 1 read, 2 write
	isReq      bool
	req, resp  []byte // per-connection templates; the id is rewritten per exchange
}

// rsRing is one ring buffer: records queued for its consumer, bounded by bytes.
type rsRing struct {
	ch       chan []byte
	inflight atomic.Int64
	capBytes int64
}

// TestRateSweep finds the offered rate at which the capture pipeline stops
// keeping up, and checks that no pair is ever crossed on the way.
func TestRateSweep(t *testing.T) {
	if testing.Short() || !strings.Contains(flag.Lookup("test.run").Value.String(), "RateSweep") {
		t.Skip("long-running perf harness; run explicitly with -run TestRateSweep")
	}

	prev := runtime.GOMAXPROCS(*rsGmpFlag)
	defer runtime.GOMAXPROCS(prev)
	runtime.SetMutexProfileFraction(1) // cumulative per process: with -parse=both the 2nd arm includes the 1st
	defer runtime.SetMutexProfileFraction(0)
	runtime.SetBlockProfileRate(1)
	defer runtime.SetBlockProfileRate(0)
	rsStartPprofServer(t, *rsPprofPort)

	// -parse picks the arm(s). parse-off: framing + pairing only (the emitted pair
	// is verified and discarded). parse-on: also the real produce path.
	var arms []bool // skipProduce
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
	switch strings.ToLower(*rsEncoder) {
	case "json", "both":
	case "flatbuffers":
		t.Skip("ebpf-core has only the JSON encoder; -encoder=flatbuffers has nothing to measure")
	default:
		t.Fatalf("invalid -encoder=%q (want json)", *rsEncoder)
	}

	// Produce path: the zero-copy fast parser + JSON encoder, as shipped. Without
	// -kafka the write itself is a no-op (no writer), everything before it runs.
	metaUtils.FastParser = true
	metaUtils.FastParserGunzip = false
	metaUtils.ThreatEnabled = *rsThreat
	if *rsKafka {
		if *rsResetTopic {
			rsResetKafkaTopic(t, *rsKafkaDocker, rsKafkaTopic)
			if *rsThreat {
				rsResetKafkaTopic(t, *rsKafkaDocker, rsThreatTopic)
			}
		}
		t.Log("kafka=true: calling InitKafka() — blocks until a broker is reachable")
		kafka.InitKafka()
	}

	conns := *rsConnsFlg
	size := rsParseSize(t, *rsSize)
	inactivityThreshold = 1 * time.Second
	maxActiveConnections = conns + 10
	ringCap := int64(*rsRingMB) << 20 / rsRings
	// NOTE: the memory watchdog (utils.LogMemoryStats) reads its limits from env at
	// init; raise them at launch: AKTO_MEM_THRESH_RESTART / AKTO_SYS_MEM_HARD_LIMIT.

	reqT, reqIDOff := rsMessage(true, size)
	respT, respIDOff := rsMessage(false, size)
	chunks := func(n int) int { return min((n+rsMaxMsgChunk-1)/rsMaxMsgChunk, rsChunkLimit) }
	evPerPair := chunks(len(reqT)) + chunks(len(respT))

	rates := []int{50_000, 100_000, 200_000, 300_000, 500_000}
	if *rsRps != "" {
		rates = []int{rsParseRate(t, *rsRps)}
	}

	t.Logf("size=%s reqBytes=%d respBytes=%d records/pair=%d GOMAXPROCS=%d rings=%d×%dMB conns=%d",
		*rsSize, len(reqT), len(respT), evPerPair, runtime.GOMAXPROCS(0), rsRings, ringCap>>20, conns)
	t.Logf("%-16s %8s %10s %11s %12s %10s %10s %10s %9s",
		"arm", "rate/s", "offered/s", "kernelDrop%", "perConnDrop%", "evChanLen", "consumed/s", "pairs_ok/s", "cov%")

	// Every emitted pair is checked by request id; parse-on then produces it.
	var pairsOK, pairsMismatched atomic.Int64
	var skipProduce atomic.Bool
	oldEmit := emitHTTP1
	defer func() { emitHTTP1 = oldEmit }()
	emitHTTP1 = func(c *conn, req, resp []byte) {
		a, b := rsIDOf(req), rsIDOf(resp)
		if a != nil && bytes.Equal(a, b) {
			pairsOK.Add(1)
		} else {
			pairsMismatched.Add(1)
		}
		if !skipProduce.Load() {
			produceHTTP1(c, req, resp)
		}
	}

	var idSeq uint64 // exchange counter → X-Request-Id, unique across the run
	cellBase := uint64(0)

	for _, skip := range arms {
		skipProduce.Store(skip)
		arm, armName := "parse-on", "parse-on/json"
		if skip {
			arm, armName = "parse-off", "parse-off"
		}

		for _, rate := range rates {
			StatsArgs() // reset the capture counters for this cell
			pairsOK.Store(0)
			pairsMismatched.Store(0)
			factory := NewFactory(rsRings)

			// One ring + one consumer per shard, as bpfwrapper.ShardReader does:
			// records in order, Sweep when idle for a sweep interval.
			rings := make([]*rsRing, rsRings)
			var consumed atomic.Int64
			var wg sync.WaitGroup
			for k := range rings {
				r := &rsRing{ch: make(chan []byte, 1<<16), capBytes: ringCap}
				rings[k] = r
				sh := factory.Shard(k)
				wg.Add(1)
				go func() {
					defer wg.Done()
					sweep := time.NewTimer(SweepInterval())
					defer sweep.Stop()
					for {
						select {
						case rec, ok := <-r.ch:
							if !ok {
								sh.Sweep(time.Now().Add(time.Hour)) // finish and remove every conn of this cell
								return
							}
							sh.HandleRecord(rec, time.Now())
							r.inflight.Add(-int64(len(rec)))
							consumed.Add(1)
						case now := <-sweep.C:
							sh.Sweep(now)
							sweep.Reset(SweepInterval())
						}
					}
				}()
			}

			// Kernel side: connections, records, ring choice, lost-byte accounting.
			cs := make([]*rsConn, conns)
			var offered, kernelDrops int64
			for i := range cs {
				c := &rsConn{id: (cellBase+uint64(i)+1)<<32 | 4242, startNs: cellBase + uint64(i) + 1, fd: uint32(i + 10), isReq: true,
					req: append([]byte(nil), reqT...), resp: append([]byte(nil), respT...)}
				c.tgidFd = (c.id>>32)<<32 | uint64(c.fd)
				c.ring = rsConnShard(c.tgidFd)
				cs[i] = c
				// open record (accept): local address and server port
				rec := make([]byte, int(unsafe.Sizeof(structs.SocketOpenEvent{})))
				ev := (*structs.SocketOpenEvent)(unsafe.Pointer(&rec[0]))
				ev.ConnId = structs.ConnID{Id: c.id, Fd: c.fd, Kind: structs.EventOpen, Conn_start_ns: c.startNs, Port: 0x3930, Ip: 0x0b00800a}
				ev.SrcIp, ev.SrcPort = 0x0e00800a, rsServerPort
				rings[c.ring].ch <- rec
				rings[c.ring].inflight.Add(int64(len(rec)))
			}
			cellBase += uint64(conns)

			// syscall emits one read (request) or write (response) the way
			// process_syscall_data does: chunk, count each chunk, drop on a full ring
			// and carry the dropped bytes on the next delivered chunk.
			syscall := func(c *rsConn, isSend bool, data []byte) {
				dir := 1
				if isSend {
					dir = 2
				}
				if c.runDir != dir {
					c.runDir, c.lostRun = dir, 0
				}
				li := dir - 1
				r := rings[c.ring]
				for i, off := 0, 0; i < rsChunkLimit && off < len(data); i++ {
					n := len(data) - off
					if n > rsMaxMsgChunk {
						n = rsMaxMsgChunk
					}
					if isSend {
						c.wc++
					} else {
						c.rc++
					}
					offered++
					recLen := structs.MsgPayloadOffset + n
					if r.inflight.Load()+int64(recLen) > r.capBytes {
						kernelDrops++
						c.lost[li] += uint32(n)
						c.lostRun += uint32(n)
					} else {
						rec := make([]byte, recLen)
						a := (*structs.SocketDataEventAttr)(unsafe.Pointer(&rec[0]))
						a.ConnId = structs.ConnID{Id: c.id, Fd: c.fd, Kind: structs.EventData, Conn_start_ns: c.startNs, Port: 0x3930, Ip: 0x0b00800a}
						a.Bytes_sent = int32(n)
						if !isSend {
							a.Bytes_sent = -int32(n)
						}
						a.ReadEventsCount, a.WriteEventsCount = c.rc, c.wc
						a.Lost, a.LostRun = c.lost[li], c.lostRun
						a.Laddr, a.Lport = 0x0e00800a, rsServerPort
						copy(rec[structs.MsgPayloadOffset:], data[off:off+n])
						select {
						case r.ch <- rec:
							r.inflight.Add(int64(recLen))
							c.lost[li], c.lostRun = 0, 0
						default: // queue slots exhausted: same as a full ring
							kernelDrops++
							c.lost[li] += uint32(n)
							c.lostRun += uint32(n)
						}
					}
					off += n
				}
				if rest := len(data) - rsChunkLimit*rsMaxMsgChunk; rest > 0 {
					c.lost[li] += uint32(rest) // beyond the chunk limit: counted, never sent
					c.lostRun += uint32(rest)
				}
			}

			// ---- pprof capture for this cell: pprof/<testname>/<arm>[/json]/<rate>/ ----
			profDir := fmt.Sprintf("pprof/%s/%s", *rsTestName, arm)
			if !skip {
				profDir += "/json"
			}
			profDir += "/" + rsRateLabel(rate)
			if err := os.MkdirAll(profDir, 0o755); err != nil {
				t.Fatalf("mkdir %s: %v", profDir, err)
			}
			cpuDone := rsCaptureCPU(*rsPprofPort, int(rsWindowFlg.Seconds()), profDir+"/cpu.prof")
			heapDone := make(chan struct{})
			go func() {
				// Periodic heap without a forced GC (a forced STW GC under load is
				// itself load); goroutine-count.tsv records the trajectory.
				tick := time.NewTicker(10 * time.Second)
				defer tick.Stop()
				gf, gfErr := os.Create(profDir + "/goroutine-count.tsv")
				if gfErr == nil {
					defer gf.Close()
					fmt.Fprintf(gf, "elapsed_sec\tnum_goroutine\n")
				}
				for n := 0; ; {
					select {
					case <-heapDone:
						return
					case <-tick.C:
						_ = rsWriteProfile("heap-noforce", fmt.Sprintf("%s/heap-%d.prof", profDir, n))
						if gf != nil {
							fmt.Fprintf(gf, "%d\t%d\n", (n+1)*10, runtime.NumGoroutine())
						}
						n++
					}
				}
			}()

			// ---- sustained load ----
			start := time.Now()
			ci := 0
			var pairsSent int64
			for time.Since(start) < *rsWindowFlg {
				should := int64(float64(rate) * time.Since(start).Seconds())
				for offered < should {
					c := cs[ci%conns]
					ci++
					if c.isReq {
						idSeq++
						id := fmt.Sprintf("%0*x", rsIDWidth, idSeq)
						copy(c.req[reqIDOff:], id)
						copy(c.resp[respIDOff:], id)
						syscall(c, false, c.req)
					} else {
						syscall(c, true, c.resp)
						pairsSent++
					}
					c.isReq = !c.isReq
				}
				time.Sleep(50 * time.Microsecond)
			}
			elapsed := time.Since(start).Seconds()

			// Window-end: sustained consume rate and how much was still queued.
			consumedAtEnd := consumed.Load()
			var queued int64
			for _, r := range rings {
				queued += int64(len(r.ch))
			}

			// Drain: wait for the rings to empty and the pair count to settle.
			lastPairs, stable := int64(-1), 0
			for i := 0; i < 150; i++ {
				time.Sleep(100 * time.Millisecond)
				empty := true
				for _, r := range rings {
					if len(r.ch) > 0 {
						empty = false
					}
				}
				p := pairsOK.Load() + pairsMismatched.Load()
				if empty && p == lastPairs {
					if stable++; stable >= 5 {
						break
					}
				} else {
					stable, lastPairs = 0, p
				}
			}

			close(heapDone)
			if err := <-cpuDone; err != nil {
				t.Errorf("cpu profile capture: %v", err)
			}
			for _, p := range []string{"goroutine", "allocs", "block", "mutex"} {
				if err := rsWriteProfile(p, profDir+"/"+p+".prof"); err != nil {
					t.Fatalf("write %s profile: %v", p, err)
				}
			}
			_ = rsWriteProfile("heap", profDir+"/heap-final.prof")

			// Stop the consumers; each finishes and removes its connections.
			for _, r := range rings {
				close(r.ch)
			}
			wg.Wait()
			stats := StatsArgs()

			ok, bad := pairsOK.Load(), pairsMismatched.Load()
			pct := func(n, d int64) float64 {
				if d == 0 {
					return 0
				}
				return 100 * float64(n) / float64(d)
			}
			cov := pct(ok, pairsSent)

			t.Logf("%-16s %8d %10.0f %10.1f%% %11.1f%% %12d %10.0f %10.0f %8.1f%%",
				armName, rate, float64(offered)/elapsed, pct(kernelDrops, offered), 0.0, queued,
				float64(consumedAtEnd)/elapsed, float64(ok)/elapsed, cov)
			t.Logf("summary[%s@%s]: totalReq=%s duration=%.1fs req/s=%s conns=%d avgReq/conn=%s",
				armName, rsComma(int64(rate)), rsComma(pairsSent), elapsed,
				rsComma(int64(float64(pairsSent)/elapsed)), conns, rsComma(pairsSent/int64(conns)))
			t.Logf("pairs[%s@%s]: sent=%s ok=%s mismatched=%s  capture: %v",
				armName, rsComma(int64(rate)), rsComma(pairsSent), rsComma(ok), rsComma(bad), stats)
			if bad > 0 {
				t.Errorf("%s@%d: %d crossed pairs (a request emitted with another exchange's response)", armName, rate, bad)
			}

			// metrics.json: the field names skills/rate-sweep-baseline reads, plus the
			// capture counters from connections.StatsArgs.
			m := map[string]any{
				"arm":                            armName,
				"rate":                           rate,
				"duration_sec":                   elapsed,
				"events_offered":                 offered,
				"events_received":                consumed.Load(),
				"events_dropped_kernel_ring_buf": kernelDrops,
				"events_dropped_channel_full":    0,
				"input_chan_len":                 queued,
				"ring_bytes_cap":                 ringCap * rsRings,
				"pairs_attempted":                pairsSent,
				"pairs_parse_success":            ok,
				"pairs_mismatched":               bad,
				"coverage_pct":                   cov,
			}
			for i := 0; i+1 < len(stats); i += 2 {
				if k, ok := stats[i].(string); ok {
					m[k] = stats[i+1]
				}
			}
			if b, err := json.MarshalIndent(m, "", "  "); err != nil {
				t.Errorf("marshal metrics: %v", err)
			} else if err := os.WriteFile(profDir+"/metrics.json", b, 0o644); err != nil {
				t.Errorf("write metrics.json: %v", err)
			}
		}
	}
}
