# Message Chunking Pipeline: Kernel to Kafka

## Overview

eBPF captures TCP read/write syscalls from traced processes, chunks the data into perf events,
delivers them to Go userspace, groups them into HTTP request-response pairs, parses them,
and produces to Kafka.

## Pipeline Stages

```
Kernel (BPF)                    Go Userspace
────────────                    ────────────
read()/write() syscall
  │
  ▼
process_syscall_data()
  │ splits data into chunks (max 30KB each)
  │ each chunk gets: rc/wc counter, msg_seq, direction, role
  │ msg_seq increments on direction change (read→write or write→read)
  │
  ▼
perf_event_output()  ──────────►  Three separate ProbeChannels, each with:
                                    - its own BPF perf map (BPF_PERF_OUTPUT)
                                    - its own per-CPU perf event mmap buffers
                                      (8192 pages ~32MB per CPU, via perf_event_open)
                                    - its own Go eventChannel (chan []byte)
                                    - its own single callback goroutine
                                  
                                  socket_open_events  ──► SocketOpenEventCallback
                                  socket_data_events  ──► SocketDataEventCallback
                                  socket_close_events ──► SocketCloseEventCallback

                                  Each per-CPU perf event buffer is drained by gobpf
                                  reader goroutines into that channel. If a buffer fills
                                  before being drained → events dropped → lostEventsChannel
                                  fires → EventsDroppedKernelPerfBuf++
                                  │
                                  ▼
                          ┌─ SocketDataEventCallback (SINGLE goroutine) ──────────────────┐
                          │                                                                 │
                          │  1. CanBeFilled() — drop silently if maxActiveConnections      │
                          │     exceeded. (BufferCheck()/UpdateBufferSize() bandwidth-cap  │
                          │     helpers exist in bandwidthSampler.go but are currently      │
                          │     unwired — reserved for future re-use, not called here.)     │
                          │  2. unsafe.Pointer cast kernelBytes[0] → *SocketDataEventAttr   │
                          │     (attr is a VIEW, no copy; no binary.Read/reflection)        │
                          │  3. Filter: skip ports (kafka/zookeeper/mongo/redis)            │
                          │  4. CreateIfNotExists(connId)                                  │
                          │     └─ if new: Tracker + per-conn channel (buffer=10)          │
                          │        + start Worker goroutine                                │
                          │        + start Flush goroutine (if FastIngestion)              │
                          │  5. Pipeline.EventsReceived.Add(1)                             │
                          │  6. SendDataEvent(connId, &kernelBytes) — non-blocking send,    │
                          │     passes the raw []byte pointer through zero-copy            │
                          │     if channel full: DROP → EventsDroppedChannelFull++         │
                          └───────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
                          per-connection channel (chan interface{}, buffer=AKTO_PER_CONN_CH_BUFFER_SIZE=10)
                                  │
                                  ▼
                          ┌─ Worker Goroutine (one per connection) ───────────────────────┐
                          │                                                                │
                          │  select:                                                       │
                          │    case event := <-ch:                                         │
                          │      *[]byte (data event) → tracker.AddDataEvent(kernelBytesPtr)│
                          │        └─ acquires tracker.mutex (Lock)                        │
                          │        └─ group.fragments = append(group.fragments,            │
                          │             fragment{seq: chunkKey, data: payload})            │
                          │             (payload is a zero-copy view; append stores by ref) │
                          │        └─ updates highestMsgSeq if higher                     │
                          │           (set AFTER msgGroups insert, in same lock hold —    │
                          │            guarantees msgGroups[seq] exists when highestMsgSeq│
                          │            reflects it)                                        │
                          │        └─ LateArrivals++ or OutOfOrderArrivals++ if applicable│
                          │        └─ releases tracker.mutex                               │
                          │        └─ resets inactivityTimer only on new MsgSeq value     │
                          │      SocketOpenEvent  → tracker.AddOpenEvent(*e)              │
                          │      SocketCloseEvent → tracker.AddCloseEvent(*e)             │
                          │                         schedules 100ms delayed close          │
                          │                                                                │
                          │    case <-delayedDeleteChan (100ms after SocketClose):        │
                          │      close(done) → signals flush goroutine for final flush     │
                          │      factory.DeleteWorker(connID)                              │
                          │      return                                                    │
                          │                                                                │
                          │    case <-inactivityTimer (TRAFFIC_INACTIVITY_THRESHOLD=7s):  │
                          │      close(done) → signals flush goroutine for final flush     │
                          │      factory.DeleteWorker(connID)                              │
                          │      return                                                    │
                          └────────────────────────────────────────────────────────────────┘
                                  │
                          (worker closes done channel → signals flush goroutine)
                                  │
                                  ▼
                          ┌─ Flush Goroutine (one per connection, started only if FastIngestion) ────────────┐
                          │                                                                                   │
                          │  ticker (every MSG_SEQ_FLUSH_TICK_INTERVAL=500ms):                               │
                          │    tracker.GetFlushablePairs()                                                   │
                          │      └─ acquires tracker.mutex                                                   │
                          │      └─ skips if len(msgGroups) < 3                                             │
                          │      └─ drainPairs(lowestPendingSeq, sealed: seq+2 <= highestMsgSeq)            │
                          │           walk msgGroups from lowestPendingSeq:                                  │
                          │             if g1(seq) + g2(seq+1) both present → pair, delete both             │
                          │             if either missing → gap-skip:                                        │
                          │               advance seq, orphan any present half (GroupsOrphaned++)            │
                          │               GapSkipsFired++, GapSkipSeqsLost += skipped count                 │
                          │           stop when seq+2 > highestMsgSeq                                       │
                          │           (seq+2 not yet confirmed arrived — avoids premature orphaning          │
                          │            of the last pair before its trigger event lands)                      │
                          │      └─ advances lowestPendingSeq                                               │
                          │      └─ releases tracker.mutex                                                   │
                          │    for each flushed pair:                                                        │
                          │      fragmentsToBytes(pair.ReqGroup.fragments) → reqBlob                        │
                          │        slices.SortFunc by seq (zero-alloc), append into pre-sized combined []byte│
                          │        stops early on seq gap → ChunkAssemblyGaps++                              │
                          │      fragmentsToBytes(pair.RespGroup.fragments) → respBlob                       │
                          │      ProcessSinglePair → tryReadFromBD → ParseAndProduce                        │
                          │        → http.ReadRequest / http.ReadResponse                                    │
                          │        → json.Marshal → Kafka produce                                            │
                          │                                                                                   │
                          │  case <-done:                                                                    │
                          │    tracker.FlushRemainingPairs()                                                 │
                          │      └─ drainPairs(lowestPendingSeq, sealed: seq <= highestMsgSeq)              │
                          │           (relaxed seal — no N+2 trigger needed, connection is ending)           │
                          │      └─ after drain: iterate remaining msgGroups entries                         │
                          │           these are stranded late arrivals (below lowestPendingSeq)              │
                          │           GroupsStranded++ for each, then delete                                 │
                          │    process remaining pairs (same copy chain)                                     │
                          │    return                                                                         │
                          └─────────────────────────────────────────────────────────────────────────────────┘
```

## How a 4KB HTTP Request Flows Through (keep-alive connection)

```
Kernel: echo-server calls read(fd=8, buf, 4096)
  → BPF intercepts, direction=kIngress
  → prev direction was kEgress (last response) → direction changed → msg_seq becomes 3
  → perf_event_output: rc=1, wc=N_prev, msg_seq=3, bytes=4096

Kernel: echo-server calls write(fd=8, response, 4096)
  → direction=kEgress, changed from kIngress → msg_seq becomes 4
  → perf_event_output: rc=M, wc=1, msg_seq=4, bytes=4096

Go: SocketDataEventCallback
  → unsafe.Pointer cast kernelBytes[0] → attr (view, no copy)
  → SendDataEvent(connId, &kernelBytes) → per-conn channel (zero-copy)

Go: Worker goroutine
  → AddDataEvent: append fragment{seq, data} into msgGroups[3].fragments, msgGroups[4].fragments
    (data is a view into kernelBytes — still zero-copy at this point)
  → highestMsgSeq = 4

Go: next request arrives → msg_seq=5 event
  → highestMsgSeq = 5

Go: flush ticker (500ms)
  → GetFlushablePairs: seq=3, seq+2=5 <= highestMsgSeq=5 ✓
  → g1=msgGroups[3], g2=msgGroups[4] both present → pair
  → delete msgGroups[3], msgGroups[4], lowestPendingSeq=5
  → fragmentsToBytes(g1.fragments) → reqBlob
  → fragmentsToBytes(g2.fragments) → respBlob
  → ParseAndProduce → json.Marshal → Kafka
```

## Goroutines per Connection

```
Connection fd=8:
  1. Worker goroutine  — reads ch, calls AddDataEvent (fast: mutex + map append)
  2. Flush goroutine   — ticker 500ms, GetFlushablePairs + HTTP parse + Kafka (slow)

Shared state: tracker.msgGroups (protected by tracker.mutex)
  - Worker writes:  AddDataEvent acquires Lock → append fragment → Unlock
  - Flush reads:    GetFlushablePairs acquires Lock → walk/delete → Unlock
  - Contention:     flush holds lock for full map walk; worker blocks during that window
                    if blocked long enough → per-conn channel fills (buffer=10) → DROP
```

## Key Data Structures

```
Tracker.msgGroups: map[uint32]*msgSeqGroup
  │
  ├─ msgSeq=3 → msgSeqGroup{direction=kIngress, fragments: []fragment}
  │                                                        ├─ {seq:1, data: []byte} (view, no copy)
  │                                                        └─ {seq:2, data: []byte} (if multi-chunk)
  ├─ msgSeq=4 → msgSeqGroup{direction=kEgress, fragments: []fragment}
  │                                                       └─ {seq:1, data: []byte}
  └─ msgSeq=5 → msgSeqGroup{...}  ← existence of this triggers flush of (3,4)

fragments holds chunks in ARRIVAL order, not seq order (per-CPU perf buffers can
deliver out of order) — fragmentsToBytes sorts by seq at flush time. A plain
growable slice instead of map[int][]byte: seq keys are unique and monotonic per
group, so no map/hash/bucket machinery is needed.

Tracker state:
  lowestPendingSeq  — drainPairs walks from here; advances past flushed/skipped seqs
  highestMsgSeq     — highest msg_seq seen; set AFTER msgGroups insert in same lock hold,
                      so seq+2 <= highestMsgSeq guarantees msgGroups[seq+2] already exists
  seenMsgSeqs       — utils.SeqRingBitset (fixed-size ring bitset, ~8KB, no growth).
                      Marks each msg_seq the first time its group is created, so
                      GroupsCreated counts each unique msg_seq exactly once even if
                      the group is later deleted (paired/orphaned/stranded) and
                      re-created by a late-arriving chunk under the same msg_seq.
```

## Drop Points

```
1. Kernel perf event buffer overflow
   → Cause: per-CPU perf event mmap buffer fills before gobpf goroutine drains it
   → Metric: events_dropped_kernel_ring_buf
   → Logged: "⚠️ Lost N events on channel socket_data_events"
   → Cascade: missing events → sequence gaps → gap-skips → late arrivals

2. Per-connection channel overflow (buffer=10)
   → Cause: Worker blocked on tracker.mutex while Flush goroutine holds it
   → Metric: events_dropped_channel_full
   → Logged: "Dropping event Channel full"
   → Effect: dropped chunk corrupts the msg_seq group for that direction

3. Gap-skip
   → Cause: drop 1 or 2 left a hole; g1(seq) or g2(seq+1) missing in drainPairs
   → Metric: gap_skips_fired, gap_skip_seqs_lost
   → Logged: "msg_seq: gap-skip" (behind MSG_SEQ_LOGS flag)
   → Effect: events for skipped seqs arriving later become late arrivals

4. Late arrivals
   → Cause: gap-skip advanced lowestPendingSeq; delayed event arrives below it.
             Also caused by cross-CPU delivery skew: per-CPU gobpf goroutines race
             into eventChannel — msg_seq=N+1 may arrive in Go before msg_seq=N.
   → Metric: late_arrivals
   → Logged: "msg_seq: late arrival below lowestPendingSeq" (behind MSG_SEQ_LOGS flag)
   → Effect: group written into msgGroups below lowestPendingSeq; stranded at final flush

5. Stranded groups
   → Cause: late arrivals that landed below lowestPendingSeq; drainPairs never reaches them
   → Cleaned up explicitly in FlushRemainingPairs after drainPairs finishes
   → Metric: groups_stranded
   → Logged: "msg_seq: stranded group discarded at final flush" (behind MSG_SEQ_LOGS flag)

6. Orphaned groups
   → Cause: partner permanently missing (actual drop, not reordering)
   → Metric: groups_orphaned
   → Logged: "msg_seq: orphaned group (partner missing)" (behind MSG_SEQ_LOGS flag)

7. Chunk assembly gap
   → Cause: middle fragment (seq key) dropped; fragmentsToBytes stops early after sorting
   → Metric: chunk_assembly_gaps
   → Effect: truncated blob → parse failure downstream
```

Note: the old flat-buffer path (active when `AKTO_FAST_INGESTION=false`) has the same
gap-detection logic in `convertToSingleByteArr` (`connections/flushFlatBuffer.go`), operating
over `map[int][]byte]` instead of `[]fragment`. `fragmentsToBytes` (`flushPairedRequests.go`)
is the msg_seq path's equivalent, used above.

## Cross-CPU Ordering: Root Cause of Out-of-Order and Late Arrivals

BCC's `InitPerfMapWithPageCnt` calls `perf_event_open` per CPU and mmap's each CPU's perf
event buffer (8192 pages each). One gobpf goroutine drains each CPU's buffer into that
ProbeChannel's Go eventChannel.

When a process migrates CPUs between syscalls (or via IRQ affinity changes), events for the
same connection are submitted to different CPUs' buffers and drained by different goroutines:

```
CPU0 goroutine: drains msg_seq=4 (write events) → eventChannel
CPU1 goroutine: drains msg_seq=3 (read events)  → eventChannel (arrives later)

Result in Go: msg_seq=4 processed before msg_seq=3
  → msg_seq=3 arrival: out_of_order_arrivals++ (3 < highestMsgSeq=4, >= lowestPendingSeq)
  → drainPairs next tick: both present, no gap-skip, pair flushed → no data loss
```

**Key distinction:**
- `out_of_order_arrivals`: arrived late but within [lowestPendingSeq, highestMsgSeq] → **not data loss**
- `late_arrivals`: arrived after lowestPendingSeq already advanced past it → **data loss**

The boundary: whether a gap-skip fired before the delayed event arrived.
If delayed event arrives between two drainPairs ticks → out-of-order (safe).
If gap-skip fires first (500ms tick saw partner missing) → late arrival (lost).

## Known Problems

### 1. Premature gap-skip (open problem)
drainPairs fires gap-skip on a missing seq that is actually in-transit (cross-CPU skew, not a
real drop). The partner then arrives as a late arrival and is discarded. Metrics to calibrate
fix: `highestMsgSeq - msgSeq` at out-of-order arrival gives the seq-distance distribution.

Fix candidates: seq-distance threshold, miss-count (ticks of patience), map-size cap.

### 2. Mutex contention under high load
`GetFlushablePairs` holds `tracker.mutex` for the full msgGroups walk. Worker blocks on same
lock. Under high throughput, per-conn channel (buffer=10) fills → drops.

### 3. Chunk assembly truncation
`fragmentsToBytes` (msg_seq path) / `convertToSingleByteArr` (flat-buffer path) stop on first
seq/key gap. Dropped middle fragment → truncated blob → `pairs_parse_failure`.

### 4. Last-pair delay
Final request-response pair of a burst has no N+2 trigger. Waits for inactivity timer (7s)
before `FlushRemainingPairs` is called. Expected behavior, not a bug.

## File Map (ebpf/connections/)

| File | Owns |
|---|---|
| `eventCallbacks.go` | Ingress boundary: `SocketOpenEventCallback`, `SocketDataEventCallback`, `SocketCloseEventCallback` |
| `factory.go` | `Factory`, `NewFactory`, `StartWorker` (worker-loop goroutine), `DeleteWorker`, `SendEvent`/`SendDataEvent` |
| `tracker.go` | `Tracker`, `AddDataEvent`/`AddOpenEvent`/`AddCloseEvent`, sequencing algorithm (`drainPairs`, `GetFlushablePairs`, `FlushRemainingPairs`) |
| `flushPairedRequests.go` | msg_seq flush/dispatch layer: `fragment`/`msgSeqGroup`/`MsgSeqPair` types, `fragmentsToBytes`, `startFlushRoutine`, `flushAndProcessRemainingPairs`, `ProcessSinglePair` |
| `flushFlatBuffer.go` | Old flat-buffer flush path (active when `AKTO_FAST_INGESTION=false`): `convertToSingleByteArr`, `ProcessTrackerData` |
| `dispatchConfig.go` | Config shared by both flush paths: `httpBytes`, `sequenceCheckSkip`, `disableEgress`, `uniqueDaemonsetId` |
| `bandwidthSampler.go` | `BufferCheck`/`UpdateBufferSize` bandwidth-cap gate — currently unwired, reserved for future re-use |
| `metrics.go` | *(removed — moved to `trafficUtil/utils/metrics_server.go`; owns no `connections`-specific state)* |

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `AKTO_FAST_INGESTION` | false | Selects the whole msg_seq-based flow end to end (fragments + incremental pair flushing) instead of the old flat-buffer path; also gates the encoder path in `kafkaUtil/parser.go`. Replaces the old, now-removed `UseMsgSeqFlush`/`MSG_SEQ_FLUSH_ENABLED`. |
| `MSG_SEQ_FLUSH_TICK_INTERVAL` | 500ms | How often flush goroutine checks for complete pairs |
| `AKTO_PER_CONN_CH_BUFFER_SIZE` | 10 | Per-connection channel buffer (events) |
| `EVENT_CHAN_BUFF_SIZE` | 100000 | Per-ProbeChannel Go event channel buffer size |
| `TRAFFIC_INACTIVITY_THRESHOLD` | 7s | Worker + flush goroutines exit after this silence |
| `TRAFFIC_MAX_ACTIVE_CONN` | 4096 | Max tracked connections; new conns dropped if exceeded |
| `TRAFFIC_IGNORE_DEFAULT_PORTS` | true | Ignore kafka/zookeeper/mongo/redis ports |
| `MSG_SEQ_LOGS` | false | Gate all msg_seq pipeline log lines (slog.Warn/Info) |
