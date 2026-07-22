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
                          │  1. CanBeFilled() + BufferCheck() — drop silently if over      │
                          │     limits (maxActiveConnections, sampleBufferPerMin)           │
                          │  2. binary.Read → parse event.Attr (fixed-size header, 68B)    │
                          │  3. copy(event.Msg[:], data[68:68+absBytes])                   │
                          │     perf event buffer bytes → event.Msg array on stack         │
                          │  4. Filter: skip ports (kafka/zookeeper/mongo/redis)            │
                          │  5. CreateIfNotExists(connId)                                  │
                          │     └─ if new: Tracker + per-conn channel (buffer=10)          │
                          │        + start Worker goroutine                                │
                          │        + start Flush goroutine (if UseMsgSeqFlush)             │
                          │  6. Pipeline.EventsReceived.Add(1)                             │
                          │  7. SendEvent(connId, &event) — non-blocking send              │
                          │     if channel full: DROP → EventsDroppedChannelFull++         │
                          │  8. UpdateBufferSize(absBytes)                                 │
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
                          │      SocketDataEvent → tracker.AddDataEvent(*e)               │
                          │        └─ acquires tracker.mutex (Lock)                        │
                          │        └─ append(group.chunks[chunkKey], event.Msg[:n]...)    │
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
                          ┌─ Flush Goroutine (one per connection) ──────────────────────────────────────────┐
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
                          │      convertToSingleByteArr(pair.ReqGroup.chunks) → reqBlob                │
                          │        sort chunk keys (rc order), append into combined []byte                   │
                          │        stops early on key gap → ChunkAssemblyGaps++                              │
                          │      convertToSingleByteArr(pair.RespGroup.chunks) → respBlob                   │
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
  → copy(event.Msg, data[68:68+4096])
  → SendEvent → per-conn channel

Go: Worker goroutine
  → AddDataEvent: append chunk into msgGroups[3], msgGroups[4]
  → highestMsgSeq = 4

Go: next request arrives → msg_seq=5 event
  → highestMsgSeq = 5

Go: flush ticker (500ms)
  → GetFlushablePairs: seq=3, seq+2=5 <= highestMsgSeq=5 ✓
  → g1=msgGroups[3], g2=msgGroups[4] both present → pair
  → delete msgGroups[3], msgGroups[4], lowestPendingSeq=5
  → convertToSingleByteArr(g1.chunks) → reqBlob
  → convertToSingleByteArr(g2.chunks) → respBlob
  → ParseAndProduce → json.Marshal → Kafka
```

## Goroutines per Connection

```
Connection fd=8:
  1. Worker goroutine  — reads ch, calls AddDataEvent (fast: mutex + map append)
  2. Flush goroutine   — ticker 500ms, GetFlushablePairs + HTTP parse + Kafka (slow)

Shared state: tracker.msgGroups (protected by tracker.mutex)
  - Worker writes:  AddDataEvent acquires Lock → append chunk → Unlock
  - Flush reads:    GetFlushablePairs acquires Lock → walk/delete → Unlock
  - Contention:     flush holds lock for full map walk; worker blocks during that window
                    if blocked long enough → per-conn channel fills (buffer=10) → DROP
```

## Key Data Structures

```
Tracker.msgGroups: map[uint32]*msgSeqGroup
  │
  ├─ msgSeq=3 → msgSeqGroup{direction=kIngress, chunks: map[int][]byte}
  │                                                      ├─ rc=1 → []byte
  │                                                      └─ rc=2 → []byte (if multi-chunk)
  ├─ msgSeq=4 → msgSeqGroup{direction=kEgress, chunks: map[int][]byte}
  │                                                     └─ wc=1 → []byte
  └─ msgSeq=5 → msgSeqGroup{...}  ← existence of this triggers flush of (3,4)

Tracker state:
  lowestPendingSeq  — drainPairs walks from here; advances past flushed/skipped seqs
  highestMsgSeq     — highest msg_seq seen; set AFTER msgGroups insert in same lock hold,
                      so seq+2 <= highestMsgSeq guarantees msgGroups[seq+2] already exists
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
   → Cause: middle chunk (rc/wc key) dropped; convertToSingleByteArr stops early
   → Metric: chunk_assembly_gaps
   → Effect: truncated blob → parse failure downstream
```

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
`convertToSingleByteArr` stops on first rc/wc key gap. Dropped middle chunk → truncated blob
→ `pairs_parse_failure`.

### 4. Last-pair delay
Final request-response pair of a burst has no N+2 trigger. Waits for inactivity timer (7s)
before `FlushRemainingPairs` is called. Expected behavior, not a bug.

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `MSG_SEQ_FLUSH_ENABLED` | false | Enable msg_seq based incremental pair flushing |
| `MSG_SEQ_FLUSH_TICK_INTERVAL` | 500ms | How often flush goroutine checks for complete pairs |
| `AKTO_PER_CONN_CH_BUFFER_SIZE` | 10 | Per-connection channel buffer (events) |
| `EVENT_CHAN_BUFF_SIZE` | 100000 | Per-ProbeChannel Go event channel buffer size |
| `TRAFFIC_INACTIVITY_THRESHOLD` | 7s | Worker + flush goroutines exit after this silence |
| `TRAFFIC_MAX_ACTIVE_CONN` | 4096 | Max tracked connections; new conns dropped if exceeded |
| `TRAFFIC_IGNORE_DEFAULT_PORTS` | true | Ignore kafka/zookeeper/mongo/redis ports |
| `MSG_SEQ_LOGS` | false | Gate all msg_seq pipeline log lines (slog.Warn/Info) |
