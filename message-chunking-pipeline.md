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
perf_submit()  ──────────────►  perf reader goroutines (one per CPU, BPF_PERF_OUTPUT)
                                  │ 8192 pages per CPU → ~32MB kernel-side buffer
                                  │ multiple goroutines race into a single Go channel
                                  │
                                  ▼
                                eventChannel (chan []byte, buffer=EVENT_CHAN_BUFF_SIZE)
                                  │ single global channel for ALL connections
                                  │
                                  ▼
                          ┌─ SocketDataEventCallback (SINGLE goroutine) ─┐
                          │                                               │
                          │  1. binary.Read → parse SocketDataEvent       │
                          │  2. CreateIfNotExists(connId)                  │
                          │     └─ if new: create Tracker + per-conn ch   │
                          │        + start worker goroutine               │
                          │        + start flush goroutine                │
                          │  3. SendEvent(connId, &event)                 │
                          │     └─ ch <- event (non-blocking)             │
                          │     └─ if channel full: DROP                  │
                          └───────────────────────────────────────────────┘
                                  │
                                  ▼
                          per-connection channel (chan interface{}, buffer=AKTO_PER_CONN_CH_BUFFER_SIZE)
                                  │
                                  ▼
                          ┌─ Worker Goroutine (one per connection) ──────┐
                          │                                              │
                          │  select:                                     │
                          │    case event <- ch:                         │
                          │      SocketDataEvent → tracker.AddDataEvent  │
                          │        └─ appends chunk to msgGroups[msg_seq]│
                          │      SocketOpenEvent  → tracker.AddOpenEvent │
                          │      SocketCloseEvent → close(done)          │
                          │                                              │
                          │    case <-inactivityTimer (7s):              │
                          │      close(done) → cleanup                   │
                          └──────────────────────────────────────────────┘
                                  │
                          (done channel signals flush routine to exit)
                                  │
                                  ▼
                          ┌─ Flush Goroutine (one per connection) ────────────────────────┐
                          │                                                                │
                          │  ticker (every MSG_SEQ_FLUSH_TICK_INTERVAL, default 500ms):   │
                          │    1. tracker.GetFlushablePairs()                              │
                          │       └─ acquires tracker.mutex                               │
                          │       └─ pair (N, N+1) is flushable when N+2 exists          │
                          │       └─ advances lowestPendingSeq                            │
                          │       └─ deletes flushed groups from msgGroups                │
                          │       └─ releases tracker.mutex                               │
                          │    2. for each pair:                                          │
                          │       convertToSingleByteArr(chunks) → reqBlob, respBlob     │
                          │       ProcessSinglePair → tryReadFromBD → ParseAndProduce    │
                          │         └─ http.ReadRequest / http.ReadResponse               │
                          │         └─ Kafka produce                                     │
                          │                                                               │
                          │  case <-done:                                                 │
                          │    FlushRemainingPairs (no N+2 trigger needed)               │
                          │    return                                                     │
                          └───────────────────────────────────────────────────────────────┘
```

## How a 20KB HTTP Request Flows Through

```
Kernel: echo-server calls read(fd=8, buf, 4096)
  → BPF intercepts via syscall__probe_ret_read
  → process_syscall_data(is_send=false)
  → direction = kIngress
  → msg_seq was 0 → set to 1, prev_direction = kIngress
  → chunk loop: 4096 bytes → perf_submit (rc=1, wc=0, msg_seq=1)

Kernel: read(fd=8) again → 4096 bytes
  → direction = kIngress, same as prev → msg_seq stays 1
  → perf_submit (rc=2, wc=0, msg_seq=1)

... more reads (all msg_seq=1) ...

Kernel: echo-server calls write(fd=8, response, 4096)
  → direction = kEgress, different from prev (kIngress) → msg_seq becomes 2
  → perf_submit (rc=N, wc=1, msg_seq=2)

... more writes (all msg_seq=2) ...

Go: all events arrive on eventChannel, dispatched to fd=8's worker channel
  → AddDataEvent: chunks grouped into msgGroups[1] (request) and msgGroups[2] (response)

Kernel: next request arrives, read(fd=8)
  → direction = kIngress, different from prev (kEgress) → msg_seq becomes 3
  → perf_submit arrives in Go

Go: flush ticker fires, GetFlushablePairs:
  → msgGroups[1] exists, msgGroups[2] exists, msgGroups[3] exists (trigger)
  → pair (1, 2) is complete → flush
  → convertToSingleByteArr(msgGroups[1].chunks) → request blob
  → convertToSingleByteArr(msgGroups[2].chunks) → response blob
  → ProcessSinglePair → ParseAndProduce → Kafka
```

## Goroutines per Connection

```
Connection fd=8:
  1. Worker goroutine     — reads ch, calls AddDataEvent (fast, map append)
  2. Flush goroutine      — ticker, calls GetFlushablePairs + ProcessSinglePair (slow, HTTP parse + Kafka)

Shared state: tracker.msgGroups (protected by tracker.mutex)
  - Worker writes (AddDataEvent acquires Lock)
  - Flush reads/deletes (GetFlushablePairs acquires Lock)
  - Contention: flush holds lock while iterating/deleting → worker blocks
```

## Key Data Structures

```
Tracker.msgGroups: map[uint32]*msgSeqGroup
  │
  ├─ msgSeq=1 → msgSeqGroup{direction=kIngress, chunks: map[int][]byte}
  │                                                      ├─ rc=1 → []byte
  │                                                      ├─ rc=2 → []byte
  │                                                      └─ ...
  ├─ msgSeq=2 → msgSeqGroup{direction=kEgress, chunks: map[int][]byte}
  │                                                     ├─ wc=1 → []byte
  │                                                     └─ ...
  └─ msgSeq=3 → msgSeqGroup{direction=kIngress, ...} (next request, triggers flush of 1,2)

Tracker state:
  lowestPendingSeq  — drainPairs starts walking from here; advances past flushed/skipped seqs
  highestMsgSeq     — highest msg_seq seen; used as upper bound for GetFlushablePairs
```

## Drop Points (where data can be lost)

```
1. Kernel perf ring buffer overflow
   → Cause: perf reader goroutines drain too slowly; kernel buffer fills
   → Metric: events_dropped_kernel_ring_buf
   → Logged: "Lost N events on channel socket_data_events"

2. Per-connection channel overflow
   → Cause: worker goroutine blocked on tracker.mutex (flush routine holding it)
   → Metric: events_dropped_channel_full
   → Logged: "Dropping event Channel full"
   → Effect: one dropped chunk corrupts that msg_seq group

3. Gap-skip (indirect loss)
   → Cause: a sequence gap (from drop 1 or 2) forces lowestPendingSeq past missing seqs
   → Metric: gap_skips_fired, gap_skip_seqs_lost
   → Logged: "msg_seq: gap-skip"
   → Effect: events that arrive after the skip but belong to an already-skipped seq
     become late arrivals and are silently discarded

4. Late arrivals (indirect loss)
   → Cause: gap-skip advanced lowestPendingSeq past a seq whose events are delayed
     (cross-CPU delivery skew from gobpf's per-CPU reader goroutines racing into eventChannel)
   → Metric: late_arrivals
   → Logged: "msg_seq: late arrival below lowestPendingSeq"

5. Orphaned groups
   → Cause: one side of a pair (request or response) was dropped; partner has no match
   → Metric: groups_orphaned
   → Logged: "msg_seq: orphaned group (partner missing)"
```

## Cross-CPU Ordering: The Root Cause of Out-of-Order Arrivals

gobpf's `InitPerfMapWithPageCnt` starts one reader goroutine per CPU core. Each CPU has its own
perf event sub-buffer. All reader goroutines write into the same `eventChannel chan []byte`.

When the kernel submits events for a single connection across multiple CPUs (which happens when
the process migrates CPUs between syscalls, or via IRQ affinity), the goroutines race:

```
CPU0 reader: reads events for writes (msg_seq=2)
CPU1 reader: reads events for reads  (msg_seq=1, but submitted later to CPU1's buffer)

Both race into eventChannel → msg_seq=2 events may arrive before msg_seq=1 events
```

This is NOT data loss — the out-of-order group is still created in msgGroups and reachable
by drainPairs. It only becomes data loss if a gap-skip fires before all chunks arrive.

**Key distinction:**
- `out_of_order_arrivals`: group arrives late but within [lowestPendingSeq, highestMsgSeq] → safe, reachable
- `late_arrivals`: group arrives after lowestPendingSeq already passed it → silently discarded

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| MSG_SEQ_FLUSH_ENABLED | false | Enable msg_seq based incremental pair flushing |
| MSG_SEQ_FLUSH_TICK_INTERVAL | 500ms | How often flush routine checks for complete pairs |
| AKTO_PER_CONN_CH_BUFFER_SIZE | 10 | Per-connection channel buffer size |
| EVENT_CHAN_BUFF_SIZE | 100000 | Global perf event channel buffer |
| TRAFFIC_INACTIVITY_THRESHOLD | 7s | Worker killed after this much silence |

## Known Problems

### 1. Mutex contention under load
`GetFlushablePairs` holds `tracker.mutex` while iterating and deleting msgGroups.
`AddDataEvent` blocks waiting for the same lock. Under sustained high throughput, this can
cause the per-connection channel to fill while the worker is blocked, leading to drops.

### 2. Gap-skip cascade
One kernel-side or channel drop creates a sequence gap. The gap causes a gap-skip, which
advances `lowestPendingSeq`. Cross-CPU delayed events for the skipped seqs then become
late arrivals. A single drop can thus cause multiple downstream discards.

### 3. No chunk-level gap detection
`convertToSingleByteArr` assembles chunks in rc/wc order and stops on the first gap in keys.
If a middle chunk is dropped (e.g., wc=2 of a 3-write response), the assembled blob is
truncated silently. The HTTP parser then sees a partial message.

### 4. Last-pair delay
The final request-response pair of a burst has no N+2 trigger. It waits for the inactivity
timer (default 7s) before being flushed. This is expected behavior, not a bug.
