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
perf_submit()  ──────────────►  perf reader (per-CPU ring buffers, 8192 pages = 32MB each)
                                  │
                                  ▼
                                eventChannel (chan []byte, buffer=100,000)
                                  │ single global channel for ALL connections
                                  │
                                  ▼
                          ┌─ SocketDataEventCallback (SINGLE goroutine) ─┐
                          │                                               │
                          │  1. binary.Read → parse SocketDataEvent       │
                          │  2. CreateIfNotExists(connId)                  │
                          │     └─ if new: create Tracker + per-conn ch   │
                          │        + start worker goroutine               │
                          │        + start flush goroutine (if msg_seq)   │
                          │  3. SendEvent(connId, &event)                 │
                          │     └─ ch <- event (non-blocking)             │
                          │     └─ if channel full: DROP (default case)   │
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
                          ┌─ Flush Goroutine (one per connection, if MSG_SEQ_FLUSH_ENABLED) ─┐
                          │                                                                   │
                          │  ticker (every MSG_SEQ_FLUSH_TICK_INTERVAL, default 500ms):       │
                          │    1. tracker.GetFlushablePairs()                                  │
                          │       └─ acquires tracker.mutex                                    │
                          │       └─ pair (N, N+1) is flushable when N+2 exists               │
                          │       └─ deletes flushed groups from msgGroups                    │
                          │       └─ releases tracker.mutex                                   │
                          │    2. for each pair:                                               │
                          │       convertToSingleByteArr(chunks) → reqBlob, respBlob          │
                          │       ProcessSinglePair → tryReadFromBD → ParseAndProduce         │
                          │         └─ http.ReadRequest / http.ReadResponse                   │
                          │         └─ Kafka produce                                          │
                          │                                                                   │
                          │  case <-done:                                                     │
                          │    FlushRemainingPairs (no N+2 trigger needed)                    │
                          │    return                                                         │
                          └───────────────────────────────────────────────────────────────────┘
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

... 4 more reads (rc=3,4,5,6, all msg_seq=1) ...

Kernel: echo-server calls write(fd=8, response, 4096)
  → direction = kEgress, different from prev (kIngress) → msg_seq becomes 2
  → perf_submit (rc=6, wc=1, msg_seq=2)

... 2 more writes (wc=2,3, all msg_seq=2) ...

Go: all 9 events arrive on eventChannel, dispatched to fd=8's worker channel
  → AddDataEvent: chunks grouped into msgGroups[1] (6 chunks) and msgGroups[2] (3 chunks)

Kernel: next request arrives, read(fd=8)
  → direction = kIngress, different from prev (kEgress) → msg_seq becomes 3
  → perf_submit arrives in Go

Go: flush ticker fires, GetFlushablePairs:
  → msgGroups[1] exists, msgGroups[2] exists, msgGroups[3] exists (trigger)
  → pair (1, 2) is complete → flush
  → convertToSingleByteArr(msgGroups[1].chunks) → 21KB request blob
  → convertToSingleByteArr(msgGroups[2].chunks) → 24KB response blob
  → ProcessSinglePair → ParseAndProduce → Kafka
```

## Goroutines per Connection (when MSG_SEQ_FLUSH_ENABLED=true)

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
  │                                                      ├─ rc=1 → []byte (4096 bytes)
  │                                                      ├─ rc=2 → []byte (4096 bytes)
  │                                                      └─ ...
  ├─ msgSeq=2 → msgSeqGroup{direction=kEgress, chunks: map[int][]byte}
  │                                                     ├─ wc=1 → []byte (4096 bytes)
  │                                                     └─ ...
  └─ msgSeq=3 → msgSeqGroup{direction=kIngress, ...} (next request, triggers flush of 1,2)
```

## Drop Points (where data can be lost)

```
1. Kernel perf ring buffer overflow
   → "Lost N events on channel socket_data_events" logged
   → Cause: Go perf reader too slow to drain
   → Buffer: 8192 pages = 32MB per CPU

2. eventChannel overflow
   → SocketDataEventCallback blocks, perf reader backs up → drop point 1
   → Buffer: 100,000 events (EVENT_CHAN_BUFF_SIZE)

3. Per-connection channel overflow  ← MAIN DROP POINT
   → SendEvent drops with "Dropping event Channel full"
   → Buffer: AKTO_PER_CONN_CH_BUFFER_SIZE (default 10, set to 200)
   → Cause: worker goroutine blocked on tracker.mutex (flush routine holding it)

4. Stale/orphaned msg_seq groups
   → Partner group's events were dropped at point 3
   → Discarded on inactivity flush with "orphaned group discarded"
```

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| MSG_SEQ_FLUSH_ENABLED | false | Enable msg_seq based incremental pair flushing |
| MSG_SEQ_FLUSH_TICK_INTERVAL | 500ms | How often flush routine checks for complete pairs |
| AKTO_PER_CONN_CH_BUFFER_SIZE | 10 | Per-connection channel buffer size |
| EVENT_CHAN_BUFF_SIZE | 100000 | Global perf event channel buffer |
| TRAFFIC_INACTIVITY_THRESHOLD | 7s | Worker killed after this much silence |
| SOCKET_DATA_EVENT_BYTES_THRESHOLD | 10MB | Worker killed after accumulating this much data (disabled when msg_seq on) |

## Known Issues

1. **Mutex contention**: GetFlushablePairs holds tracker.mutex while iterating/deleting.
   AddDataEvent blocks waiting. At 6000 RPM: up to 195ms wait, 186ms hold.
   Absorbed by buffer=200 but won't scale to 1 Gbps.

2. **Channel drops**: At high throughput (6000 RPM, 20KB payload), per-connection channel
   overflows if buffer is too small. Dropped events cause orphaned msg_seq groups.

3. **Chunked encoding terminator**: The 7-byte `0\r\n\r\n` is a separate write() syscall
   and a separate perf event. If this specific event is dropped, the response gets
   "unexpected EOF" during HTTP parsing. The request is captured but response body is lost.
