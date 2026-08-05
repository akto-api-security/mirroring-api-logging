# Pipeline Metrics Reference

## Endpoint

```
GET http://<pod-ip>:6060/metrics/pipeline        # current counters (since last reset)
GET http://<pod-ip>:6060/metrics/pipeline/reset  # return current then zero all counters
```

Both return JSON. All counters are cumulative since the last reset (or since process start).

**`AKTO_FAST_INGESTION` matters for interpretation.** Most of these counters (group lifecycle,
gap-skip, reorder histograms, `pairs_attempted`) are populated only on the msg_seq path
(`AKTO_FAST_INGESTION=true`, `ebpf/connections/tracker.go` + `flushPairedRequests.go`). With
fast ingestion disabled, the old flat-buffer path (`flushFlatBuffer.go`) runs instead and does
not touch those counters at all — they'll stay at zero regardless of actual traffic. Only
`events_received`, `input_chan_len/cap`, the two drop counters, and (depending on
`AKTO_FAST_INGESTION` inside `kafkaUtil`) the parse/pair-outcome counters are populated on
both paths.

---

## Counter Definitions

### Input

| Field | Description |
|---|---|
| `events_received` | Data events that passed the port-ignore filter in `SocketDataEventCallback` and were dispatched to `SendDataEvent` (zero-copy — no binary decode, just an `unsafe.Pointer` view cast). Does **not** include events dropped at the kernel ring buffer level. |
| `input_chan_len` | `len(inputChan)` sampled every 1000 events — how backed-up the perf-buffer→callback channel is. |
| `input_chan_cap` | `cap(inputChan)` — set once at startup; the ceiling `input_chan_len` is measured against. |

### Drop Points

| Field | Description |
|---|---|
| `events_dropped_kernel_ring_buf` | Events lost before reaching Go. Reported by gobpf's `lostEventsChannel`. Cause: perf reader goroutines too slow to drain the kernel perf buffer. |
| `events_dropped_channel_full` | Events dropped because the per-connection channel was full (non-blocking send, default case) — from either `SendEvent` (open/close events) or `SendDataEvent` (data events, `factory.go`). Cause: worker goroutine blocked on tracker.mutex, or the worker simply can't keep up with the channel's inflow rate. |

### Group Lifecycle

One group = one HTTP message direction (all chunks sharing the same `msg_seq`).
Every HTTP request on a connection creates 2 groups: one ingress (request), one egress (response).

| Field | Description |
|---|---|
| `groups_created` | New msg_seq group first seen in `AddDataEvent`. Proxy for "HTTP message boundaries seen". |
| `groups_orphaned` | Groups whose partner (request or response) was missing at flush time in `drainPairs`. Cause: partner's events were dropped, or connection closed mid-flight. |
| `groups_stranded` | Groups discarded at final flush because they were below `lowestPendingSeq` (late arrivals written back into msgGroups). Cause: premature gap-skip due to cross-CPU delivery skew. |
| `out_of_order_arrivals` | Group arrived with `msg_seq < highestMsgSeq` but `≥ lowestPendingSeq`. Cross-CPU delivery skew (multiple gobpf reader goroutines race into eventChannel). **Not data loss** — group is still reachable by drainPairs. |
| `late_arrivals` | Group arrived with `msg_seq < lowestPendingSeq` (already passed by drainPairs). **Silent discard** — group is stranded, never flushed. |

### Reorder Distance Histograms

`out_of_order_dist` and `late_arrival_dist` bucket `highestMsgSeq - msgSeq` (the reorder
distance) at the moment each out-of-position arrival is observed — one histogram for the
recoverable case (`out_of_order_arrivals`), one for the lost case (`late_arrivals`). Buckets:
`d1`, `d2_4`, `d5_8`, `d9_16`, `d17_32`, `d33_64`, `d65_plus`. Used to size the flush-hold /
gap-skip threshold: pick it at roughly the p99 of `late_arrival_dist`'s recoverable cluster —
see Known Problem #1 (premature gap-skip) in `message-chunking-pipeline.md`.

### Gap-Skip

A gap-skip occurs when `drainPairs` encounters a missing seq (e.g., seq=5 missing) and
must advance `lowestPendingSeq` past it. Any events for seq=5 that arrive *after* the skip
become late arrivals.

| Field | Description |
|---|---|
| `gap_skips_fired` | How many times drainPairs hit a missing seq and had to skip forward. |
| `gap_skip_seqs_lost` | Total number of individual seqs skipped across all gap-skips. |

### Pair Outcomes

| Field | Description |
|---|---|
| `chunk_assembly_gaps` | `fragmentsToBytes` (msg_seq path, `flushPairedRequests.go`) or `convertToSingleByteArr` (flat-buffer path, `flushFlatBuffer.go`) detected a gap in seq/chunk keys and truncated the blob early. A dropped fragment/chunk causes this. The resulting truncated blob typically causes `pairs_parse_failure` downstream. Connects top-of-pipeline drops to parse failures. |
| `pairs_attempted` | Pairs passed to `ProcessSinglePair` (`flushPairedRequests.go`), incremented before HTTP blob detection. **Only incremented on the msg_seq path** (`AKTO_FAST_INGESTION=true`) — the flat-buffer path's `ProcessTrackerData` has no equivalent counter, so this (and `groups_created`, `coverage_pct`) reads near-zero when fast ingestion is disabled. |
| `pairs_parse_success` | Pairs where HTTP parsing + Kafka produce succeeded. Incremented from either parse path: `fastParseAndProduce` (fast/zero-copy, `AKTO_FAST_INGESTION=true`) or the std-lib `ParseAndProduce`/`parseHTTPTraffic` path (`AKTO_FAST_INGESTION=false`), in `trafficUtil/kafkaUtil/parse.go`+`parser.go`. |
| `pairs_parse_failure` | Pairs where parsing failed — `parseHTTPTraffic` returned nil (std-lib path) or `ParseRequest`/`ParseResponse` errored (fast path) — neither blob was a recognizable HTTP message (corrupt or truncated). |
| `pairs_mismatched` | Pairs where `X-Debug-Token` request header value was not found in the response body. Indicates a mangled or mismatched request-response pairing. Only fires when the header is present (echo-server / debug runs). Checked on both parse paths. |
| `request_body_failure` | Pairs where `io.ReadAll` failed on the request body. **Only fires on the std-lib slow path** (`parseHTTPTraffic`, `AKTO_FAST_INGESTION=false`), and only for requests whose method/host/path matched the body-parsing policy (`shouldParseBody`) — the fast path (zero-copy `fastparser`) has no equivalent failure mode. Pair is still produced with empty body; not counted as a parse failure. |
| `response_body_failure` | Same as `request_body_failure`, for the response body. |

### Computed Fields

| Field | Description |
|---|---|
| `duration_sec` | Seconds elapsed since last reset. |
| `coverage_pct` | `pairs_parse_success / (groups_created / 2) * 100`. Measures internal pipeline efficiency: of all HTTP message boundaries captured, what fraction became successful pairs. **Does not measure coverage vs total requests sent** — it only counts what the pipeline saw. |

---

## Interpreting the Numbers

### Ideal run (no drops, no gaps)

```
events_dropped_kernel_ring_buf = 0
events_dropped_channel_full    = 0
late_arrivals                  = 0
gap_skips_fired                = 0
groups_orphaned                = 0
pairs_parse_failure            = 0
coverage_pct                   = ~100%
```

`out_of_order_arrivals` will typically be non-zero even in ideal runs due to cross-CPU
gobpf reader goroutine races. This is expected and does not cause data loss by itself.

### Diagnosing data loss

Work through the pipeline in order:

1. **Kernel drops?** Check `events_dropped_kernel_ring_buf > 0`.
   - If yes: perf reader goroutines are behind. Consider increasing page count or reducing event volume.

2. **Channel drops?** Check `events_dropped_channel_full > 0`.
   - If yes: mutex contention between worker and flush goroutine. Increase `AKTO_PER_CONN_CH_BUFFER_SIZE` or reduce flush lock hold time.

3. **Gap-skips?** Check `gap_skips_fired > 0`.
   - Confirms that a drop created a sequence gap. Each gap-skip can cause downstream late arrivals.
   - `gap_skip_seqs_lost` shows total seqs abandoned.

4. **Late arrivals?** Check `late_arrivals`.
   - Direct count of events that arrived too late and were discarded.
   - Typically caused by gap-skip cascade (drop → gap → skip → late arrival).

5. **Orphaned groups?** Check `groups_orphaned`.
   - Half-pairs that couldn't be matched. Divide by 2 for approximate lost HTTP transactions.

6. **Parse failures?** Check `pairs_parse_failure`.
   - Corrupt or truncated blobs that couldn't be parsed as HTTP at all.

### Reconciliation formula

```
pairs_attempted  ≈  (groups_created / 2)
                  - (groups_orphaned / 2)
                  - (late_arrivals / 2)   [approximate]
                  - pending_in_trackers   [not exposed]
```

Differences from exact `groups_created/2` are caused by late arrivals and orphans removing
groups before they can be paired. The "pending_in_trackers" term is not exposed but represents
groups still buffered in live connections at snapshot time.

---

## Example Queries

```bash
# Live snapshot
curl -s http://localhost:6060/metrics/pipeline | python3 -m json.tool

# Reset and capture previous window
curl -s http://localhost:6060/metrics/pipeline/reset | python3 -m json.tool

# Watch coverage in a loop (requires jq)
watch -n 5 'curl -s http://localhost:6060/metrics/pipeline | jq .coverage_pct'

# Check for any drops
curl -s http://localhost:6060/metrics/pipeline | jq '{
  kernel_drops: .events_dropped_kernel_ring_buf,
  channel_drops: .events_dropped_channel_full,
  gap_skips: .gap_skips_fired,
  gap_seqs_lost: .gap_skip_seqs_lost,
  late: .late_arrivals,
  orphaned: .groups_orphaned,
  parse_fail: .pairs_parse_failure,
  coverage: .coverage_pct
}'
```

---

## Log Correlation

Each metric has a corresponding log line to pinpoint when it occurred. All `msg_seq: ...` lines
are gated behind the `MSG_SEQ_LOGS` env var (`IsMsgSeqLogsEnabled()`) — off by default, since
they fire per-group/per-pair and are too high-volume for always-on production logging.

| Metric | Log message |
|---|---|
| `events_dropped_kernel_ring_buf` | `⚠️ Lost N events on channel socket_data_events` |
| `events_dropped_channel_full` | `Dropping event Channel full` |
| `out_of_order_arrivals` | `msg_seq: out-of-order group arrival` (behind `MSG_SEQ_LOGS`) |
| `late_arrivals` | `msg_seq: late arrival below lowestPendingSeq (already flushed)` (behind `MSG_SEQ_LOGS`) |
| `gap_skips_fired` / `gap_skip_seqs_lost` | `msg_seq: gap-skip fd=N skipped_from=M lowestPendingSeq_after=K` (behind `MSG_SEQ_LOGS`) |
| `groups_orphaned` | `msg_seq: orphaned group (partner missing)` (behind `MSG_SEQ_LOGS`) |
| `groups_stranded` | `msg_seq: stranded group discarded at final flush` (behind `MSG_SEQ_LOGS`) |
| `pairs_parse_failure` | `PrintLog` inside `parseHTTPTraffic` (slow path) or silent on the fast path (`ParseRequest`/`ParseResponse` error, no log) |
| `pairs_parse_success` (inverse) | `msg_seq: flushing pair` (behind `MSG_SEQ_LOGS`, msg_seq path only — one per pair attempted, logged in `drainPairs` before the parse actually runs) |
| `pairs_mismatched` | no log line — check by correlating `X-Debug-Token` values in request/response blobs |
