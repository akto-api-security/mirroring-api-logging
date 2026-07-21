# Pipeline Metrics Reference

## Endpoint

```
GET http://<pod-ip>:6060/metrics/pipeline        # current counters (since last reset)
GET http://<pod-ip>:6060/metrics/pipeline/reset  # return current then zero all counters
```

Both return JSON. All counters are cumulative since the last reset (or since process start).

---

## Counter Definitions

### Input

| Field | Description |
|---|---|
| `events_received` | Events that were successfully binary-decoded in `SocketDataEventCallback` and dispatched to `SendEvent`. Does **not** include events dropped at the kernel ring buffer level. |

### Drop Points

| Field | Description |
|---|---|
| `events_dropped_kernel_ring_buf` | Events lost before reaching Go. Reported by gobpf's `lostEventsChannel`. Cause: perf reader goroutines too slow to drain the kernel perf buffer. |
| `events_dropped_channel_full` | Events dropped by `SendEvent` because the per-connection channel was full (non-blocking send, default case). Cause: worker goroutine blocked on tracker.mutex. |

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
| `chunk_assembly_gaps` | `convertToSingleByteArr` detected a gap in rc/wc chunk keys and truncated the blob early. A dropped chunk causes this. The resulting truncated blob typically causes `pairs_parse_failure` downstream. Connects top-of-pipeline drops to parse failures. |
| `pairs_attempted` | Pairs passed to `ProcessSinglePair`. Incremented before HTTP blob detection. |
| `pairs_parse_success` | Pairs where `ParseAndProduce` successfully produced at least one request-response to Kafka. |
| `pairs_parse_failure` | Pairs where `parseHTTPTraffic` returned nil — neither blob was a recognizable HTTP message (corrupt or truncated). |
| `request_body_failure` | Pairs where `io.ReadAll` failed on the request body. Pair is still produced with empty body; not counted as parse failure. |
| `response_body_failure` | Pairs where `io.ReadAll` failed on the response body. Same treatment as above. |

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

Each metric has a corresponding log line to pinpoint when it occurred:

| Metric | Log message |
|---|---|
| `events_dropped_kernel_ring_buf` | `⚠️ Lost N events on channel socket_data_events` |
| `events_dropped_channel_full` | `Dropping event Channel full` |
| `out_of_order_arrivals` | `msg_seq: out-of-order group arrival` |
| `late_arrivals` | `msg_seq: late arrival below lowestPendingSeq (already flushed)` |
| `gap_skips_fired` / `gap_skip_seqs_lost` | `msg_seq: gap-skip fd=N skipped_from=M lowestPendingSeq_after=K` |
| `groups_orphaned` | `msg_seq: orphaned group (partner missing)` |
| `pairs_parse_failure` | logged inside `ParseAndProduce` |
| `pairs_parse_success` (inverse) | `msg_seq: flushing pair` (one per pair attempted) |
