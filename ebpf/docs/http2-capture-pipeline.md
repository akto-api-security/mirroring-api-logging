# HTTP/2 + gRPC Capture Pipeline: Kernel to Kafka

## Overview

eBPF captures TCP read/write (and SSL_read/write) syscalls, chunks the data into
perf events, and delivers them to Go userspace — identical to the HTTP/1.1 path up
to the tracker. From there HTTP/2 diverges: it cannot use the `msg_seq` /
`drainPairs` pairing (that assumes half-duplex ping-pong), so a per-connection
**stream_id**-based, HPACK-stateful parser takes over. Completed unary
request/response pairs are emitted through the same fast encode + Kafka produce
pipeline the HTTP/1.1 path uses.

Scope today: **unary (1:1)** RPCs. Streaming modes (1:N / N:1 / N:M) are recognized
but not emitted (see Known Problems).

## Why HTTP/2 needs a different path

```
HTTP/1.1 (msg_seq path)                 HTTP/2 (this doc)
───────────────────────                 ─────────────────
half-duplex req→resp→req→resp           multiplexed + full-duplex
msg_seq increments on direction change  direction change is meaningless
pair = (msg_seq N, N+1)                 pair = same stream_id, egress+ingress
each request parses independently       HPACK dynamic table is cumulative per
  (stateless http.ReadRequest at flush)   direction → MUST decode the whole
                                          ordered frame stream from the start
fragments sorted by rc/wc AT FLUSH      bytes must be fed IN ORDER, INCREMENTALLY
  (fragmentsToBytes)                      (h2Reassembler, on ingest)
zero-copy fragment views                copies (contiguous framing + body accrual)
```

Two facts drive the whole design:

1. **stream_id is the pairing key.** A gRPC call's request and response share the
   same HTTP/2 stream_id, told apart only by direction. Correlation is free once
   frames are demuxed — no odd/even adjacency.
2. **HPACK is connection-global.** The dynamic table is per-connection,
   per-direction, and cumulative: decoding stream 7's headers requires having
   decoded every prior HEADERS frame (all streams) in order. So there is one
   long-lived decoder per direction, fed the full ordered byte stream — you cannot
   parse a stream in isolation, and a single dropped/reordered header block desyncs
   the rest of the connection.

## Pipeline Stages

```
Kernel (BPF)                         Go Userspace
────────────                         ────────────
read()/write()/SSL_*()
  │ classify_protocol() on first
  │ decisive buffer → conn.protocol
  │ = HTTP2 (PRI * HTTP/2.0 preface)
  │ stamped on every socket_data_event
  ▼
perf_event_output()  ──────────────► SocketDataEventCallback (unchanged)
  (≤30KB chunks, rc/wc per direction)   │  CreateIfNotExists + Worker + Flush goroutine
                                        ▼
                            ┌─ Worker Goroutine (one per connection) ────────────────┐
                            │  AddDataEvent(kernelBytesPtr):                          │
                            │    latch conn.protocol ← attr.Protocol                  │
                            │    if protocol == HTTP2 (and FastIngestion):            │
                            │        addHTTP2Event(attr, payload)   ── http2.go       │
                            │        └─ pick reassembler by direction:                │
                            │             egress → h2egress (seq = WriteEventsCount)   │
                            │             ingress→ h2ingress(seq = ReadEventsCount)    │
                            │        └─ h2Reassembler.add(seq, payload, feed):         │
                            │             release CONTIGUOUS prefix in seq order,     │
                            │             buffer out-of-order chunks (gap → Fail)     │
                            │        └─ feed → HTTP2Conn.Feed(isRequest, bytes)        │
                            └────────────────────────────────────────────────────────┘
                                        │
                            ┌─ HTTP2Conn (persistent, per connection) — http2parser.go ┐
                            │  req  dirState: hpack.Decoder + buf (partial frame)       │
                            │  resp dirState: hpack.Decoder + buf                        │
                            │  streams map[stream_id]*HTTP2Stream                        │
                            │                                                            │
                            │  Feed(isRequest, data):                                    │
                            │    (request dir, once) strip 24B client preface            │
                            │    buf = append(buf, data)      ← COPY (contiguity)        │
                            │    walk 9-byte frame headers (hand-parsed, uncompressed):  │
                            │      HEADERS/CONTINUATION → accumulate block →             │
                            │          hpack.DecodeFull (persistent table) →             │
                            │          pseudo-headers, content-type grpc, grpc-status    │
                            │      DATA → append to stream ReqBody/RespBody  ← COPY      │
                            │      END_STREAM flag → mark reqEnded / respEnded           │
                            │      SETTINGS/RST → ignored                                │
                            │    compact buf to the trailing partial frame              │
                            └────────────────────────────────────────────────────────┘
                                        │
                            ┌─ Flush Goroutine (startFlushRoutine, 500ms tick) ─────────┐
                            │  if conn.protocol == HTTP2:                                │
                            │    streams := tracker.TakeCompleteHTTP2()                  │
                            │      └─ returns + removes streams with BOTH END_STREAM     │
                            │    produceHTTP2Streams(connID, tracker, streams):          │
                            │      for each stream:                                      │
                            │        req, resp := stream.ToRequestResponse()             │
                            │          └─ fastparser.Request/Response;                   │
                            │             gRPC body: unwrap length-prefix + base64       │
                            │        orient by role (server=inbound, client=outbound)    │
                            │        kafkaUtil.ProduceReqResp(req, resp, ctx)            │
                            │          └─ SAME encode + Kafka produce as HTTP/1 fast path │
                            │                                                            │
                            │  case <-done (close / inactivity):                         │
                            │    final TakeCompleteHTTP2() + produce;                     │
                            │    incomplete / streaming streams are dropped             │
                            └────────────────────────────────────────────────────────┘
```

## How a 4KB unary gRPC request flows (client perspective)

We trace the **client**: role=client → request=egress (`WriteEventsCount`),
response=ingress (`ReadEventsCount`).

```
Kernel: client write(preface + SETTINGS + HEADERS)  → event wc=1  (~110B)
Kernel: client write(DATA: 9B + gRPC[5B + 4096B])   → event wc=2  (4110B, END_STREAM)
Kernel: client read(SETTINGS + HEADERS :status 200) → event rc=1  (~66B)
Kernel: client read(DATA response)                  → event rc=2
Kernel: client read(HEADERS grpc-status 0)          → event rc=3  (END_STREAM)

Go worker:
  wc=1 → h2egress.add(1,…) → Feed(req): strip preface; HEADERS → hpack →
         streams[1]{Method=POST, Path=/svc/SayHello, IsGRPC=true}
  wc=2 → Feed(req): DATA → streams[1].ReqBody += 4101B; reqEnded=true
  rc=1 → Feed(resp): HEADERS → StatusCode=200
  rc=2 → Feed(resp): DATA → RespBody += …
  rc=3 → Feed(resp): HEADERS trailer → GRPCStatus="0"; respEnded=true

Go flush (≤500ms later):
  TakeCompleteHTTP2() → [streams[1]]  (reqEnded && respEnded)
  ToRequestResponse(): Body = base64(unwrapGRPC(ReqBody))  4096→5461B
  ProduceReqResp → encode → Kafka
```

### Memory held (this connection, peak, before flush)

| What | Bytes | Note |
|---|---|---|
| `streams[1].ReqBody` | ~4101 | gRPC-framed body, accrued by append |
| `streams[1].RespBody` + headers | ~few hundred | header `[]Header` copied from hpack fields |
| `hpack.Decoder` × 2 | ~few hundred | dynamic tables, capped 4KB each |
| `h2egress`/`h2ingress` pending | ~0 | empty when chunks arrive in order |
| `buf(req)` / `buf(resp)` | ~0 | only a partial trailing frame |
| **steady-state** | **≈ 4.5 KB** | dominated by the un-flushed body |
| transient at produce | +~5.5 KB | base64 expansion, freed after produce |

Bounded by **open (incomplete) streams**, not by connection lifetime.

## Key Data Structures

```
Tracker (ebpf/connections/tracker.go)
  protocol   uint32              — kernel verdict; ProtoHTTP2 selects this path
  h2         *fastparser.HTTP2Conn   (lazily created on first HTTP2 event)
  h2egress   h2Reassembler       — orders egress chunks by WriteEventsCount
  h2ingress  h2Reassembler       — orders ingress chunks by ReadEventsCount

h2Reassembler (ebpf/connections/http2.go)
  next    int                    — next seq to release (lazily seeded to first seq)
  pending map[int][]byte         — out-of-order chunks held until the gap fills
  add(): release contiguous prefix in seq order; false if pending overflows (gap)

HTTP2Conn (trafficUtil/fastparser/http2parser.go)  — PERSISTENT per connection
  req, resp  dirState{ dec *hpack.Decoder; buf []byte; pendingHdr … }
  streams    map[uint32]*HTTP2Stream
  failed     bool                — gap / HPACK desync → abandon connection

HTTP2Stream
  StreamID, Method, Path, Authority, StatusCode, IsGRPC, GRPCStatus
  ReqHeaders/RespHeaders []Header, ReqBody/RespBody []byte
  reqEnded, respEnded    — set on END_STREAM each direction (unary = both)
  dropped                — exceeded per-stream body cap (likely streaming)
```

## Drop / Failure Points

```
1. Kernel drop (non-HTTP)         — Other-classified conns dropped before submit
   → not HTTP/2-specific; see classify_protocol / drop_non_http_flag.

2. Chunk gap (lost rc/wc)         — a missing chunk never fills; h2Reassembler
   → Metric: http2_conn_failed      pending overflows (>128) → HTTP2Conn.Fail().
   → HPACK cannot resync, so the WHOLE connection is abandoned (unlike HTTP/1,
     which gap-skips one pair and continues).

3. HPACK decode error             — DecodeFull fails (corrupt/desynced block).
   → Metric: http2_conn_failed      Connection marked failed; Feed becomes a no-op.

4. Per-stream body cap            — a stream's body exceeds 8MB (likely a long
   → stream.dropped = true          server-stream); the stream is discarded to
                                     bound memory. Not emitted.

5. Incomplete at close            — a stream without both END_STREAM at
   → dropped silently               inactivity/close (streaming, or truncated).

6. Mid-connection attach          — collector starts after the channel opened →
   → http2_conn_failed (on decode)  no HPACK history → headers undecodable.
```

## Metrics (trafficUtil/utils/pipeline_metrics.go)

| Metric | Meaning |
|---|---|
| `http2_streams_produced` | completed unary streams handed to produce |
| `http2_conn_failed` | connections abandoned (byte gap or HPACK desync) |
| `pairs_attempted` | shared with the msg_seq path; incremented per produced stream |
| `pairs_parse_success` | incremented by the shared `produceReqResp` tail |

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `AKTO_KERNEL_DROP_NON_HTTP_TRAFFIC` | true | Kernel drops non-HTTP/1/HTTP/2/TLS conns before submit |
| `AKTO_FAST_INGESTION` | true (fwd) | Required for HTTP/2: the h2 flush lives in `startFlushRoutine`, which only runs under FastIngestion |
| `MSG_SEQ_FLUSH_TICK_INTERVAL` | 500ms | Flush tick; also drives `TakeCompleteHTTP2` |
| `TRAFFIC_INACTIVITY_THRESHOLD` | 7s | Worker + flush exit; final h2 flush then |

## File Map

| File | Owns |
|---|---|
| `ebpf/kernel/module.cc` | `classify_protocol` (tags HTTP2 from the preface), stamps `protocol` on every event |
| `ebpf/connections/tracker.go` | `Tracker.protocol`/`h2`/`h2egress`/`h2ingress`; `AddDataEvent` HTTP/2 branch |
| `ebpf/connections/http2.go` | `h2Reassembler`, `addHTTP2Event`, `TakeCompleteHTTP2`, `produceHTTP2Streams`, orientation/context |
| `ebpf/connections/flushPairedRequests.go` | `startFlushRoutine` protocol branch (tick + final flush) |
| `trafficUtil/fastparser/http2parser.go` | `HTTP2Conn`/`HTTP2Stream`, `Feed`, `TakeComplete`, `ToRequestResponse`, gRPC unwrap |
| `trafficUtil/kafkaUtil/parse.go` | `ProduceReqResp` / `produceReqResp` — shared encode + produce tail |
| `trafficUtil/utils/pipeline_metrics.go` | `http2_streams_produced`, `http2_conn_failed` |

## Known Problems

### 1. Streaming not emitted (open)
Only unary (both-directions END_STREAM) completes. Server/client/bidi streaming
streams never complete-as-unary and are dropped at close. Fix (future): emit per
decoded gRPC message instead of on END_STREAM, capping per-stream memory.

### 2. Gap = whole-connection loss
HPACK's cumulative state means a single dropped chunk poisons the rest of the
connection (metric `http2_conn_failed`), unlike HTTP/1's per-pair gap-skip. This
raises the stakes on the kernel-side drop points (perf buffer overflow, channel
full) — they now lose a connection, not one request.

### 3. Mid-connection attach undecodable
A gRPC channel open before the collector starts has no HPACK history, so its
headers cannot be decoded. Shared limitation of any HTTP/2 approach; conntrack
prefill cannot help (it has no byte history).

### 4. Copies on the hot path
Unlike the HTTP/1 zero-copy fragment path, HTTP/2 copies bytes twice (into
`dirState.buf` for contiguous framing, then into the stream body). Necessary for
cross-frame reassembly; a candidate for optimization if pprof shows it hot (e.g.
parse directly from the event slice when `buf` is empty).

### 5. FastIngestion coupling
HTTP/2 only works when `AKTO_FAST_INGESTION=true`, because the h2 flush is hosted
in the FastIngestion-only flush goroutine. Not fundamental — a lazily-started h2
ticker would decouple it.
