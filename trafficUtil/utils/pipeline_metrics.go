package utils

import (
	"sync/atomic"
	"time"
)

// ReorderHist buckets a seq reorder distance (highestMsgSeq - msgSeq) observed
// at the moment an out-of-position seq arrives. Used to size the flush hold
// threshold: pick threshold at the p99 of the recoverable cluster.
// Buckets: 1, 2-4, 5-8, 9-16, 17-32, 33-64, >64.
type ReorderHist struct {
	B1     atomic.Int64
	B2_4   atomic.Int64
	B5_8   atomic.Int64
	B9_16  atomic.Int64
	B17_32 atomic.Int64
	B33_64 atomic.Int64
	B65    atomic.Int64
}

func (h *ReorderHist) Observe(dist uint32) {
	switch {
	case dist <= 1:
		h.B1.Add(1)
	case dist <= 4:
		h.B2_4.Add(1)
	case dist <= 8:
		h.B5_8.Add(1)
	case dist <= 16:
		h.B9_16.Add(1)
	case dist <= 32:
		h.B17_32.Add(1)
	case dist <= 64:
		h.B33_64.Add(1)
	default:
		h.B65.Add(1)
	}
}

func (h *ReorderHist) Reset() {
	h.B1.Store(0)
	h.B2_4.Store(0)
	h.B5_8.Store(0)
	h.B9_16.Store(0)
	h.B17_32.Store(0)
	h.B33_64.Store(0)
	h.B65.Store(0)
}

// ReorderHistSnapshot is the plain (non-atomic) form for JSON emission.
type ReorderHistSnapshot struct {
	B1     int64 `json:"d1"`
	B2_4   int64 `json:"d2_4"`
	B5_8   int64 `json:"d5_8"`
	B9_16  int64 `json:"d9_16"`
	B17_32 int64 `json:"d17_32"`
	B33_64 int64 `json:"d33_64"`
	B65    int64 `json:"d65_plus"`
}

func (h *ReorderHist) Snapshot() ReorderHistSnapshot {
	return ReorderHistSnapshot{
		B1:     h.B1.Load(),
		B2_4:   h.B2_4.Load(),
		B5_8:   h.B5_8.Load(),
		B9_16:  h.B9_16.Load(),
		B17_32: h.B17_32.Load(),
		B33_64: h.B33_64.Load(),
		B65:    h.B65.Load(),
	}
}

// PipelineMetrics holds run-scoped atomic counters for the ingest/flush/parse
// pipeline. All fields are safe for concurrent access. Populated by both
// ingestion modes (AKTO_FAST_INGESTION true/false) to varying degrees — see
// per-field comments; group-lifecycle/gap-skip/reorder/PairsAttempted are
// msg_seq-path only (AKTO_FAST_INGESTION=true, ebpf/connections) and read zero
// on the flat-buffer path. Incremented directly by connections and kafkaUtil.
type PipelineMetrics struct {
	// Input
	EventsReceived atomic.Int64 // SocketDataEventCallback: data events past the port-ignore filter, dispatched to SendDataEvent (zero-copy view cast, not decoded)
	InputChanLen   atomic.Int64 // sampled len(inputChan) every 1000 events
	InputChanCap   atomic.Int64 // cap(inputChan) — set once at startup

	// Drop points
	EventsDroppedKernelRingBuf atomic.Int64 // gobpf lostEventsChannel: kernel perf ring buffer overflow
	EventsDroppedChannelFull   atomic.Int64 // SendEvent (open/close) or SendDataEvent (data): per-conn channel full

	// Group lifecycle (one group = one HTTP message direction). msg_seq path only.
	GroupsCreated      atomic.Int64 // new msg_seq group first seen in AddDataEvent
	GroupsOrphaned     atomic.Int64 // partner missing at flush time (drainPairs)
	GroupsStranded     atomic.Int64 // late arrivals below lowestPendingSeq, discarded at final flush
	OutOfOrderArrivals atomic.Int64 // msg_seq < highestMsgSeq at group creation
	LateArrivals       atomic.Int64 // msg_seq < lowestPendingSeq (already flushed)

	// Reorder distance (highestMsgSeq - msgSeq) at out-of-position arrival.
	// Sizes the flush hold threshold. msg_seq path only.
	OutOfOrderDist  ReorderHist // above lps (currently recovered)
	LateArrivalDist ReorderHist // below lps (currently lost) — key sizing input

	// Gap-skip (drainPairs advancing lowestPendingSeq past a missing seq). msg_seq path only.
	GapSkipsFired   atomic.Int64 // how many times a missing seq triggered a skip
	GapSkipSeqsLost atomic.Int64 // total individual seqs skipped across all gap-skips

	// Chunk/fragment assembly
	ChunkAssemblyGaps atomic.Int64 // fragmentsToBytes (msg_seq path) or convertToSingleByteArr (flat-buffer path) broke early due to a missing seq/chunk key (silent truncation)

	// Pair outcomes. PairsAttempted is msg_seq-path only (ProcessSinglePair,
	// flushPairedRequests.go) — the flat-buffer path's ProcessTrackerData has no
	// equivalent counter. The rest are populated by kafkaUtil regardless of
	// which ingestion mode produced the pair.
	PairsAttempted      atomic.Int64 // pairs passed to ProcessSinglePair
	PairsParseSuccess   atomic.Int64 // fastParseAndProduce or parseHTTPTraffic/ParseAndProduce produced at least one req-resp pair
	PairsParseFailure   atomic.Int64 // parseHTTPTraffic returned nil, or fast-path ParseRequest/ParseResponse errored (corrupt/truncated req or resp)
	PairsMismatched     atomic.Int64 // X-Debug-Token in request not found in response body (echo mismatch)
	RequestBodyFailure  atomic.Int64 // req body io.ReadAll failed — std-lib slow path only (parseHTTPTraffic), and only for requests matching the body-parsing policy; pair still produced, empty body
	ResponseBodyFailure atomic.Int64 // resp body io.ReadAll failed — same conditions as RequestBodyFailure

	// HTTP/2 path (protocol==HTTP2). Distinct from the msg_seq pair counters above.
	HTTP2StreamsProduced atomic.Int64 // completed unary h2/gRPC streams handed to produce
	HTTP2ConnFailed      atomic.Int64 // h2 connections abandoned (byte gap or HPACK desync)
	// Events arriving on a connection already abandoned by HTTP2ConnFailed. These
	// are discarded with no other trace, and are the real blast radius of a single
	// lost chunk: HPACK's dynamic table is cumulative, so one gap kills every later
	// stream on that connection. Without this counter that loss is invisible.
	HTTP2EventsAfterFail atomic.Int64

	// Reset tracking
	ResetAt time.Time
}

// Pipeline is the global singleton. Imported by connections and kafkaUtil.
var Pipeline PipelineMetrics

func init() {
	Pipeline.ResetAt = time.Now()
}

// PipelineMetricsSnapshot is the plain (non-atomic) JSON-marshalable form of
// PipelineMetrics, plus a couple of values derived from it at snapshot time.
type PipelineMetricsSnapshot struct {
	ResetAt                    time.Time           `json:"reset_at"`
	DurationSec                float64             `json:"duration_sec"`
	EventsReceived             int64               `json:"events_received"`
	InputChanLen               int64               `json:"input_chan_len"`
	InputChanCap               int64               `json:"input_chan_cap"`
	EventsDroppedKernelRingBuf int64               `json:"events_dropped_kernel_ring_buf"`
	EventsDroppedChannelFull   int64               `json:"events_dropped_channel_full"`
	GroupsCreated              int64               `json:"groups_created"`
	GroupsOrphaned             int64               `json:"groups_orphaned"`
	GroupsStranded             int64               `json:"groups_stranded"`
	OutOfOrderArrivals         int64               `json:"out_of_order_arrivals"`
	LateArrivals               int64               `json:"late_arrivals"`
	OutOfOrderDist             ReorderHistSnapshot `json:"out_of_order_dist"`
	LateArrivalDist            ReorderHistSnapshot `json:"late_arrival_dist"`
	GapSkipsFired              int64               `json:"gap_skips_fired"`
	GapSkipSeqsLost            int64               `json:"gap_skip_seqs_lost"`
	ChunkAssemblyGaps          int64               `json:"chunk_assembly_gaps"`
	PairsAttempted             int64               `json:"pairs_attempted"`
	PairsParseSuccess          int64               `json:"pairs_parse_success"`
	PairsParseFailure          int64               `json:"pairs_parse_failure"`
	PairsMismatched            int64               `json:"pairs_mismatched"`
	RequestBodyFailure         int64               `json:"request_body_failure"`
	ResponseBodyFailure        int64               `json:"response_body_failure"`
	HTTP2StreamsProduced       int64               `json:"http2_streams_produced"`
	HTTP2ConnFailed            int64               `json:"http2_conn_failed"`
	HTTP2EventsAfterFail       int64               `json:"http2_events_after_fail"`
	CoveragePct                float64             `json:"coverage_pct"`
}

// Snapshot takes a consistent-enough point-in-time read of all counters plus
// two derived values: DurationSec (time since last Reset) and CoveragePct
// (parsed pairs / requests seen — each request is 2 groups, req+resp).
func (m *PipelineMetrics) Snapshot() PipelineMetricsSnapshot {
	groupsCreated := m.GroupsCreated.Load()
	pairsSuccess := m.PairsParseSuccess.Load()

	var coveragePct float64
	if groupsCreated > 0 {
		coveragePct = float64(pairsSuccess) / (float64(groupsCreated) / 2.0) * 100.0
	}

	return PipelineMetricsSnapshot{
		ResetAt:                    m.ResetAt,
		DurationSec:                time.Since(m.ResetAt).Seconds(),
		EventsReceived:             m.EventsReceived.Load(),
		InputChanLen:               m.InputChanLen.Load(),
		InputChanCap:               m.InputChanCap.Load(),
		EventsDroppedKernelRingBuf: m.EventsDroppedKernelRingBuf.Load(),
		EventsDroppedChannelFull:   m.EventsDroppedChannelFull.Load(),
		GroupsCreated:              groupsCreated,
		GroupsOrphaned:             m.GroupsOrphaned.Load(),
		GroupsStranded:             m.GroupsStranded.Load(),
		OutOfOrderArrivals:         m.OutOfOrderArrivals.Load(),
		LateArrivals:               m.LateArrivals.Load(),
		OutOfOrderDist:             m.OutOfOrderDist.Snapshot(),
		LateArrivalDist:            m.LateArrivalDist.Snapshot(),
		GapSkipsFired:              m.GapSkipsFired.Load(),
		GapSkipSeqsLost:            m.GapSkipSeqsLost.Load(),
		ChunkAssemblyGaps:          m.ChunkAssemblyGaps.Load(),
		PairsAttempted:             m.PairsAttempted.Load(),
		PairsParseSuccess:          pairsSuccess,
		PairsParseFailure:          m.PairsParseFailure.Load(),
		PairsMismatched:            m.PairsMismatched.Load(),
		RequestBodyFailure:         m.RequestBodyFailure.Load(),
		ResponseBodyFailure:        m.ResponseBodyFailure.Load(),
		HTTP2StreamsProduced:       m.HTTP2StreamsProduced.Load(),
		HTTP2ConnFailed:            m.HTTP2ConnFailed.Load(),
		HTTP2EventsAfterFail:       m.HTTP2EventsAfterFail.Load(),
		CoveragePct:                coveragePct,
	}
}

// Reset zeroes all counters and records the reset time.
func (m *PipelineMetrics) Reset() {
	m.EventsReceived.Store(0)
	m.InputChanLen.Store(0)
	m.EventsDroppedKernelRingBuf.Store(0)
	m.EventsDroppedChannelFull.Store(0)
	m.GroupsCreated.Store(0)
	m.GroupsOrphaned.Store(0)
	m.GroupsStranded.Store(0)
	m.OutOfOrderArrivals.Store(0)
	m.LateArrivals.Store(0)
	m.OutOfOrderDist.Reset()
	m.LateArrivalDist.Reset()
	m.GapSkipsFired.Store(0)
	m.GapSkipSeqsLost.Store(0)
	m.ChunkAssemblyGaps.Store(0)
	m.PairsAttempted.Store(0)
	m.PairsParseSuccess.Store(0)
	m.PairsParseFailure.Store(0)
	m.PairsMismatched.Store(0)
	m.RequestBodyFailure.Store(0)
	m.ResponseBodyFailure.Store(0)
	m.HTTP2StreamsProduced.Store(0)
	m.HTTP2ConnFailed.Store(0)
	m.HTTP2EventsAfterFail.Store(0)
	m.ResetAt = time.Now()
}
