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

// PipelineMetrics holds run-scoped atomic counters for the msg_seq pipeline.
// All fields are safe for concurrent access.
// Both connections and kafkaUtil packages increment these directly.
type PipelineMetrics struct {
	// Input
	EventsReceived           atomic.Int64 // SocketDataEventCallback: successfully decoded events
	InputChanLen             atomic.Int64 // sampled len(inputChan) every 1000 events
	InputChanCap             atomic.Int64 // cap(inputChan) — set once at startup

	// Drop points
	EventsDroppedKernelRingBuf atomic.Int64 // gobpf lostEventsChannel: kernel perf ring buffer overflow
	EventsDroppedChannelFull   atomic.Int64 // SendEvent: per-conn channel full

	// Group lifecycle (one group = one HTTP message direction)
	GroupsCreated      atomic.Int64 // new msg_seq group first seen in AddDataEvent
	GroupsOrphaned     atomic.Int64 // partner missing at flush time (drainPairs)
	GroupsStranded     atomic.Int64 // late arrivals below lowestPendingSeq, discarded at final flush
	OutOfOrderArrivals atomic.Int64 // msg_seq < highestMsgSeq at group creation
	LateArrivals       atomic.Int64 // msg_seq < lowestPendingSeq (already flushed)

	// Reorder distance (highestMsgSeq - msgSeq) at out-of-position arrival.
	// Sizes the flush hold threshold.
	OutOfOrderDist  ReorderHist // above lps (currently recovered)
	LateArrivalDist ReorderHist // below lps (currently lost) — key sizing input

	// Gap-skip (drainPairs advancing lowestPendingSeq past a missing seq)
	GapSkipsFired   atomic.Int64 // how many times a missing seq triggered a skip
	GapSkipSeqsLost atomic.Int64 // total individual seqs skipped across all gap-skips

	// Chunk assembly
	ChunkAssemblyGaps atomic.Int64 // convertToSingleByteArr broke early due to missing chunk key (silent truncation)

	// Pair outcomes
	PairsAttempted      atomic.Int64 // pairs passed to ProcessSinglePair
	PairsParseSuccess   atomic.Int64 // ParseAndProduce produced at least one req-resp pair
	PairsParseFailure   atomic.Int64 // parseHTTPTraffic returned nil (corrupt/truncated req or resp)
	PairsMismatched     atomic.Int64 // X-Debug-Token in request not found in response body (echo mismatch)
	RequestBodyFailure  atomic.Int64 // req body io.ReadAll failed (pair still produced, empty body)
	ResponseBodyFailure atomic.Int64 // resp body io.ReadAll failed (pair still produced, empty body)

	// Reset tracking
	ResetAt time.Time
}

// Pipeline is the global singleton. Imported by connections and kafkaUtil.
var Pipeline PipelineMetrics

func init() {
	Pipeline.ResetAt = time.Now()
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
	m.ResetAt = time.Now()
}
