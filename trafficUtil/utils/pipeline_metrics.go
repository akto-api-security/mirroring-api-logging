package utils

import (
	"sync/atomic"
	"time"
)

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
