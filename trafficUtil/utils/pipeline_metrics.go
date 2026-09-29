package utils

import (
	"log/slog"
	"math/rand"
	"sync/atomic"
	"time"
)

// PipelineMetrics holds run-scoped atomic counters for the ingest → assemble →
// parse → produce path on this agent. All fields are safe for concurrent
// access. GET /metrics/pipeline returns Snapshot(); /metrics/pipeline/reset
// returns the current snapshot and zeroes the counters.
//
// Group-lifecycle, reorder, and HTTP/2 counters from the msg_seq pipeline are
// not tracked here. This agent assembles each connection's sent and received
// bytes and only forwards a flush that looks like HTTP/1.1.
type PipelineMetrics struct {
	// Kernel socket_data ring submissions in this window. Captured is a
	// successful ringbuf_output. SubmitFailed is the kernel refusing the
	// submit because the ring was full — that loss is not a userspace error.
	KernelCaptured     atomic.Int64
	KernelSubmitFailed atomic.Int64

	// Socket data records the userspace ring reader delivered to
	// SocketDataEventCallback, before any userspace filter.
	UserspaceReceived atomic.Int64

	// Socket data events that passed the callback filters and were handed to
	// the per-connection worker.
	EventsReceived atomic.Int64

	// Userspace drops before a worker sees the event.
	EventsDroppedIngestPaused atomic.Int64 // host CPU ingest pause
	EventsDroppedConnLimit    atomic.Int64 // active-connection cap or sample-buffer cap
	EventsDroppedIgnorePort   atomic.Int64 // kafka / zookeeper / mongo / redis ports
	EventsDroppedShortRecord  atomic.Int64 // ring record shorter than the event header or payload
	EventsDroppedChannelFull  atomic.Int64 // per-connection channel full (non-blocking send)
	EventsDroppedNoWorker     atomic.Int64 // send after the worker was already removed

	// Connection flushes (ProcessTrackerData). One flush is one connection
	// close, inactivity timeout, or byte-threshold stop.
	ConnsFlushed               atomic.Int64
	ConnsDroppedOneSided       atomic.Int64 // sent or recv side empty
	ConnsDroppedNotHTTP        atomic.Int64 // both sides present, neither starts with "HTTP"
	ConnsDroppedEgressDisabled atomic.Int64 // only the recv side starts with "HTTP", egress parsing is off
	ChunkAssemblyGaps          atomic.Int64 // sequence gap while joining chunks; the blob is truncated

	// ParseAndProduce calls and their outcomes. One forwarded flush is one
	// pairs_attempted. A single flush can produce more than one HTTP message,
	// so pairs_parse_success can exceed pairs_attempted.
	PairsAttempted            atomic.Int64
	PairsParseSuccess         atomic.Int64 // a request was marshalled and handed to produce
	PairsParseFailure         atomic.Int64 // parseHTTPTraffic returned nil
	PairsMismatched           atomic.Int64 // X-Debug-Token on the request was absent from the response body
	PairsFiltered             atomic.Int64 // shouldProcessRequest rejected the request
	PairsDroppedBandwidth     atomic.Int64 // output bandwidth limit
	PairsDroppedKafkaDisabled atomic.Int64
	PairsDroppedIncomplete    atomic.Int64 // req/resp count mismatch on a completed connection
	RequestBodyFailure        atomic.Int64 // request body read failed; pair still produced with an empty body
	ResponseBodyFailure       atomic.Int64 // response body read or gunzip failed; pair still produced with an empty body
	KafkaProduceFailure       atomic.Int64 // WriteMessages to akto.api.logs returned an error

	ResetAt time.Time
}

// Pipeline is the global singleton. Incremented by the eBPF callback, the
// connection factory, and the Kafka parser.
var Pipeline PipelineMetrics

func init() {
	Pipeline.ResetAt = time.Now()
	startPipelineMetricsLogLoop()
}

// PipelineMetricsSnapshot is the JSON form of PipelineMetrics, plus duration
// and coverage computed at read time.
type PipelineMetricsSnapshot struct {
	ResetAt                    time.Time `json:"reset_at"`
	DurationSec                float64   `json:"duration_sec"`
	KernelCaptured             int64     `json:"kernel_captured"`
	KernelSubmitFailed         int64     `json:"kernel_submit_failed"`
	UserspaceReceived          int64     `json:"userspace_received"`
	EventsReceived             int64     `json:"events_received"`
	EventsDroppedIngestPaused  int64     `json:"events_dropped_ingest_paused"`
	EventsDroppedConnLimit     int64     `json:"events_dropped_conn_limit"`
	EventsDroppedIgnorePort    int64     `json:"events_dropped_ignore_port"`
	EventsDroppedShortRecord   int64     `json:"events_dropped_short_record"`
	EventsDroppedChannelFull   int64     `json:"events_dropped_channel_full"`
	EventsDroppedNoWorker      int64     `json:"events_dropped_no_worker"`
	ConnsFlushed               int64     `json:"conns_flushed"`
	ConnsDroppedOneSided       int64     `json:"conns_dropped_one_sided"`
	ConnsDroppedNotHTTP        int64     `json:"conns_dropped_not_http"`
	ConnsDroppedEgressDisabled int64     `json:"conns_dropped_egress_disabled"`
	ChunkAssemblyGaps          int64     `json:"chunk_assembly_gaps"`
	PairsAttempted             int64     `json:"pairs_attempted"`
	PairsParseSuccess          int64     `json:"pairs_parse_success"`
	PairsParseFailure          int64     `json:"pairs_parse_failure"`
	PairsMismatched            int64     `json:"pairs_mismatched"`
	PairsFiltered              int64     `json:"pairs_filtered"`
	PairsDroppedBandwidth      int64     `json:"pairs_dropped_bandwidth"`
	PairsDroppedKafkaDisabled  int64     `json:"pairs_dropped_kafka_disabled"`
	PairsDroppedIncomplete     int64     `json:"pairs_dropped_incomplete"`
	RequestBodyFailure         int64     `json:"request_body_failure"`
	ResponseBodyFailure        int64     `json:"response_body_failure"`
	KafkaProduceFailure        int64     `json:"kafka_produce_failure"`
	CoveragePct                float64   `json:"coverage_pct"`
}

// Snapshot reads every counter. coverage_pct is pairs_parse_success / pairs_attempted.
func (m *PipelineMetrics) Snapshot() PipelineMetricsSnapshot {
	attempted := m.PairsAttempted.Load()
	success := m.PairsParseSuccess.Load()
	var coveragePct float64
	if attempted > 0 {
		coveragePct = float64(success) / float64(attempted) * 100.0
	}
	return PipelineMetricsSnapshot{
		ResetAt:                    m.ResetAt,
		DurationSec:                time.Since(m.ResetAt).Seconds(),
		KernelCaptured:             m.KernelCaptured.Load(),
		KernelSubmitFailed:         m.KernelSubmitFailed.Load(),
		UserspaceReceived:          m.UserspaceReceived.Load(),
		EventsReceived:             m.EventsReceived.Load(),
		EventsDroppedIngestPaused:  m.EventsDroppedIngestPaused.Load(),
		EventsDroppedConnLimit:     m.EventsDroppedConnLimit.Load(),
		EventsDroppedIgnorePort:    m.EventsDroppedIgnorePort.Load(),
		EventsDroppedShortRecord:   m.EventsDroppedShortRecord.Load(),
		EventsDroppedChannelFull:   m.EventsDroppedChannelFull.Load(),
		EventsDroppedNoWorker:      m.EventsDroppedNoWorker.Load(),
		ConnsFlushed:               m.ConnsFlushed.Load(),
		ConnsDroppedOneSided:       m.ConnsDroppedOneSided.Load(),
		ConnsDroppedNotHTTP:        m.ConnsDroppedNotHTTP.Load(),
		ConnsDroppedEgressDisabled: m.ConnsDroppedEgressDisabled.Load(),
		ChunkAssemblyGaps:          m.ChunkAssemblyGaps.Load(),
		PairsAttempted:             attempted,
		PairsParseSuccess:          success,
		PairsParseFailure:          m.PairsParseFailure.Load(),
		PairsMismatched:            m.PairsMismatched.Load(),
		PairsFiltered:              m.PairsFiltered.Load(),
		PairsDroppedBandwidth:      m.PairsDroppedBandwidth.Load(),
		PairsDroppedKafkaDisabled:  m.PairsDroppedKafkaDisabled.Load(),
		PairsDroppedIncomplete:     m.PairsDroppedIncomplete.Load(),
		RequestBodyFailure:         m.RequestBodyFailure.Load(),
		ResponseBodyFailure:        m.ResponseBodyFailure.Load(),
		KafkaProduceFailure:        m.KafkaProduceFailure.Load(),
		CoveragePct:                coveragePct,
	}
}

// SnapshotAndReset returns the current window and zeroes every counter.
// Swap keeps an increment that lands during the read in either this window
// or the next one.
func (m *PipelineMetrics) SnapshotAndReset() PipelineMetricsSnapshot {
	attempted := m.PairsAttempted.Swap(0)
	success := m.PairsParseSuccess.Swap(0)
	var coveragePct float64
	if attempted > 0 {
		coveragePct = float64(success) / float64(attempted) * 100.0
	}
	snap := PipelineMetricsSnapshot{
		ResetAt:                    m.ResetAt,
		DurationSec:                time.Since(m.ResetAt).Seconds(),
		KernelCaptured:             m.KernelCaptured.Swap(0),
		KernelSubmitFailed:         m.KernelSubmitFailed.Swap(0),
		UserspaceReceived:          m.UserspaceReceived.Swap(0),
		EventsReceived:             m.EventsReceived.Swap(0),
		EventsDroppedIngestPaused:  m.EventsDroppedIngestPaused.Swap(0),
		EventsDroppedConnLimit:     m.EventsDroppedConnLimit.Swap(0),
		EventsDroppedIgnorePort:    m.EventsDroppedIgnorePort.Swap(0),
		EventsDroppedShortRecord:   m.EventsDroppedShortRecord.Swap(0),
		EventsDroppedChannelFull:   m.EventsDroppedChannelFull.Swap(0),
		EventsDroppedNoWorker:      m.EventsDroppedNoWorker.Swap(0),
		ConnsFlushed:               m.ConnsFlushed.Swap(0),
		ConnsDroppedOneSided:       m.ConnsDroppedOneSided.Swap(0),
		ConnsDroppedNotHTTP:        m.ConnsDroppedNotHTTP.Swap(0),
		ConnsDroppedEgressDisabled: m.ConnsDroppedEgressDisabled.Swap(0),
		ChunkAssemblyGaps:          m.ChunkAssemblyGaps.Swap(0),
		PairsAttempted:             attempted,
		PairsParseSuccess:          success,
		PairsParseFailure:          m.PairsParseFailure.Swap(0),
		PairsMismatched:            m.PairsMismatched.Swap(0),
		PairsFiltered:              m.PairsFiltered.Swap(0),
		PairsDroppedBandwidth:      m.PairsDroppedBandwidth.Swap(0),
		PairsDroppedKafkaDisabled:  m.PairsDroppedKafkaDisabled.Swap(0),
		PairsDroppedIncomplete:     m.PairsDroppedIncomplete.Swap(0),
		RequestBodyFailure:         m.RequestBodyFailure.Swap(0),
		ResponseBodyFailure:        m.ResponseBodyFailure.Swap(0),
		KafkaProduceFailure:        m.KafkaProduceFailure.Swap(0),
		CoveragePct:                coveragePct,
	}
	m.ResetAt = time.Now()
	return snap
}

// Reset zeroes all counters and records the reset time.
func (m *PipelineMetrics) Reset() {
	m.SnapshotAndReset()
}

const pipelineMetricsInterval = 60 * time.Second

func startPipelineMetricsLogLoop() {
	go func() {
		for {
			jitter := time.Duration(1+rand.Intn(5)) * time.Second
			time.Sleep(pipelineMetricsInterval + jitter)
			snap := Pipeline.SnapshotAndReset()
			slog.Warn("pipeline metrics",
				"window_sec", snap.DurationSec,
				"jitter_sec", jitter.Seconds(),
				"kernel_captured", snap.KernelCaptured,
				"kernel_submit_failed", snap.KernelSubmitFailed,
				"userspace_received", snap.UserspaceReceived,
				"userspace_queued", snap.EventsReceived,
				"userspace_dropped_ingest_paused", snap.EventsDroppedIngestPaused,
				"userspace_dropped_conn_limit", snap.EventsDroppedConnLimit,
				"userspace_dropped_ignore_port", snap.EventsDroppedIgnorePort,
				"userspace_dropped_short_record", snap.EventsDroppedShortRecord,
				"userspace_dropped_channel_full", snap.EventsDroppedChannelFull,
				"userspace_dropped_no_worker", snap.EventsDroppedNoWorker,
				"userspace_conns_flushed", snap.ConnsFlushed,
				"userspace_conns_dropped_one_sided", snap.ConnsDroppedOneSided,
				"userspace_conns_dropped_not_http", snap.ConnsDroppedNotHTTP,
				"userspace_conns_dropped_egress_disabled", snap.ConnsDroppedEgressDisabled,
				"userspace_chunk_assembly_gaps", snap.ChunkAssemblyGaps,
				"userspace_pairs_attempted", snap.PairsAttempted,
				"userspace_parsed_ok", snap.PairsParseSuccess,
				"userspace_parse_failed", snap.PairsParseFailure,
				"userspace_pairs_mismatched", snap.PairsMismatched,
				"userspace_pairs_filtered", snap.PairsFiltered,
				"userspace_dropped_bandwidth", snap.PairsDroppedBandwidth,
				"userspace_dropped_kafka_disabled", snap.PairsDroppedKafkaDisabled,
				"userspace_dropped_incomplete", snap.PairsDroppedIncomplete,
				"userspace_request_body_failure", snap.RequestBodyFailure,
				"userspace_response_body_failure", snap.ResponseBodyFailure,
				"userspace_kafka_produce_failure", snap.KafkaProduceFailure,
				"coverage_pct", snap.CoveragePct,
			)
		}
	}()
}
