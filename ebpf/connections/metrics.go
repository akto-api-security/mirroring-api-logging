package connections

import (
	"encoding/json"
	"net/http"
	"time"

	metaUtils "github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

type metricsSnapshot struct {
	ResetAt                  time.Time `json:"reset_at"`
	DurationSec              float64   `json:"duration_sec"`
	EventsReceived             int64     `json:"events_received"`
	EventsDroppedKernelRingBuf int64     `json:"events_dropped_kernel_ring_buf"`
	EventsDroppedChannelFull   int64     `json:"events_dropped_channel_full"`
	GroupsCreated            int64     `json:"groups_created"`
	GroupsOrphaned           int64     `json:"groups_orphaned"`
	GroupsStranded           int64     `json:"groups_stranded"`
	OutOfOrderArrivals       int64     `json:"out_of_order_arrivals"`
	LateArrivals             int64     `json:"late_arrivals"`
	GapSkipsFired            int64     `json:"gap_skips_fired"`
	GapSkipSeqsLost          int64     `json:"gap_skip_seqs_lost"`
	ChunkAssemblyGaps        int64     `json:"chunk_assembly_gaps"`
	PairsAttempted           int64     `json:"pairs_attempted"`
	PairsParseSuccess        int64     `json:"pairs_parse_success"`
	PairsParseFailure        int64     `json:"pairs_parse_failure"`
	PairsMismatched          int64     `json:"pairs_mismatched"`
	RequestBodyFailure       int64     `json:"request_body_failure"`
	ResponseBodyFailure      int64     `json:"response_body_failure"`
	CoveragePct              float64   `json:"coverage_pct"`
}

func snapshot() metricsSnapshot {
	m := &metaUtils.Pipeline
	groupsCreated := m.GroupsCreated.Load()
	pairsSuccess := m.PairsParseSuccess.Load()

	// Each request = 2 groups (req + resp). groupsCreated/2 = requests seen by pipeline.
	var coveragePct float64
	if groupsCreated > 0 {
		coveragePct = float64(pairsSuccess) / (float64(groupsCreated) / 2.0) * 100.0
	}

	return metricsSnapshot{
		ResetAt:                  m.ResetAt,
		DurationSec:              time.Since(m.ResetAt).Seconds(),
		EventsReceived:             m.EventsReceived.Load(),
		EventsDroppedKernelRingBuf: m.EventsDroppedKernelRingBuf.Load(),
		EventsDroppedChannelFull:   m.EventsDroppedChannelFull.Load(),
		GroupsCreated:            groupsCreated,
		GroupsOrphaned:           m.GroupsOrphaned.Load(),
		GroupsStranded:           m.GroupsStranded.Load(),
		OutOfOrderArrivals:       m.OutOfOrderArrivals.Load(),
		LateArrivals:             m.LateArrivals.Load(),
		GapSkipsFired:            m.GapSkipsFired.Load(),
		GapSkipSeqsLost:          m.GapSkipSeqsLost.Load(),
		ChunkAssemblyGaps:        m.ChunkAssemblyGaps.Load(),
		PairsAttempted:           m.PairsAttempted.Load(),
		PairsParseSuccess:        pairsSuccess,
		PairsParseFailure:        m.PairsParseFailure.Load(),
		PairsMismatched:          m.PairsMismatched.Load(),
		RequestBodyFailure:       m.RequestBodyFailure.Load(),
		ResponseBodyFailure:      m.ResponseBodyFailure.Load(),
		CoveragePct:              coveragePct,
	}
}

// RegisterMetricsHandlers registers /metrics/pipeline and /metrics/pipeline/reset
// on the default HTTP mux (same mux used by pprof).
func RegisterMetricsHandlers() {
	http.HandleFunc("/metrics/pipeline", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(snapshot())
	})

	http.HandleFunc("/metrics/pipeline/reset", func(w http.ResponseWriter, r *http.Request) {
		snap := snapshot() // capture before reset
		metaUtils.Pipeline.Reset()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(snap)
	})
}
