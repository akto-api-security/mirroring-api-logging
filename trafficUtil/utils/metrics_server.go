package utils

import (
	"encoding/json"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"runtime"
)

// RegisterMetricsHandlers registers /metrics/pipeline and /metrics/pipeline/reset
// on the default HTTP mux (same mux used by pprof).
func RegisterMetricsHandlers() {
	http.HandleFunc("/metrics/pipeline", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Pipeline.Snapshot())
	})

	http.HandleFunc("/metrics/pipeline/reset", func(w http.ResponseWriter, r *http.Request) {
		snap := Pipeline.Snapshot() // capture before reset
		Pipeline.Reset()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(snap)
	})
}

// StartObservabilityServer wires up the pipeline metrics + pprof endpoints and
// starts serving them on :6060. Access pprof via:
// go tool pprof http://<pod-ip>:6060/debug/pprof/mutex
func StartObservabilityServer(enablePprof bool) {
	RegisterMetricsHandlers()
	if enablePprof {
		runtime.SetMutexProfileFraction(1)
		runtime.SetBlockProfileRate(1)
	}
	go func() {
		slog.Info("HTTP server starting on :6060 (metrics + pprof if enabled)")
		if err := http.ListenAndServe(":6060", nil); err != nil {
			slog.Error("HTTP server failed", "error", err)
		}
	}()
}
