package utils

import "sync/atomic"

var (
	systemCPUIngestPaused atomic.Bool
	pauseIngestionEnv     atomic.Bool
)

// SetPauseIngestionEnv records AKTO_PAUSE_INGESTION (read once at process start).
// When true, ingest is paused in addition to any host system CPU soft-limit pause.
func SetPauseIngestionEnv(v bool) {
	pauseIngestionEnv.Store(v)
}

func PauseIngestionEnv() bool {
	return pauseIngestionEnv.Load()
}

func SystemCPUIngestPaused() bool {
	return PauseIngestionEnv() || systemCPUIngestPaused.Load()
}

// SetSystemCPUIngestPaused sets only the host system CPU soft-limit pause flag.
func SetSystemCPUIngestPaused(v bool) {
	systemCPUIngestPaused.Store(v)
}
