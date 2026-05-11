package utils

import "sync/atomic"

var systemCPUIngestPaused atomic.Bool

func SystemCPUIngestPaused() bool {
	return systemCPUIngestPaused.Load()
}

func SetSystemCPUIngestPaused(v bool) {
	systemCPUIngestPaused.Store(v)
}
