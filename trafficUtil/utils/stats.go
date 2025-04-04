package utils

import (
	"log/slog"
	"os"
	"runtime"
)

var aktoMemThreshRestart = 500

func init() {
	InitVar("AKTO_MEM_THRESH_RESTART", &aktoMemThreshRestart)
	InitVar("AKTO_MEM_HARD_LIMIT", &aktoMemThreshRestart)
}

func LogMemoryStats() int {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	mem := int(m.Alloc / 1024 / 1024)
	if mem > aktoMemThreshRestart {
		slog.Debug("current mem usage", "mem", mem)
		os.Exit(3)
	}

	slog.Debug("Alloc in MB: ", "mem", mem)
	slog.Debug("Sys in MB: ", "mem", m.Sys/1024/1024)

	// gc stats

	// slog.Debug("Last gc finished: ", "lastGC", m.LastGC)
	// slog.Debug("Target heap size of next gc cycle: ", "nextGC", m.NextGC)
	// slog.Debug("Stop The world pauses ", "pauseTotalNs", m.PauseTotalNs)
	// slog.Debug("GcSys ", "gcSys", m.GCSys)
	// slog.Debug("GCCPUFraction ", "gcCPUFraction", m.GCCPUFraction)
	// slog.Debug("NumGC ", "numGC", m.NumGC)
	// slog.Debug("NumForcedGC ", "numForcedGC", m.NumForcedGC)

	return mem
}
