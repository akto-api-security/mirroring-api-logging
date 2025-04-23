package utils

import (
	"log/slog"
	"os"
	"runtime"
)

var aktoMemThreshRestart = 500
var aktoSysMemThreshRestart = 950

func init() {
	InitVar("AKTO_MEM_THRESH_RESTART", &aktoMemThreshRestart)
	InitVar("AKTO_MEM_HARD_LIMIT", &aktoMemThreshRestart)
	InitVar("AKTO_SYS_MEM_HARD_LIMIT", &aktoSysMemThreshRestart)
}

func LogMemoryStats() int {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	/*
		Since the same check is on system memory,
		the check on Alloc is redundant.
		Can be removed, in future.
		Or can be used with a different threshold/flag.
	*/
	mem := int(m.Alloc / 1024 / 1024)
	if mem > aktoMemThreshRestart {
		slog.Error("Refreshing, current alloc mem usage", "mem", mem, "threshold", aktoMemThreshRestart)
		os.Exit(3)
	}

	sysMem := int(m.Sys / 1024 / 1024)
	if sysMem > aktoSysMemThreshRestart {
		slog.Error("Refreshing, current sys mem usage", "mem", sysMem, "threshold", aktoSysMemThreshRestart)
		os.Exit(3)
	}

	slog.Debug("Alloc in MB: ", "mem", mem)
	slog.Debug("Sys in MB: ", "mem", sysMem)

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
