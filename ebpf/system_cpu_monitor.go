package main

import (
	"encoding/binary"
	"log/slog"
	"math"
	"os"
	"time"

	"github.com/iovisor/gobpf/bcc"

	trafficUtils "github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

// Default margins when AKTO_SYSTEM_CPU_SOFT_CORES / AKTO_SYSTEM_CPU_HARD_CORES are unset
// (limits = baseline + add, after MeasureHostSystemCPUBaseline before probes attach).
// NaN means that limit was not set via env (see InitVar in init).
var (
	systemCPUSoftAbs          = math.NaN()
	systemCPUHardAbs          = math.NaN()
	systemCPUSoftAddCores     = 1.5
	systemCPUHardAddCores     = 2.0
	systemCPUCheckIntervalSec = 1
)

func init() {
	trafficUtils.InitVar("AKTO_SYSTEM_CPU_SOFT_CORES", &systemCPUSoftAbs)
	trafficUtils.InitVar("AKTO_SYSTEM_CPU_HARD_CORES", &systemCPUHardAbs)
	trafficUtils.InitVar("AKTO_SYSTEM_CPU_SOFT_ADD_CORES", &systemCPUSoftAddCores)
	trafficUtils.InitVar("AKTO_SYSTEM_CPU_HARD_ADD_CORES", &systemCPUHardAddCores)
	trafficUtils.InitVar("AKTO_SYSTEM_CPU_CHECK_INTERVAL_SEC", &systemCPUCheckIntervalSec)
}

func setPerfSubmitPause(table *bcc.Table, key, val []byte, paused bool) error {
	u := uint64(0)
	if paused {
		u = 1
	}
	binary.LittleEndian.PutUint64(val, u)
	return table.Set(key, val)
}

// startHostSystemCPULimitMonitor samples aggregate host kernel CPU (/proc/stat "system" jiffies)
// every checkInterval. Before kprobes attach, baseline may be sampled for default limits.
//
// If AKTO_SYSTEM_CPU_SOFT_CORES / AKTO_SYSTEM_CPU_HARD_CORES are set (InitVar), those are absolute
// core-equivalent thresholds. If unset (NaN sentinel), the limit is baseline + *_ADD_CORES.
func startHostSystemCPULimitMonitor(module *bcc.Module) {
	softFromEnv := !math.IsNaN(systemCPUSoftAbs)
	hardFromEnv := !math.IsNaN(systemCPUHardAbs)

	if hardFromEnv && systemCPUHardAbs <= 0 {
		slog.Warn("Host system CPU limit monitor off (AKTO_SYSTEM_CPU_HARD_CORES <= 0)")
		return
	}
	if !hardFromEnv && systemCPUHardAddCores <= 0 {
		slog.Warn("Host system CPU limit monitor off (AKTO_SYSTEM_CPU_HARD_ADD_CORES <= 0 and no hard limit env)")
		return
	}

	sec := systemCPUCheckIntervalSec
	if sec <= 0 {
		sec = 1
	}
	baselineWait := time.Duration(sec) * time.Second

	needBaseline := !softFromEnv || !hardFromEnv
	var baseline float64
	if needBaseline {
		slog.Warn("Sampling host system CPU baseline before probes attach", "wait", baselineWait)
		b, ok := trafficUtils.MeasureHostSystemCPUBaseline(baselineWait)
		if !ok {
			slog.Warn("Host system CPU baseline sample failed; using 0 baseline for computed limits")
			baseline = 0
		} else {
			baseline = b
		}
	}

	var soft, hard float64
	if softFromEnv {
		soft = systemCPUSoftAbs
	} else {
		soft = baseline + systemCPUSoftAddCores
	}
	if hardFromEnv {
		hard = systemCPUHardAbs
	} else {
		hard = baseline + systemCPUHardAddCores
	}
	if hard <= soft {
		hard = soft + 1e-9
	}

	interval := baselineWait
	table := bcc.NewTable(module.TableId("perf_submit_pause"), module)
	key := []byte{0, 0, 0, 0}
	val := make([]byte, 8)
	sampler := trafficUtils.NewHostSystemCPUSampler()

	go func() {
		_, _, _ = sampler.Step() // Prime /proc/stat baseline so the first tick yields a measurement.

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		var wasPaused bool
		for range ticker.C {
			_, cores, ok := sampler.Step()
			if !ok {
				continue
			}

			if cores >= hard {
				slog.Error("host system CPU hard limit exceeded, exiting", "systemCpuCores", cores, "hardLimitCores", hard)
				os.Exit(4)
			}

			var paused bool
			if softFromEnv {
				paused = soft > 0 && cores >= soft
			} else {
				paused = systemCPUSoftAddCores > 0 && cores >= soft
			}
			if paused != wasPaused {
				if paused {
					slog.Warn("host system CPU soft limit exceeded; pausing ingest and BPF perf_submit", "systemCpuCores", cores, "softLimitCores", soft)
				} else {
					slog.Warn("host system CPU below soft limit; resuming", "systemCpuCores", cores, "softLimitCores", soft)
				}
				wasPaused = paused
			}

			trafficUtils.SetSystemCPUIngestPaused(paused)
			if err := setPerfSubmitPause(table, key, val, paused); err != nil {
				slog.Error("failed to update perf_submit_pause BPF map", "error", err)
			}
		}
	}()

	logArgs := []any{
		"softLimitCores", soft,
		"hardLimitCores", hard,
		"interval", interval,
		"softFromEnv", softFromEnv,
		"hardFromEnv", hardFromEnv,
	}
	if needBaseline {
		logArgs = append(logArgs, "baselineCores", baseline, "softAddCores", systemCPUSoftAddCores, "hardAddCores", systemCPUHardAddCores)
	}
	slog.Warn("Host system CPU limit monitor started", logArgs...)
}
