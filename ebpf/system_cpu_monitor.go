package main

import (
	"log/slog"
	"math"
	"os"
	"time"

	trafficUtils "github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
	"github.com/cilium/ebpf"
)

var (
	systemCPUSoftAbs          = math.NaN()
	systemCPUHardAbs          = math.NaN()
	systemCPUSoftAddCores     = 2.0
	systemCPUHardAddCores     = 3.0
	systemCPUCheckIntervalSec = 1
)

func init() {
	trafficUtils.InitVar("AKTO_SYSTEM_CPU_SOFT_CORES", &systemCPUSoftAbs)
	trafficUtils.InitVar("AKTO_SYSTEM_CPU_HARD_CORES", &systemCPUHardAbs)
	trafficUtils.InitVar("AKTO_SYSTEM_CPU_SOFT_ADD_CORES", &systemCPUSoftAddCores)
	trafficUtils.InitVar("AKTO_SYSTEM_CPU_HARD_ADD_CORES", &systemCPUHardAddCores)
	trafficUtils.InitVar("AKTO_SYSTEM_CPU_CHECK_INTERVAL_SEC", &systemCPUCheckIntervalSec)
}

// startHostSystemCPULimitMonitor samples aggregate host kernel CPU (/proc/stat "system" jiffies)
// at a configurable interval. When the soft limit is exceeded, Go-side ingest is paused
// (callbacks skip events). When the hard limit is exceeded, the process exits.
func startHostSystemCPULimitMonitor(coll *ebpf.Collection) {
	softFromEnv := !math.IsNaN(systemCPUSoftAbs)
	hardFromEnv := !math.IsNaN(systemCPUHardAbs)

	if hardFromEnv && systemCPUHardAbs <= 0 {
		trafficUtils.PrintLog("Host system CPU limit monitor off (AKTO_SYSTEM_CPU_HARD_CORES <= 0)")
		return
	}
	if !hardFromEnv && systemCPUHardAddCores <= 0 {
		trafficUtils.PrintLog("Host system CPU limit monitor off (AKTO_SYSTEM_CPU_HARD_ADD_CORES <= 0 and no hard limit env)")
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
		trafficUtils.PrintLog("Sampling host system CPU baseline before probes attach", "wait", baselineWait)
		b, ok := trafficUtils.MeasureHostSystemCPUBaseline(baselineWait)
		if !ok {
			trafficUtils.PrintLog("Host system CPU baseline sample failed; using 0 baseline for computed limits")
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
	sampler := trafficUtils.NewHostSystemCPUSampler()

	go func() {
		_, _, _ = sampler.Step()

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		wasPaused := trafficUtils.PauseIngestionEnv()
		for range ticker.C {
			_, cores, ok := sampler.Step()
			if !ok {
				continue
			}

			var paused bool
			if softFromEnv {
				paused = soft > 0 && cores >= soft
			} else {
				paused = systemCPUSoftAddCores > 0 && cores >= soft
			}
			ingestPaused := trafficUtils.PauseIngestionEnv() || paused

			trafficUtils.PrintLog("host system CPU check", "systemCpuCores", cores, "softLimitCores", soft, "hardLimitCores", hard, "ingestPaused", ingestPaused)

			if cores >= hard {
				slog.Error("host system CPU hard limit exceeded, exiting", "systemCpuCores", cores, "hardLimitCores", hard)
				os.Exit(4)
			}

			if ingestPaused != wasPaused {
				if ingestPaused {
					if trafficUtils.PauseIngestionEnv() {
						slog.Warn("ingest paused", "systemCpuCores", cores, "softLimitCores", soft)
					} else {
						slog.Warn("host system CPU soft limit exceeded; pausing ingest", "systemCpuCores", cores, "softLimitCores", soft)
					}
				} else {
					slog.Warn("host system CPU below soft limit; resuming", "systemCpuCores", cores, "softLimitCores", soft)
				}
				wasPaused = ingestPaused
			}

			trafficUtils.SetSystemCPUIngestPaused(paused)
			setBPFSystemCPUIngestPaused(coll, ingestPaused)
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
	trafficUtils.PrintLog("Host system CPU limit monitor started", logArgs...)
}

func setBPFSystemCPUIngestPaused(coll *ebpf.Collection, paused bool) {
	if coll == nil {
		return
	}
	m, ok := coll.Maps["system_cpu_ingest_paused"]
	if !ok {
		return
	}
	key := uint32(0)
	value := uint8(0)
	if paused {
		value = 1
	}
	if err := m.Update(key, value, ebpf.UpdateAny); err != nil {
		slog.Warn("failed to update BPF system CPU ingest pause flag", "error", err)
	}
}
