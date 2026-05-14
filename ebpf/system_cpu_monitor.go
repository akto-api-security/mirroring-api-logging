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
	systemCPUSoftAbs                        = math.NaN()
	systemCPUHardAbs                        = math.NaN()
	systemCPUSoftAddCores                   = 2.0
	systemCPUHardAddCores                   = 3.0
	systemCPUCheckIntervalSec               = 1
	systemCPUBaselineWindowSec              = 15
	systemCPUBaselineStepSec                = 1
	systemCPUSoftOscillationExitTransitions = 1800 // if 1800 transitions, i.e. 1 per second
)

func init() {
	trafficUtils.InitVar("AKTO_SYSTEM_CPU_SOFT_CORES", &systemCPUSoftAbs)
	trafficUtils.InitVar("AKTO_SYSTEM_CPU_HARD_CORES", &systemCPUHardAbs)
	trafficUtils.InitVar("AKTO_SYSTEM_CPU_SOFT_ADD_CORES", &systemCPUSoftAddCores)
	trafficUtils.InitVar("AKTO_SYSTEM_CPU_HARD_ADD_CORES", &systemCPUHardAddCores)
	trafficUtils.InitVar("AKTO_SYSTEM_CPU_CHECK_INTERVAL_SEC", &systemCPUCheckIntervalSec)
	trafficUtils.InitVar("AKTO_SYSTEM_CPU_BASELINE_SAMPLE_SEC", &systemCPUBaselineWindowSec)
	trafficUtils.InitVar("AKTO_SYSTEM_CPU_BASELINE_STEP_SEC", &systemCPUBaselineStepSec)
	trafficUtils.InitVar("AKTO_SYSTEM_CPU_SOFT_OSCILLATION_EXIT_TRANSITIONS", &systemCPUSoftOscillationExitTransitions)
}

// hostSystemCPULimitConfig holds limits computed before any BPF collection is loaded, so baseline
// reflects host /proc/stat without this module's programs or goroutines from run() (package inits may still run).
type hostSystemCPULimitConfig struct {
	disabled bool

	interval                           time.Duration
	soft, hard                         float64
	baseline                           float64
	needBaseline                       bool
	softFromEnv, hardFromEnv           bool
	baselineWindowSec, baselineStepSec int
}

// determineHostSystemCPULimitsBeforeBPF runs synchronously at the start of run(), before loading
// the BPF object or starting any other work in run(), so baseline P50 is measured on the host
// without this process having attached probes or started consumers.
func determineHostSystemCPULimitsBeforeBPF() hostSystemCPULimitConfig {
	var cfg hostSystemCPULimitConfig
	softFromEnv := !math.IsNaN(systemCPUSoftAbs)
	hardFromEnv := !math.IsNaN(systemCPUHardAbs)
	cfg.softFromEnv = softFromEnv
	cfg.hardFromEnv = hardFromEnv

	if hardFromEnv && systemCPUHardAbs <= 0 {
		trafficUtils.PrintLog("Host system CPU limit monitor off (AKTO_SYSTEM_CPU_HARD_CORES <= 0)")
		cfg.disabled = true
		return cfg
	}
	if !hardFromEnv && systemCPUHardAddCores <= 0 {
		trafficUtils.PrintLog("Host system CPU limit monitor off (AKTO_SYSTEM_CPU_HARD_ADD_CORES <= 0 and no hard limit env)")
		cfg.disabled = true
		return cfg
	}

	sec := systemCPUCheckIntervalSec
	if sec <= 0 {
		sec = 1
	}
	cfg.interval = time.Duration(sec) * time.Second

	baselineWindowSec := systemCPUBaselineWindowSec
	if baselineWindowSec <= 0 {
		baselineWindowSec = 15
	}
	if baselineWindowSec < 5 {
		baselineWindowSec = 5
	}
	if baselineWindowSec > 300 {
		baselineWindowSec = 300
	}
	baselineStepSec := systemCPUBaselineStepSec
	if baselineStepSec <= 0 {
		baselineStepSec = 1
	}
	if baselineStepSec < 1 {
		baselineStepSec = 1
	}
	if baselineStepSec > baselineWindowSec {
		baselineStepSec = baselineWindowSec
	}
	cfg.baselineWindowSec = baselineWindowSec
	cfg.baselineStepSec = baselineStepSec
	baselineWindow := time.Duration(baselineWindowSec) * time.Second
	baselineStep := time.Duration(baselineStepSec) * time.Second

	cfg.needBaseline = !softFromEnv || !hardFromEnv
	if cfg.needBaseline {
		trafficUtils.PrintLog("Sampling host system CPU baseline (P50 over window) before BPF load",
			"window", baselineWindow, "step", baselineStep)
		b, ok := trafficUtils.MeasureHostSystemCPUBaseline(baselineWindow, baselineStep)
		if !ok {
			trafficUtils.PrintLog("Host system CPU baseline sample failed; using 0 baseline for computed limits")
			cfg.baseline = 0
		} else {
			cfg.baseline = b
		}
	}

	if softFromEnv {
		cfg.soft = systemCPUSoftAbs
	} else {
		cfg.soft = cfg.baseline + systemCPUSoftAddCores
	}
	if hardFromEnv {
		cfg.hard = systemCPUHardAbs
	} else {
		cfg.hard = cfg.baseline + systemCPUHardAddCores
	}
	if cfg.hard <= cfg.soft {
		cfg.hard = cfg.soft + 1e-9
	}

	trafficUtils.PrintLog("Host system CPU limit configuration (before BPF load)",
		"disabled", cfg.disabled,
		"checkInterval", cfg.interval,
		"softLimitCores", cfg.soft,
		"hardLimitCores", cfg.hard,
		"softFromEnv", cfg.softFromEnv,
		"hardFromEnv", cfg.hardFromEnv,
		"needBaseline", cfg.needBaseline,
		"baselineCoresP50", cfg.baseline,
		"baselineWindowSec", cfg.baselineWindowSec,
		"baselineStepSec", cfg.baselineStepSec,
		"softAddCores", systemCPUSoftAddCores,
		"hardAddCores", systemCPUHardAddCores,
		"softOscillationExitTransitions", systemCPUSoftOscillationExitTransitions,
	)

	return cfg
}

// startHostSystemCPULimitMonitor runs the periodic CPU check using limits from
// determineHostSystemCPULimitsBeforeBPF (must be called first in run()).
func startHostSystemCPULimitMonitor(coll *ebpf.Collection, cfg hostSystemCPULimitConfig) {
	if cfg.disabled {
		return
	}

	soft, hard := cfg.soft, cfg.hard
	interval := cfg.interval
	needBaseline := cfg.needBaseline
	baseline := cfg.baseline
	softFromEnv := cfg.softFromEnv
	hardFromEnv := cfg.hardFromEnv
	baselineWindowSec := cfg.baselineWindowSec
	baselineStepSec := cfg.baselineStepSec

	sampler := trafficUtils.NewHostSystemCPUSampler()

	go func() {
		_, _, _ = sampler.Step()

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		wasPaused := trafficUtils.PauseIngestionEnv()
		oscillationTrack := !softFromEnv && systemCPUSoftOscillationExitTransitions > 0
		var prevSoftPaused bool
		var havePrevSoftPaused bool
		var softPauseTransitions int
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

			if cores >= hard {
				slog.Error("host system CPU hard limit exceeded, exiting", "systemCpuCores", cores, "hardLimitCores", hard)
				os.Exit(4)
			}

			if oscillationTrack {
				if havePrevSoftPaused && paused != prevSoftPaused {
					softPauseTransitions++
					if softPauseTransitions >= systemCPUSoftOscillationExitTransitions {
						slog.Error("host system CPU repeatedly crossed computed soft limit; exiting to resample baseline",
							"softPauseTransitions", softPauseTransitions,
							"threshold", systemCPUSoftOscillationExitTransitions,
							"systemCpuCores", cores,
							"softLimitCores", soft)
						os.Exit(5)
					}
				}
				prevSoftPaused = paused
				havePrevSoftPaused = true
			}

			trafficUtils.PrintLog("host system CPU check", "systemCpuCores", cores, "softLimitCores", soft, "hardLimitCores", hard, "ingestPaused", ingestPaused)

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
		logArgs = append(logArgs, "baselineCoresP50", baseline, "baselineWindowSec", baselineWindowSec, "baselineStepSec", baselineStepSec, "softAddCores", systemCPUSoftAddCores, "hardAddCores", systemCPUHardAddCores)
	}
	if !softFromEnv && systemCPUSoftOscillationExitTransitions > 0 {
		logArgs = append(logArgs, "softOscillationExitTransitions", systemCPUSoftOscillationExitTransitions)
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
