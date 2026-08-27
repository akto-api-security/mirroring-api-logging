package utils

import (
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"runtime/pprof"
	"sync"
	"time"
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
	sysMem := int(m.Sys / 1024 / 1024)
	slog.Warn("Alloc in MB: ", "mem", mem)
	slog.Warn("Sys in MB: ", "mem", sysMem)
	// Sys = HeapSys + StackSys + MSpanSys + MCacheSys + BuckHashSys + GCSys + OtherSys.
	// Logged unconditionally (before either threshold check below can os.Exit) so this
	// breakdown is captured at the exact moment a run dies, not just periodically —
	// disambiguates goroutine-stack growth (StackSys) from unreturned/fragmented heap
	// (HeapIdle - HeapReleased) from GC/allocator bookkeeping (GCSys/MSpanSys/MCacheSys),
	// none of which a pprof heap profile (-inuse_space/-alloc_space) can see: those only
	// cover HeapInuse-family bytes.
	slog.Warn("MemStats Sys breakdown (MB)",
		"heapSys", m.HeapSys/1024/1024,
		"heapInuse", m.HeapInuse/1024/1024,
		"heapIdle", m.HeapIdle/1024/1024,
		"heapReleased", m.HeapReleased/1024/1024,
		"stackSys", m.StackSys/1024/1024,
		"mSpanSys", m.MSpanSys/1024/1024,
		"mCacheSys", m.MCacheSys/1024/1024,
		"gcSys", m.GCSys/1024/1024,
		"otherSys", m.OtherSys/1024/1024,
		"buckHashSys", m.BuckHashSys/1024/1024,
		"numGoroutine", runtime.NumGoroutine(),
	)
	if mem > aktoMemThreshRestart {
		slog.Error("Refreshing, current alloc mem usage", "mem", mem, "threshold", aktoMemThreshRestart)
		dumpHeapOnDeath("alloc")
		os.Exit(3)
	}

	if sysMem > aktoSysMemThreshRestart {
		slog.Error("Refreshing, current sys mem usage", "mem", sysMem, "threshold", aktoSysMemThreshRestart)
		dumpHeapOnDeath("sys")
		os.Exit(3)
	}

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

// dumpHeapOnDeath writes a heap profile to the current working directory right
// before os.Exit(3) — the fatal-restart path. A pprof heap profile only covers
// HeapInuse-family bytes (see the Sys-breakdown comment above), but it's still
// the only thing that can attribute WHICH function's allocations make up that
// HeapInuse total, and periodic tickers (e.g. the rate-sweep test's 10s heap
// snapshots) can miss a sharp spike between samples — this dump is tied to the
// actual kill decision, not a clock, so it can't miss the death-moment state.
func dumpHeapOnDeath(reason string) {
	path := fmt.Sprintf("heap-death-%s-%d.prof", reason, time.Now().UnixNano())
	f, err := os.Create(path)
	if err != nil {
		slog.Error("dumpHeapOnDeath: create file", "path", path, "error", err)
		return
	}
	defer f.Close()
	if err := pprof.WriteHeapProfile(f); err != nil {
		slog.Error("dumpHeapOnDeath: write profile", "path", path, "error", err)
		return
	}
	slog.Error("dumpHeapOnDeath: wrote heap profile", "path", path, "reason", reason)
}

// HeapWatermarkMonitor polls HeapInuse at a fixed cadence and, only when it
// climbs past the previous high-water mark by more than growthPct, writes a
// full heap profile. This is cheaper than dumping on every poll (ReadMemStats
// alone is near-free; WriteHeapProfile is not) while still catching every
// local peak across a run — unlike a fixed low-frequency ticker (which can
// sample between spikes and miss them entirely, as observed on the 300k rate
// cell: 10s-apart snapshots peaked at 1.47GB while the actual death-moment
// HeapInuse, caught by dumpHeapOnDeath above, was 3.2GB) or a single
// death-moment dump (which only shows the final state, not the climb).
type HeapWatermarkMonitor struct {
	mu        sync.Mutex
	peak      uint64
	outDir    string
	pollEvery time.Duration
	growthPct float64
	stopCh    chan struct{}
	doneCh    chan struct{}
	stopOnce  sync.Once
}

// NewHeapWatermarkMonitor creates a monitor that writes new-peak heap profiles
// into outDir. growthPct is the minimum percentage climb over the current peak
// required before a new profile is written (e.g. 10 means only re-dump once
// HeapInuse exceeds peak*1.10) — this bounds write frequency near a sustained
// peak without missing genuinely new highs.
func NewHeapWatermarkMonitor(outDir string, pollEvery time.Duration, growthPct float64) *HeapWatermarkMonitor {
	return &HeapWatermarkMonitor{outDir: outDir, pollEvery: pollEvery, growthPct: growthPct}
}

// Start begins polling in a background goroutine. Safe to call once per
// monitor instance; call Stop before Start-ing again.
func (m *HeapWatermarkMonitor) Start() {
	m.stopCh = make(chan struct{})
	m.doneCh = make(chan struct{})
	if err := os.MkdirAll(m.outDir, 0o755); err != nil {
		slog.Error("HeapWatermarkMonitor: mkdir outDir", "dir", m.outDir, "error", err)
	}
	go func() {
		defer close(m.doneCh)
		ticker := time.NewTicker(m.pollEvery)
		defer ticker.Stop()
		for {
			select {
			case <-m.stopCh:
				return
			case <-ticker.C:
				m.checkAndMaybeDump()
			}
		}
	}()
}

func (m *HeapWatermarkMonitor) checkAndMaybeDump() {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	m.mu.Lock()
	prevPeak := m.peak
	threshold := uint64(float64(prevPeak) * (1 + m.growthPct/100))
	isNewPeak := prevPeak == 0 || ms.HeapInuse > threshold
	if isNewPeak {
		m.peak = ms.HeapInuse
	}
	m.mu.Unlock()

	if !isNewPeak {
		return
	}

	path := fmt.Sprintf("%s/heap-watermark-%d.prof", m.outDir, time.Now().UnixNano())
	f, err := os.Create(path)
	if err != nil {
		slog.Error("HeapWatermarkMonitor: create file", "path", path, "error", err)
		return
	}
	defer f.Close()
	if err := pprof.WriteHeapProfile(f); err != nil {
		slog.Error("HeapWatermarkMonitor: write profile", "path", path, "error", err)
		return
	}
	slog.Warn("HeapWatermarkMonitor: new peak captured",
		"heapInuseMB", ms.HeapInuse/1024/1024,
		"prevPeakMB", prevPeak/1024/1024,
		"numGoroutine", runtime.NumGoroutine(),
		"path", path,
	)
}

// Stop halts polling and blocks until the background goroutine has exited.
// Stop is idempotent — safe to call more than once (e.g. an explicit Stop at
// normal cell-teardown plus a defer'd Stop as a safety net for early
// t.Fatalf/panic paths). Only the first call actually closes stopCh.
func (m *HeapWatermarkMonitor) Stop() {
	if m.stopCh == nil {
		return
	}
	m.stopOnce.Do(func() {
		close(m.stopCh)
		<-m.doneCh
	})
}

// ResetPeak zeroes the watermark, e.g. between rate-sweep cells so a smaller
// subsequent cell isn't compared against a larger prior cell's peak.
func (m *HeapWatermarkMonitor) ResetPeak() {
	m.mu.Lock()
	m.peak = 0
	m.mu.Unlock()
}
