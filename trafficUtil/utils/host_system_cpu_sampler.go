package utils

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// HostSystemCPUSampler reads the aggregate "cpu" line of /proc/stat and, on each Step after the
// first prime, reports kernel ("system") CPU usage two ways (same jiffies deltas):
//   - systemPercent: 100 * Δsystem / Δtotal jiffies (share of CPU time in kernel mode)
//   - systemCores: Δsystem / USER_HZ / wall_seconds (average kernel core-equivalents)
type HostSystemCPUSampler struct {
	mu      sync.Mutex
	clk     int64
	primed  bool
	lastUser, lastNice, lastSystem, lastIdle, lastIowait, lastIrq, lastSoftirq, lastSteal uint64
	lastWall time.Time
}

func NewHostSystemCPUSampler() *HostSystemCPUSampler {
	// /proc/stat counters are in units of USER_HZ; 100 Hz is universal on Linux (see proc(5)).
	const userHz int64 = 100
	return &HostSystemCPUSampler{clk: userHz}
}

// Step updates the sampler from /proc/stat. The first successful call primes internal state
// and returns ok=false (same as a baseline sample). Later calls return ok=true with metrics
// since the previous Step.
func (s *HostSystemCPUSampler) Step() (systemPercent, systemCores float64, ok bool) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0, false
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return 0, 0, false
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 9 || fields[0] != "cpu" {
		return 0, 0, false
	}

	parse := func(i int) uint64 {
		if i >= len(fields) {
			return 0
		}
		v, err := strconv.ParseUint(fields[i], 10, 64)
		if err != nil {
			return 0
		}
		return v
	}

	user := parse(1)
	nice := parse(2)
	system := parse(3)
	idle := parse(4)
	iowait := parse(5)
	irq := parse(6)
	softirq := parse(7)
	steal := parse(8)

	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	// Ignore pathological windows (e.g. overlapping Step calls): tiny elapsed blows up cores/sec.
	const minSampleGap = 100 * time.Millisecond

	if !s.primed {
		s.lastUser, s.lastNice = user, nice
		s.lastSystem = system
		s.lastIdle, s.lastIowait = idle, iowait
		s.lastIrq, s.lastSoftirq, s.lastSteal = irq, softirq, steal
		s.lastWall = now
		s.primed = true
		return 0, 0, false
	}

	du := subDeltaUint64(user, s.lastUser)
	dn := subDeltaUint64(nice, s.lastNice)
	ds := subDeltaUint64(system, s.lastSystem)
	di := subDeltaUint64(idle, s.lastIdle)
	diow := subDeltaUint64(iowait, s.lastIowait)
	dirq := subDeltaUint64(irq, s.lastIrq)
	dsoft := subDeltaUint64(softirq, s.lastSoftirq)
	dst := subDeltaUint64(steal, s.lastSteal)

	s.lastUser, s.lastNice = user, nice
	s.lastSystem = system
	s.lastIdle, s.lastIowait = idle, iowait
	s.lastIrq, s.lastSoftirq, s.lastSteal = irq, softirq, steal

	elapsed := now.Sub(s.lastWall).Seconds()
	s.lastWall = now

	if elapsed < minSampleGap.Seconds() {
		return 0, 0, false
	}

	if elapsed <= 0 {
		return 0, 0, false
	}

	totalDelta := du + dn + ds + di + diow + dirq + dsoft + dst
	if totalDelta > 0 {
		systemPercent = 100 * float64(ds) / float64(totalDelta)
	}
	systemCores = float64(ds) / float64(s.clk) / elapsed

	return systemPercent, systemCores, true
}

func subDeltaUint64(curr, prev uint64) uint64 {
	if curr >= prev {
		return curr - prev
	}
	// Counter reset, hotplug, migrate, or bad read — do not treat curr as a delta.
	return 0
}

// MeasureHostSystemCPUBaseline returns average host kernel CPU usage in core-equivalents over `wait`
// (after an initial prime sample). Call before attaching probes so the value reflects load without
// this module's kprobes/BPF work.
func MeasureHostSystemCPUBaseline(wait time.Duration) (baselineCores float64, ok bool) {
	if wait <= 0 {
		wait = time.Second
	}
	s := NewHostSystemCPUSampler()
	_, _, _ = s.Step()
	time.Sleep(wait)
	_, cores, ok := s.Step()
	return cores, ok
}
