package utils

import (
	"math"
	"os"
	"slices"
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
	mu                                                                                    sync.Mutex
	clk                                                                                   int64
	primed                                                                                bool
	lastUser, lastNice, lastSystem, lastIdle, lastIowait, lastIrq, lastSoftirq, lastSteal uint64
	lastWall                                                                              time.Time
}

func NewHostSystemCPUSampler() *HostSystemCPUSampler {
	const userHz int64 = 100
	return &HostSystemCPUSampler{clk: userHz}
}

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

	if elapsed < minSampleGap.Seconds() || elapsed <= 0 {
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
	return 0
}

// linearPercentile returns the p-th percentile (0 <= p <= 1) of x, which must be sorted ascending.
func linearPercentile(x []float64, p float64) float64 {
	n := len(x)
	if n == 0 {
		return 0
	}
	if n == 1 {
		return x[0]
	}
	if p <= 0 {
		return x[0]
	}
	if p >= 1 {
		return x[n-1]
	}
	pos := p * float64(n-1)
	lo := int(math.Floor(pos))
	hi := int(math.Ceil(pos))
	if lo == hi {
		return x[lo]
	}
	return x[lo] + (pos-float64(lo))*(x[hi]-x[lo])
}

// MeasureHostSystemCPUBaseline collects kernel systemCores samples every sampleEvery over totalWindow,
// then returns their P90 (linear interpolation between order statistics). Each sample is one
// HostSystemCPUSampler.Step after sleeping sampleEvery (same semantics as the runtime monitor ticks).
func MeasureHostSystemCPUBaseline(totalWindow, sampleEvery time.Duration) (baselineCores float64, ok bool) {
	if totalWindow <= 0 {
		totalWindow = 15 * time.Second
	}
	if sampleEvery < 100*time.Millisecond {
		sampleEvery = 100 * time.Millisecond
	}
	if sampleEvery > totalWindow {
		sampleEvery = totalWindow
	}
	n := int(totalWindow / sampleEvery)
	if n < 1 {
		n = 1
	}

	s := NewHostSystemCPUSampler()
	_, _, _ = s.Step()

	samples := make([]float64, 0, n)
	for i := 0; i < n; i++ {
		time.Sleep(sampleEvery)
		_, cores, sampleOk := s.Step()
		if sampleOk {
			samples = append(samples, cores)
		}
	}
	if len(samples) == 0 {
		return 0, false
	}
	slices.Sort(samples)
	return linearPercentile(samples, 0.9), true
}
