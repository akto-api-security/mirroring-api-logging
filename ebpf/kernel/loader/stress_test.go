package main

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStressBurst(t *testing.T) {
	h := setupStressHarness(t)

	count := 500
	concurrency := 100
	t.Logf("Burst: %d connections, %d concurrent", count, concurrency)

	succeeded := makeConnections(t, h.Addr, count, concurrency)
	t.Logf("Successful connections: %d/%d", succeeded, count)

	h.DrainAndAssert(t, succeeded, 0)
}

func TestStressSustained(t *testing.T) {
	h := setupStressHarness(t)

	rate := 1000
	durationSec := 20
	count := rate * durationSec
	t.Logf("Sustained: %d conn/sec for %ds = %d total", rate, durationSec, count)

	var succeeded atomic.Int64
	var wg sync.WaitGroup
	interval := time.Second / time.Duration(rate)

	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", h.Addr, 2*time.Second)
			if err != nil {
				return
			}
			conn.Close()
			succeeded.Add(1)
		}()
		time.Sleep(interval)
	}
	wg.Wait()

	t.Logf("Successful connections: %d/%d", succeeded.Load(), count)

	h.DrainAndAssert(t, int(succeeded.Load()), 0)
}

func TestStressRapidChurn(t *testing.T) {
	h := setupStressHarness(t)

	count := 10000
	t.Logf("Rapid churn: %d sequential connect+close", count)

	succeeded := 0
	for i := 0; i < count; i++ {
		conn, err := net.Dial("tcp", h.Addr)
		if err != nil {
			continue
		}
		conn.Close()
		succeeded++
	}

	t.Logf("Successful connections: %d/%d", succeeded, count)

	h.DrainAndAssert(t, succeeded, 0.01)
}
