package main

import (
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func bpfObjPath() string {
	p := os.Getenv("BPF_OBJ")
	if p == "" {
		p = "../module.bpf.o"
	}
	return p
}

// eventCollector reads events in the background. Call stop() to get results.
type eventCollector struct {
	loader *BPFLoader
	events []ConnEvent
	mu     sync.Mutex
	done   chan struct{}
}

func startCollecting(loader *BPFLoader) *eventCollector {
	ec := &eventCollector{
		loader: loader,
		done:   make(chan struct{}),
	}
	go func() {
		defer close(ec.done)
		for {
			ev, err := loader.ReadEvent()
			if err != nil {
				return
			}
			ec.mu.Lock()
			ec.events = append(ec.events, ev)
			ec.mu.Unlock()
		}
	}()
	return ec
}

func (ec *eventCollector) stop() []ConnEvent {
	ec.loader.RB.Close()
	<-ec.done
	ec.mu.Lock()
	defer ec.mu.Unlock()
	return ec.events
}

// collectEvents reads events from the ring buffer for the given duration (legacy helper).
func collectEvents(t testing.TB, loader *BPFLoader, duration time.Duration) []ConnEvent {
	t.Helper()
	var events []ConnEvent

	loader.RB.SetDeadline(time.Now().Add(duration))

	for {
		ev, err := loader.ReadEvent()
		if err != nil {
			break
		}
		events = append(events, ev)
	}

	return events
}

// stressHarness sets up echo server, BPF loader, and event collector.
// Returns server addr, server port, loader, collector, and a cleanup function.
type stressHarness struct {
	Addr       string
	ServerPort int
	Loader     *BPFLoader
	EC         *eventCollector
}

func setupStressHarness(t testing.TB) *stressHarness {
	t.Helper()

	ln, stop := startEchoServer(t)
	addr := ln.Addr().String()
	serverPort := ln.Addr().(*net.TCPAddr).Port
	t.Logf("Server on %s", addr)

	loader, err := LoadAndAttachWithOpts(LoadOpts{
		BpfObjPath: bpfObjPath(),
		Metrics:    true,
	})
	if err != nil {
		stop()
		t.Fatalf("LoadAndAttach: %v", err)
	}

	ec := startCollecting(loader)

	t.Cleanup(func() {
		loader.Close()
		stop()
	})

	return &stressHarness{
		Addr:       addr,
		ServerPort: serverPort,
		Loader:     loader,
		EC:         ec,
	}
}

// DrainAndAssert waits for events to drain, stops collecting, and asserts event counts.
func (h *stressHarness) DrainAndAssert(t testing.TB, expected int, maxLoss float64) {
	t.Helper()
	time.Sleep(2 * time.Second)
	events := h.EC.stop()
	assertConnEvents(t, h.Loader, events, h.ServerPort, expected, maxLoss)
}

// startEchoServer starts a TCP server that accepts connections and immediately closes them.
func startEchoServer(t testing.TB) (net.Listener, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var stopped sync.Once
	done := make(chan struct{})

	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	stop := func() {
		stopped.Do(func() {
			ln.Close()
			<-done
		})
	}

	return ln, stop
}

// makeConnections dials the target n times with the given concurrency.
func makeConnections(t testing.TB, addr string, count int, concurrency int) int {
	t.Helper()
	var wg sync.WaitGroup
	var success int64
	sem := make(chan struct{}, concurrency)

	for i := 0; i < count; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				return
			}
			conn.Close()
			atomic.AddInt64(&success, 1)
		}()
	}

	wg.Wait()
	return int(atomic.LoadInt64(&success))
}

// logEvents logs all collected events.
func logEvents(t testing.TB, events []ConnEvent) {
	t.Helper()
	t.Logf("Collected %d events:", len(events))
	for _, e := range events {
		c := e.Conn
		t.Logf("  %s pid=%d fd=%d %s:%d -> %s:%d role=%s",
			eventTypeStr(e.EventType), c.ID>>32, c.FD,
			IPStr(c.Laddr), c.Lport,
			IPStr(c.Raddr), PortToHost(c.Rport),
			roleStr(c.Role))
	}
}

// logMetrics logs all non-zero metrics.
func logMetrics(t testing.TB, loader *BPFLoader) {
	t.Helper()
	metrics := loader.ReadMetrics()
	t.Log("--- Metrics ---")
	for _, name := range MetricNames {
		if v, ok := metrics[name]; ok {
			t.Logf("  %-24s %d", name, v)
		}
	}
}

// countEvents counts events matching the given filter.
func countEvents(events []ConnEvent, filter func(ConnEvent) bool) int {
	n := 0
	for _, e := range events {
		if filter(e) {
			n++
		}
	}
	return n
}

// assertConnEvents counts client/server open/close events by role,
// logs the results, and fails the test if loss exceeds maxLoss (0.0 = zero tolerance, 0.01 = 1%).
func assertConnEvents(t testing.TB, loader *BPFLoader, events []ConnEvent, serverPort int, expected int, maxLoss float64) {
	t.Helper()

	clientOpens := countEvents(events, func(e ConnEvent) bool {
		return e.EventType == 0 && e.Conn.Role == 1 && PortToHost(e.Conn.Rport) == uint16(serverPort)
	})
	serverOpens := countEvents(events, func(e ConnEvent) bool {
		return e.EventType == 0 && e.Conn.Role == 2 && e.Conn.Lport == uint16(serverPort)
	})
	clientCloses := countEvents(events, func(e ConnEvent) bool {
		return e.EventType == 1 && e.Conn.Role == 1 && PortToHost(e.Conn.Rport) == uint16(serverPort)
	})
	serverCloses := countEvents(events, func(e ConnEvent) bool {
		return e.EventType == 1 && e.Conn.Role == 2 && e.Conn.Lport == uint16(serverPort)
	})

	t.Logf("Client:  %d opens, %d closes (expect %d each)", clientOpens, clientCloses, expected)
	t.Logf("Server:  %d opens, %d closes (expect %d each)", serverOpens, serverCloses, expected)

	logMetrics(t, loader)

	for _, tc := range []struct {
		name     string
		got, exp int
	}{
		{"client_open", clientOpens, expected},
		{"server_open", serverOpens, expected},
		{"client_close", clientCloses, expected},
		{"server_close", serverCloses, expected},
	} {
		if tc.exp == 0 {
			continue
		}
		loss := float64(tc.exp-tc.got) / float64(tc.exp)
		if loss > maxLoss {
			t.Errorf("%s: %d/%d (%.1f%% loss, threshold %.1f%%)",
				tc.name, tc.got, tc.exp, loss*100, maxLoss*100)
		}
	}
}

// formatEvent returns a one-line string for an event.
func formatEvent(e ConnEvent) string {
	c := e.Conn
	return fmt.Sprintf("%s pid=%d fd=%d %s:%d->%s:%d role=%s",
		eventTypeStr(e.EventType), c.ID>>32, c.FD,
		IPStr(c.Laddr), c.Lport,
		IPStr(c.Raddr), PortToHost(c.Rport),
		roleStr(c.Role))
}
