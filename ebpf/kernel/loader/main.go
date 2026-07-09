package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
)

// Must match struct conn_info_t in module.bpf.c
type ConnInfo struct {
	ID          uint64
	FD          uint32
	_           [4]byte // padding for conn_start_ns alignment
	ConnStartNs uint64
	Raddr       uint32
	Laddr       uint32
	Rport       uint16
	Lport       uint16
	Role        uint32
}

// Must match struct conn_event_t in module.bpf.c
type ConnEvent struct {
	Conn      ConnInfo
	EventType uint32
}

func roleStr(role uint32) string {
	switch role {
	case 1:
		return "client"
	case 2:
		return "server"
	default:
		return "unknown"
	}
}

func eventTypeStr(t uint32) string {
	if t == 0 {
		return "OPEN"
	}
	return "CLOSE"
}

func ipStr(ip uint32) string {
	return net.IP([]byte{
		byte(ip), byte(ip >> 8), byte(ip >> 16), byte(ip >> 24),
	}).String()
}

func main() {
	mode := flag.String("mode", "capture", "Mode: capture, test, stress")
	bpfObj := flag.String("bpf-obj", "../module.bpf.o", "Path to BPF object file")
	tracePids := flag.String("trace-pids", "", "Comma-separated PIDs to trace")
	traceComms := flag.String("trace-comms", "", "Comma-separated process names to trace")
	metrics := flag.Bool("metrics", false, "Enable BPF metrics (auto-enabled for stress)")
	debug := flag.Bool("debug", true, "Enable BPF kernel debug logs (trace_pipe)")
	ringbufMB := flag.Int("ringbuf-mb", 0, "Ring buffer size in MB (0 = default 4MB)")
	maxConns := flag.Int("max-tracked-conns", 0, "Max tracked connections (0 = default 131072)")
	maxInflight := flag.Int("max-inflight-syscalls", 0, "Max in-flight accept/connect syscalls (0 = default 4096)")
	flag.Parse()

	switch *mode {
	case "capture":
		runCapture(*bpfObj, *tracePids, *traceComms, *metrics, *debug, uint32(*ringbufMB)<<20, uint32(*maxConns), uint32(*maxInflight))
	case "test":
		runTests(*bpfObj)
	case "stress":
		runTests(*bpfObj, "-run", "TestStress")
	default:
		log.Fatalf("Unknown mode: %s (use capture, test, or stress)", *mode)
	}
}

func buildOpts(bpfObj, tracePids, traceComms string, metrics, debug bool, ringbufSize, maxTrackedConns, maxInflightSyscalls uint32) LoadOpts {
	pids := ParsePids(tracePids)
	comms := ParseComms(traceComms)

	return LoadOpts{
		BpfObjPath:          bpfObj,
		TracePids:           pids,
		TraceComms:          comms,
		Metrics:             metrics,
		Debug:               debug,
		RingbufSize:         ringbufSize,
		MaxTrackedConns:     maxTrackedConns,
		MaxInflightSyscalls: maxInflightSyscalls,
	}
}

func runCapture(bpfObj, tracePids, traceComms string, metrics, debug bool, ringbufSize, maxTrackedConns, maxInflightSyscalls uint32) {
	opts := buildOpts(bpfObj, tracePids, traceComms, metrics, debug, ringbufSize, maxTrackedConns, maxInflightSyscalls)
	loader, err := LoadAndAttachWithOpts(opts)
	if err != nil {
		log.Fatalf("LoadAndAttach: %v", err)
	}
	defer loader.Close()

	log.Printf("Waiting for events... (Ctrl+C to stop)")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\nDetaching probes...")
		loader.RB.Close()
	}()

	fmt.Println()
	fmt.Printf("%-6s %-8s %-7s %-22s %-22s\n", "EVENT", "PID", "FD", "LOCAL", "REMOTE")
	fmt.Println("------ -------- ------- ---------------------- ----------------------")

	for {
		event, err := loader.ReadEvent()
		if err != nil {
			break
		}

		c := event.Conn
		pid := c.ID >> 32
		local := fmt.Sprintf("%s:%d", ipStr(c.Laddr), c.Lport)
		rport := binary.BigEndian.Uint16([]byte{byte(c.Rport), byte(c.Rport >> 8)})
		remote := fmt.Sprintf("%s:%d", ipStr(c.Raddr), rport)

		fmt.Printf("%-6s %-8d %-7d %-22s %-22s  role=%s\n",
			eventTypeStr(event.EventType), pid, c.FD, local, remote, roleStr(c.Role))
	}

	if opts.Metrics {
		fmt.Println("\n--- Metrics ---")
		for _, name := range MetricNames {
			if v := loader.ReadMetrics()[name]; v > 0 {
				fmt.Printf("  %-24s %d\n", name, v)
			}
		}
	}
	fmt.Println("Done.")
}

func runTests(bpfObj string, extraArgs ...string) {
	// Resolve to absolute path so tests find it regardless of working dir
	absBpfObj := bpfObj
	if !filepath.IsAbs(bpfObj) {
		if abs, err := filepath.Abs(bpfObj); err == nil {
			absBpfObj = abs
		}
	}

	args := []string{"test", "-v", "-count=1", "-timeout", "120s"}

	// For stress mode, auto-enable metrics
	isStress := false
	for _, a := range extraArgs {
		if a == "TestStress" {
			isStress = true
		}
	}

	args = append(args, extraArgs...)
	args = append(args, ".")

	loaderDir := findLoaderDir()
	cmd := exec.Command("go", args...)
	cmd.Dir = loaderDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "BPF_OBJ="+absBpfObj)
	if isStress {
		cmd.Env = append(cmd.Env, "ENABLE_METRICS=1")
	}

	log.Printf("Running: go %s (dir=%s, BPF_OBJ=%s)", args, loaderDir, absBpfObj)
	if err := cmd.Run(); err != nil {
		os.Exit(1)
	}
}

func findLoaderDir() string {
	// Try to find the loader directory relative to the binary or cwd
	for _, dir := range []string{".", "./loader", "../loader"} {
		if _, err := os.Stat(dir + "/main_test.go"); err == nil {
			return dir
		}
	}
	return "."
}
