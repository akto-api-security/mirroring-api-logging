package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/bpfwrapper"
	"github.com/akto-api-security/mirroring-api-logging/ebpf/connections"
	"github.com/akto-api-security/mirroring-api-logging/ebpf/uprobeBuilder/process"
	"github.com/akto-api-security/mirroring-api-logging/ebpf/uprobeBuilder/ssl"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/apiProcessor"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/db"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/kafkaUtil"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/trafficMetrics"
	trafficUtils "github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

func replaceBpfLogsMacros(spec *ebpf.CollectionSpec) {
	printBpfLogs := false
	if v := os.Getenv("PRINT_BPF_LOGS"); strings.EqualFold(v, "true") {
		printBpfLogs = true
	}
	if v, ok := spec.Variables["print_bpf_logs"]; ok {
		if err := v.Set(printBpfLogs); err != nil {
			slog.Warn("failed to set print_bpf_logs variable", "error", err)
		}
	}
}

func replaceMaxConnectionMapSize(spec *ebpf.CollectionSpec) {
	maxConnectionSizeMapSize := 131072
	trafficUtils.InitVar("TRAFFIC_MAX_CONNECTION_MAP_SIZE", &maxConnectionSizeMapSize)
	for _, mapName := range []string{"conn_info_map", "conn_info_map_keys"} {
		if m, ok := spec.Maps[mapName]; ok {
			m.MaxEntries = uint32(maxConnectionSizeMapSize)
		}
	}
}

func main() {
	// Setting GC percent as 50, uses less memory overhead.
	// More testing needed for final release.
	// debug.SetGCPercent(50)

	run()
}

func run() {
	// -----------------------------------------------------------------------
	// Load the pre-compiled BPF object.
	//
	// The object file is produced by `make generate` (bpftool + clang) and must
	// exist before the Go binary is started.  Its path can be overridden via the
	// BPF_OBJ_PATH environment variable for packaging / testing convenience.
	// -----------------------------------------------------------------------
	bpfObjPath := "./kernel/module.bpf.o"
	if v := os.Getenv("BPF_OBJ_PATH"); v != "" {
		bpfObjPath = v
	}
	// Resolve to an absolute path so error messages are unambiguous.
	if abs, err := filepath.Abs(bpfObjPath); err == nil {
		bpfObjPath = abs
	}

	spec, err := ebpf.LoadCollectionSpec(bpfObjPath)
	if err != nil {
		slog.Error("failed to load BPF collection spec", "path", bpfObjPath, "error", err)
		panic(err)
	}

	// Configure runtime parameters on the spec before loading into the kernel.
	replaceBpfLogsMacros(spec)
	replaceMaxConnectionMapSize(spec)

	// If the kernel supports uprobe_multi (6.6+), mark all SEC("uprobe")
	// programs with the multi attach type so they can be attached via
	// bpf(BPF_LINK_CREATE) instead of perf_event_open — bypassing
	// perf_event_paranoid restrictions.
	bpfwrapper.SetUprobeMultiAttachType(spec)

	// Load all programs and maps into the kernel.
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		slog.Error("failed to load BPF collection", "error", err)
		panic(err)
	}
	defer coll.Close()

	// Track all links for deferred cleanup.
	var allLinks []link.Link
	defer func() {
		for _, l := range allLinks {
			l.Close()
		}
	}()

	// -----------------------------------------------------------------------
	// Application-level initialisation.
	// -----------------------------------------------------------------------
	db.InitMongoClient()
	defer db.CloseMongoClient()

	// this needs to be called before InitKafka
	apiProcessor.InitCloudTrafficProcessor()
	kafkaUtil.InitKafka()

	kafkaUtil.StartConfigConsumer()

	stopCh, err := kafkaUtil.SetupPodInformer()
	if err != nil {
		slog.Error("Failed to setup pod watcher", "error", err)
	}

	connectionFactory := connections.NewFactory()

	trafficMetrics.InitTrafficMaps()
	trafficMetrics.StartMetricsTicker()

	// -----------------------------------------------------------------------
	// Perf-buffer consumers — launched before kprobes so buffers are ready.
	// -----------------------------------------------------------------------
	callbacks := []*bpfwrapper.ProbeChannel{
		bpfwrapper.NewProbeChannel("socket_open_events", bpfwrapper.SocketOpenEventCallback),
		bpfwrapper.NewProbeChannel("socket_data_events", bpfwrapper.SocketDataEventCallback),
		bpfwrapper.NewProbeChannel("socket_close_events", bpfwrapper.SocketCloseEventCallback),
	}
	if err := bpfwrapper.LaunchPerfBufferConsumers(coll, connectionFactory, callbacks); err != nil {
		slog.Error("failed to launch perf buffer consumers", "error", err)
		panic(err)
	}

	// -----------------------------------------------------------------------
	// Kprobe attachment.
	// -----------------------------------------------------------------------
	captureSsl := os.Getenv("CAPTURE_SSL")
	captureEgress := os.Getenv("CAPTURE_EGRESS")
	captureAll := "true"
	if v := os.Getenv("CAPTURE_ALL"); len(v) != 0 {
		captureAll = v
	}

	hooks := make([]bpfwrapper.Kprobe, 0)
	hooks = append(hooks, bpfwrapper.Level1hooks...)
	hooks = append(hooks, bpfwrapper.Level1hooksType2...)
	if len(captureSsl) == 0 || captureSsl == "false" || captureAll == "true" {
		if len(captureEgress) > 0 && captureEgress == "true" {
			hooks = append(hooks, bpfwrapper.Level2hooksEgress...)
			hooks = append(hooks, bpfwrapper.Level3hooksEgress...)
		} else {
			hooks = append(hooks, bpfwrapper.Level2hooks...)
			hooks = append(hooks, bpfwrapper.Level3hooks...)

		}
	}
	hooks = append(hooks, bpfwrapper.Level4hooks...)

	kprobeLinks, err := bpfwrapper.AttachKprobes(coll, hooks)
	if err != nil {
		fmt.Printf("Error attaching kprobes: %v\n", err)
	}
	allLinks = append(allLinks, kprobeLinks...)

	// -----------------------------------------------------------------------
	// Uprobe attachment (SSL / GoTLS / Node).
	// -----------------------------------------------------------------------
	processFactory := process.NewFactory()

	var isRunning bool
	var mu sync.Mutex

	pollInterval := 20 * time.Minute
	trafficUtils.InitVar("UPROBE_POLL_INTERVAL", &pollInterval)

	ssl.InitMaps(coll)

	if captureSsl == "true" || captureAll == "true" {
		go func() {
			slog.Debug("Starting uprobe process ticker")
			attachToProcesses := func() {
				slog.Debug("Starting to attach to processes in ticker")
				mu.Lock()
				if isRunning {
					mu.Unlock()
					return
				}
				isRunning = true
				mu.Unlock()

				slog.Info("Starting to attach to processes")
				processFactory.AddNewProcessesToProbe(coll)
				slog.Debug("Ended attaching to processes")

				mu.Lock()
				isRunning = false
				mu.Unlock()
				slog.Debug("Ended attaching to processes in ticker")
			}

			attachToProcesses()

			ticker := time.NewTicker(pollInterval)
			defer ticker.Stop()
			for range ticker.C {
				attachToProcesses()
			}
			slog.Debug("Ended attaching to processes in ticker end")
		}()
	}

	doProfiling := false
	trafficUtils.InitVar("AKTO_DEBUG_MEM_PROFILING", &doProfiling)

	if doProfiling {
		ticker := time.NewTicker(time.Minute) // Create a ticker to trigger every minute
		defer ticker.Stop()

		for range ticker.C {
			captureMemoryProfile() // Capture memory profile every time the ticker ticks
		}
	}

	//ticker := time.NewTicker(15 * time.Second)
	//defer ticker.Stop()
	//
	//for range ticker.C {
	//	go captureCpuProfile()
	//}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)

	slog.Info("sniffer is ready")
	<-sig
	if stopCh != nil {
		slog.Info("Stopping pod watcher")
		close(stopCh)
	}

	slog.Info("signaled to terminate")
}

func captureMemoryProfile() {
	f, _ := os.Create("mem.prof") // Create memory profile file
	defer f.Close()

	pprof.WriteHeapProfile(f) // Write memory profile
}

func captureCpuProfile() {
	timestamp := time.Now().Format("20060102_150405")
	fileName := fmt.Sprintf("cpu_%s.prof", timestamp)
	f, err := os.Create(fileName)
	if err != nil {
		panic("could not create CPU profile: " + err.Error())
	}
	defer f.Close()

	if err := pprof.StartCPUProfile(f); err != nil {
		panic("could not start CPU profile: " + err.Error())
	}
	slog.Debug("CPU profiling started")

	// Allow profiling for a certain duration or simulate workload
	time.Sleep(12 * time.Second) // Sleep for 10 seconds to simulate CPU activity

	pprof.StopCPUProfile()
	slog.Debug("CPU profiling stopped")
}
