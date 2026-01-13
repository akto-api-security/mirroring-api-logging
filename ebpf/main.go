package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"strconv"
	"sync"

	"strings"
	"syscall"
	"time"

	// need an unreleased version of the gobpf library, using from a specific branch, reasoning in the thread below.
	// https://stackoverflow.com/questions/73714654/not-enough-arguments-in-call-to-c2func-bcc-func-load

	"github.com/iovisor/gobpf/bcc"

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

var source string = ""

func replaceBpfChunkSizeMacros() {
	chunkSizeLimit := 4
	trafficUtils.InitVar("BPF_CHUNK_SIZE_LIMIT", &chunkSizeLimit)
	source = strings.Replace(source, "CHUNK_SIZE_LIMIT", strconv.Itoa(chunkSizeLimit), -1)
}

func replaceBpfLogsMacros() {

	printBpfLogsEnv := os.Getenv("PRINT_BPF_LOGS")
	printBpfLogs := "false"
	if len(printBpfLogsEnv) > 0 && strings.EqualFold(printBpfLogsEnv, "true") {
		printBpfLogs = "true"
	}

	source = strings.Replace(source, "PRINT_BPF_LOGS", printBpfLogs, -1)
}

func replaceMaxConnectionMapSize() {
	maxConnectionSizeMapSize := 131072
	trafficUtils.InitVar("TRAFFIC_MAX_CONNECTION_MAP_SIZE", &maxConnectionSizeMapSize)
	maxConnectionSizeMapSizeStr := strconv.Itoa(maxConnectionSizeMapSize)
	source = strings.Replace(source, "TRAFFIC_MAX_CONNECTION_MAP_SIZE", maxConnectionSizeMapSizeStr, -1)
}

func replaceArchType() {
	archStr := "TARGET_ARCH_X86_64"
	if isArmArch() {
		archStr = "TARGET_ARCH_AARCH64"
	}
	source = strings.Replace(source, "ARCH_TYPE", archStr, -1)
}

func isArmArch() bool {
	arch := runtime.GOARCH
	trafficUtils.PrintLog("arch type detected", "arch", arch)
	if strings.Contains(arch, "arm") {
		return true
	}
	return false
}

func isAmdArch() bool {
	arch := runtime.GOARCH
	trafficUtils.PrintLog("arch type detected", "arch", arch)
	if strings.Contains(arch, "amd") {
		return true
	}
	return false
}

func main() {
	// Setting GC percent as 50, uses less memory overhead.
	// More testing needed for final release.
	// debug.SetGCPercent(50)

	// Set up signal handling once at the top level
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)

	// Create restart control channel (buffered to prevent blocking)
	restartChan := make(chan struct{}, 1)

	// Context for test config changer
	testCtx, testCancel := context.WithCancel(context.Background())
	defer testCancel()

	// Start test config changer (changes log level every 2 minutes)
	go testConfigChanger(testCtx, restartChan)

	// Main loop that restarts run() on configuration changes
	for {
		// Create a cancellable context for this run
		ctx, cancel := context.WithCancel(context.Background())

		// Start run with context
		runDone := make(chan struct{})
		go func() {
			run(ctx)
			close(runDone)
		}()

		// Wait for either restart signal, run completion, or OS signal
		select {
		case <-restartChan:
			slog.Info("🔄 Received restart signal - stopping run() gracefully")
			cancel() // Cancel the context to stop run()
			<-runDone // Wait for run() to finish cleanup
			slog.Info("✅ Run stopped gracefully, restarting with new configuration")
			// Loop continues and restarts run() with new config
		case <-runDone:
			// run() completed (unlikely since it should run forever)
			cancel()
			slog.Info("run() completed unexpectedly")
			return
		case sig := <-sigChan:
			// OS signal received - shutdown gracefully
			slog.Info("Received OS signal, shutting down", "signal", sig)
			cancel()
			<-runDone
			slog.Info("Shutdown complete")
			return
		}
	}
}

func testConfigChanger(ctx context.Context, restartChan chan struct{}) {
	logLevels := []string{"DEBUG", "INFO", "WARN", "ERROR"}
	currentIndex := 0

	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	slog.Info("🧪 Test config changer started - will change AKTO_LOG_LEVEL every 2 minutes")

	for {
		select {
		case <-ctx.Done():
			slog.Info("Test config changer stopped")
			return
		case <-ticker.C:
			currentIndex = (currentIndex + 1) % len(logLevels)
			newLogLevel := logLevels[currentIndex]

			slog.Info("📝 Changing configuration", "AKTO_LOG_LEVEL", newLogLevel)
			os.Setenv("AKTO_LOG_LEVEL", newLogLevel)

			// Trigger restart (non-blocking send)
			slog.Info("🚀 Triggering restart to apply new log level")
			select {
			case restartChan <- struct{}{}:
				// Sent successfully
			default:
				// Channel full, restart already pending
				slog.Warn("Restart already pending, skipping this trigger")
			}
		}
	}
}

func run(ctx context.Context) {
	byteString, err := os.ReadFile("./kernel/module.cc")
	if err != nil {
		slog.Error("failed to read kernel module", "error", err)
		panic(err)
	}
	source = string(byteString)

	replaceBpfLogsMacros()
	replaceBpfChunkSizeMacros()
	replaceMaxConnectionMapSize()
	replaceArchType()

	bpfwrapper.DeleteExistingAktoKernelProbes()

	bpfModule := bcc.NewModule(source, []string{})
	if bpfModule == nil {
		slog.Error("failed to create BPF module", "error", "module is nil")
		panic("bpf module is nil")
	}
	defer bpfModule.Close()

	db.InitMongoClient()
	defer db.CloseMongoClient()

	// this needs to be called before InitKafka
	apiProcessor.InitCloudTrafficProcessor()
	kafkaUtil.InitKafka()

	stopCh, err := kafkaUtil.SetupPodInformer()
	if err != nil {
		slog.Error("Failed to setup pod watcher", "error", err)
	}
	defer func() {
		if stopCh != nil {
			slog.Info("Stopping pod watcher")
			close(stopCh)
		}
	}()

	connectionFactory := connections.NewFactory()

	trafficMetrics.InitTrafficMaps()

	callbacks := make([]*bpfwrapper.ProbeChannel, 0)

	captureSsl := os.Getenv("CAPTURE_SSL")
	captureEgress := os.Getenv("CAPTURE_EGRESS")
	captureAll := "true"
	captureAllEnv := os.Getenv("CAPTURE_ALL")
	if len(captureAllEnv) != 0 {
		captureAll = captureAllEnv
	}

	hooks := make([]bpfwrapper.Kprobe, 0)
	callbacks = append(callbacks, bpfwrapper.NewProbeChannel("socket_open_events", bpfwrapper.SocketOpenEventCallback))
	hooks = append(hooks, bpfwrapper.Level1hooks...)
	hooks = append(hooks, bpfwrapper.Level1hooksType2...)
	callbacks = append(callbacks, bpfwrapper.NewProbeChannel("socket_data_events", bpfwrapper.SocketDataEventCallback))
	if len(captureSsl) == 0 || captureSsl == "false" || captureAll == "true" {
		if len(captureEgress) > 0 && captureEgress == "true" {
			hooks = append(hooks, bpfwrapper.Level2hooksEgress...)
			hooks = append(hooks, bpfwrapper.Level3hooksEgress...)
		} else {
			hooks = append(hooks, bpfwrapper.Level2hooks...)
			hooks = append(hooks, bpfwrapper.Level3hooks...)

		}
	}
	callbacks = append(callbacks, bpfwrapper.NewProbeChannel("socket_close_events", bpfwrapper.SocketCloseEventCallback))
	hooks = append(hooks, bpfwrapper.Level4hooks...)

	if err := bpfwrapper.LaunchPerfBufferConsumers(bpfModule, connectionFactory, callbacks); err != nil {
		slog.Error("failed to launch perf buffer consumers", "error", err)
		panic(err)
	}

	// Ensure perf buffers are stopped when context is cancelled
	defer func() {
		slog.Info("Stopping perf buffer consumers")
		bpfwrapper.StopPerfBufferConsumers(callbacks)
		slog.Info("Perf buffer consumers stopped")
	}()

	if err := bpfwrapper.AttachKprobes(bpfModule, hooks); err != nil {
		fmt.Errorf("Error in attaching kprobes %v", err)
	}

	processFactory := process.NewFactory()

	var isRunning_2 bool
	var mu_2 = &sync.Mutex{}

	pollInterval := 20 * time.Minute

	trafficUtils.InitVar("UPROBE_POLL_INTERVAL", &pollInterval)

	ssl.InitMaps(bpfModule)

	// WaitGroup to track goroutines
	var wg sync.WaitGroup

	// Start metrics ticker with context and waitgroup
	trafficMetrics.StartMetricsTicker(ctx, &wg)

	if captureSsl == "true" || captureAll == "true" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			slog.Debug("Starting to attach to processes in ticker start")
			ticker := time.NewTicker(pollInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					slog.Debug("Context cancelled, stopping uprobe attachment goroutine")
					return
				case <-ticker.C:
					slog.Debug("Starting to attach to processes in ticker")
					if !isRunning_2 {
						mu_2.Lock()
						if isRunning_2 {
							mu_2.Unlock()
							continue
						}
						isRunning_2 = true
						mu_2.Unlock()

						slog.Info("Starting to attach to processes")
						processFactory.AddNewProcessesToProbe(ctx, bpfModule)
						slog.Debug("Ended attaching to processes")
						mu_2.Lock()
						isRunning_2 = false
						mu_2.Unlock()
					}
					slog.Debug("Ended attaching to processes in ticker")
				}
			}
		}()
	}

	doProfiling := false
	trafficUtils.InitVar("AKTO_DEBUG_MEM_PROFILING", &doProfiling)

	if doProfiling {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					slog.Debug("Context cancelled, stopping memory profiling goroutine")
					return
				case <-ticker.C:
					captureMemoryProfile()
				}
			}
		}()
	}

	slog.Info("sniffer is ready")

	// Wait for context cancellation (signal handling is done in main())
	<-ctx.Done()
	slog.Info("Context cancelled, stopping run()")

	// Wait for all goroutines to finish
	slog.Info("Waiting for background goroutines to finish...")
	wg.Wait()
	slog.Info("All background goroutines finished")
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
