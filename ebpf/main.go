package main

import (
	"encoding/binary"
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
	"github.com/akto-api-security/mirroring-api-logging/ebpf/conntrack"
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

func replaceLocalTrafficFilter() {
	filterLocal := "false"
	trafficUtils.InitVar("FILTER_LOCAL_TRAFFIC", &filterLocal)
	source = strings.Replace(source, "FILTER_LOCAL_TRAFFIC", filterLocal, -1)

	// Default: 127.0.0.1 as little-endian u32.
	// IP bytes [127,0,0,1] → LE u32 = 127 + 0<<8 + 0<<16 + 1<<24 = 16777343
	localIpLE := 16777343
	trafficUtils.InitVar("LOCAL_TRAFFIC_IP_LE", &localIpLE)
	source = strings.Replace(source, "LOCAL_TRAFFIC_IP", strconv.Itoa(localIpLE), -1)
}

// replaceStrictRemotePortFilter gates socket_data on conn_info->port (remote / dest port in BPF).
// When TRAFFIC_STRICT_REMOTE_PORT_FILTER is true, events for connections whose port != STRICT_REMOTE_PORT are dropped (default port 10275).
func replaceStrictRemotePortFilter() {
	filterOn := "false"
	env := os.Getenv("TRAFFIC_STRICT_REMOTE_PORT_FILTER")
	if len(env) > 0 && strings.EqualFold(env, "true") {
		filterOn = "true"
	}
	source = strings.Replace(source, "FILTER_STRICT_REMOTE_PORT", filterOn, -1)

	strictPort := 10275
	trafficUtils.InitVar("TRAFFIC_STRICT_REMOTE_PORT", &strictPort)
	if strictPort < 0 {
		strictPort = 0
	}
	if strictPort > 65535 {
		strictPort = 65535
	}
	source = strings.Replace(source, "STRICT_REMOTE_PORT", strconv.Itoa(strictPort), -1)
}

// replaceDisablePerfSubmit sets token DISABLE_PERF_SUBMIT in module.cc to true/false.
// When true (env TRAFFIC_DISABLE_PERF_SUBMIT), BPF skips all perf_submit calls (no events to userspace).
func replaceDisablePerfSubmit() {
	disablePerf := "false"
	env := os.Getenv("TRAFFIC_DISABLE_PERF_SUBMIT")
	if len(env) > 0 && strings.EqualFold(env, "true") {
		disablePerf = "true"
	}
	source = strings.Replace(source, "DISABLE_PERF_SUBMIT", disablePerf, -1)
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

	run()
}

func run() {
	slog.Debug("Go version", "version", runtime.Version())
	slog.Debug("runtime.NumCPU()", "count", runtime.NumCPU())
	slog.Debug("runtime.GOMAXPROCS(0)", "procs", runtime.GOMAXPROCS(0))

	byteString, err := os.ReadFile("./kernel/module.cc")
	if err != nil {
		slog.Error("failed to read kernel module", "error", err)
		panic(err)
	}
	source = string(byteString)

	replaceBpfLogsMacros()
	replaceBpfChunkSizeMacros()
	replaceMaxConnectionMapSize()
	replaceLocalTrafficFilter()
	replaceStrictRemotePortFilter()
	replaceDisablePerfSubmit()
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

	kafkaUtil.StartConfigConsumer()

	stopCh, err := kafkaUtil.SetupPodInformer()
	if err != nil {
		slog.Error("Failed to setup pod watcher", "error", err)
	}

	if kafkaUtil.PodInformerInstance != nil {
		kubePids := kafkaUtil.PodInformerInstance.GetAllKubePids()
		fillExistingConnections(bpfModule, kubePids)
	}

	connectionFactory := connections.NewFactory()

	trafficMetrics.InitTrafficMaps()
	trafficMetrics.StartMetricsTicker()

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

	if err := bpfwrapper.AttachKprobes(bpfModule, hooks); err != nil {
		fmt.Errorf("Error in attaching kprobes %v", err)
	}

	startBPFSubmitStatsReporter(bpfModule)

	processFactory := process.NewFactory()

	var isRunning_2 bool
	var mu_2 = &sync.Mutex{}

	pollInterval := 20 * time.Minute

	trafficUtils.InitVar("UPROBE_POLL_INTERVAL", &pollInterval)

	ssl.InitMaps(bpfModule)

	if captureSsl == "true" || captureAll == "true" {
		go func() {
			slog.Debug("Starting to attach to processes in ticker start")
			ticker := time.NewTicker(pollInterval) // Create a ticker to trigger every minute
			defer ticker.Stop()
			for range ticker.C {
				slog.Debug("Starting to attach to processes in ticker")
				if !isRunning_2 {
					mu_2.Lock()
					if isRunning_2 {
						mu_2.Unlock()
						return
					}
					isRunning_2 = true
					mu_2.Unlock()

					slog.Info("Starting to attach to processes")
					processFactory.AddNewProcessesToProbe(bpfModule)
					slog.Debug("Ended attaching to processes")
					mu_2.Lock()
					isRunning_2 = false
					mu_2.Unlock()
				}
				slog.Debug("Ended attaching to processes in ticker")
			}
			slog.Debug("Ended attaching to processes in ticker end")
		}()
	}

	doProfiling := false
	trafficUtils.InitVar("AKTO_DEBUG_MEM_PROFILING", &doProfiling)

	if doProfiling {
		ticker := time.NewTicker(30 * time.Second) // Create a ticker to trigger every 30 seconds
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

// startBPFSubmitStatsReporter reads BPF_ARRAY socket_data_submit_total every 10s when
// TRAFFIC_LOG_BPF_SOCKET_DATA_SUBMITS=true. Counting stays minimal in kernel (one add per submit);
// windowed logging happens here so we do not bloat the unrolled process_syscall_data loop.
func startBPFSubmitStatsReporter(bpfModule *bcc.Module) {
	logBPFSubmits := false
	trafficUtils.InitVar("TRAFFIC_LOG_BPF_SOCKET_DATA_SUBMITS", &logBPFSubmits)
	if !logBPFSubmits {
		return
	}

	table := bcc.NewTable(bpfModule.TableId("socket_data_submit_total"), bpfModule)
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		var prev uint64
		primed := false
		key := make([]byte, 4)
		for range ticker.C {
			val, err := table.Get(key)
			if err != nil || len(val) < 8 {
				continue
			}
			total := binary.LittleEndian.Uint64(val)
			if !primed {
				prev = total
				primed = true
				continue
			}
			delta := total - prev
			prev = total
			slog.Warn("BPF socket_data perf_submit stats",
				"countInWindow", delta,
				"cumulativeSubmits", total)
		}
	}()
}

func fillExistingConnections(bpfModule *bcc.Module, tracedPids []uint32) {
	connInfoTable := bcc.NewTable(bpfModule.TableId("conn_info_map"), bpfModule)
	connCounterTable := bcc.NewTable(bpfModule.TableId("conn_counter"), bpfModule)
	connInfoMapKeysTable := bcc.NewTable(bpfModule.TableId("conn_info_map_keys"), bpfModule)

	maxConnectionSizeMapSize := 131072
	trafficUtils.InitVar("TRAFFIC_MAX_CONNECTION_MAP_SIZE", &maxConnectionSizeMapSize)

	slog.Info("populating pre-existing connections", "pids", tracedPids)
	conntrack.PopulateExistingConnections(
		tracedPids,
		connInfoTable,
		connCounterTable,
		connInfoMapKeysTable,
		maxConnectionSizeMapSize,
	)
}

// Use this when specific pids tracing is required.
func setupTracePids(bpfModule *bcc.Module) []uint32 {
	kubePidsTable := bcc.NewTable(bpfModule.TableId("kubernetes_pids"), bpfModule)
	var tracedPids []uint32
	if tracePids := os.Getenv("TRACE_PIDS"); tracePids != "" {
		for _, pidStr := range strings.Split(tracePids, ",") {
			pidStr = strings.TrimSpace(pidStr)
			if pidStr == "" {
				continue
			}
			pid, err := strconv.ParseUint(pidStr, 10, 32)
			if err != nil {
				slog.Error("invalid pid in TRACE_PIDS", "pid", pidStr, "error", err)
				continue
			}
			var pidKey [4]byte
			binary.LittleEndian.PutUint32(pidKey[:], uint32(pid))
			if err := kubePidsTable.Set(pidKey[:], []byte{1}); err != nil {
				slog.Error("failed to add pid to kubernetes_pids map", "pid", pid, "error", err)
			} else {
				slog.Info("added pid to kubernetes_pids map", "pid", pid)
				tracedPids = append(tracedPids, uint32(pid))
			}
		}
	} else {
		slog.Warn("TRACE_PIDS env variable not set, no PIDs will be traced")
	}
	return tracedPids
}

func captureMemoryProfile() {
	timestamp := time.Now().Format("20060102_150405")
	fileName := fmt.Sprintf("mem_%s.prof", timestamp)
	f, err := os.Create(fileName)
	if err != nil {
		slog.Error("failed to create memory profile", "error", err)
		return
	}
	defer f.Close()

	pprof.WriteHeapProfile(f)
	slog.Info("memory profile captured", "filename", fileName)
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
