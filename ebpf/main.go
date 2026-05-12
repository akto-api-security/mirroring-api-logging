package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/pprof"
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

const socketDataRingbufShardCount = 8

func replaceBpfLogsMacros(spec *ebpf.CollectionSpec) {
	var printBpfLogs bool
	trafficUtils.InitVar("PRINT_BPF_LOGS", &printBpfLogs)
	if v, ok := spec.Variables["print_bpf_logs"]; ok {
		if err := v.Set(printBpfLogs); err != nil {
			slog.Warn("failed to set print_bpf_logs variable", "error", err)
		}
	}

	var logSocketDataSubmitStats bool
	trafficUtils.InitVar("TRAFFIC_LOG_BPF_SOCKET_DATA_SUBMITS", &logSocketDataSubmitStats)
	if v, ok := spec.Variables["log_socket_data_submit_stats"]; ok {
		if err := v.Set(logSocketDataSubmitStats); err != nil {
			slog.Warn("failed to set log_socket_data_submit_stats variable", "error", err)
		}
	}

	var filterLocalTraffic bool
	trafficUtils.InitVar("FILTER_LOCAL_TRAFFIC", &filterLocalTraffic)
	if v, ok := spec.Variables["filter_local_traffic"]; ok {
		if err := v.Set(filterLocalTraffic); err != nil {
			slog.Warn("failed to set filter_local_traffic variable", "error", err)
		}
	}

	// 127.0.0.1 as little-endian u32: 127 + 0<<8 + 0<<16 + 1<<24 = 16777343
	localTrafficIpLE := 16777343
	trafficUtils.InitVar("LOCAL_TRAFFIC_IP_LE", &localTrafficIpLE)
	if v, ok := spec.Variables["local_traffic_ip"]; ok {
		if err := v.Set(uint32(localTrafficIpLE)); err != nil {
			slog.Warn("failed to set local_traffic_ip variable", "error", err)
		}
	}
	slog.Info("BPF local traffic filter", "filterLocalTraffic", filterLocalTraffic, "localTrafficIpLE", localTrafficIpLE)
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

// replaceRingBufSizes overrides ring buffer max_entries from env vars (in MB).
// Values must be powers of 2; the BPF C defaults are used when env vars are unset.
func replaceRingBufSizes(spec *ebpf.CollectionSpec) {
	dataTotalMB := 512
	trafficUtils.InitVar("TRAFFIC_RINGBUF_DATA_MB", &dataTotalMB)
	if dataTotalMB > 0 {
		if dataTotalMB%socketDataRingbufShardCount != 0 {
			slog.Warn("data ring buffer total size must divide evenly across shards, ignoring", "sizeMB", dataTotalMB, "shards", socketDataRingbufShardCount)
		} else {
			dataShardMB := dataTotalMB / socketDataRingbufShardCount
			sizeBytes := uint32(dataShardMB) * 1024 * 1024
			if sizeBytes&(sizeBytes-1) != 0 {
				slog.Warn("data ring buffer shard size must be a power of 2, ignoring", "sizeMB", dataShardMB)
			} else {
				for i := 0; i < socketDataRingbufShardCount; i++ {
					mapName := fmt.Sprintf("socket_data_events_%d", i)
					m, ok := spec.Maps[mapName]
					if !ok {
						continue
					}
					m.MaxEntries = sizeBytes
					slog.Info("data ring buffer shard size overridden", "map", mapName, "sizeMB", dataShardMB)
				}
			}
		}
	}

	type rbConf struct {
		envVar    string
		mapName   string
		defaultMB int
	}
	confs := []rbConf{
		{"TRAFFIC_RINGBUF_OPEN_MB", "socket_open_events", 64},
		{"TRAFFIC_RINGBUF_CLOSE_MB", "socket_close_events", 64},
	}
	for _, c := range confs {
		sizeMB := c.defaultMB
		trafficUtils.InitVar(c.envVar, &sizeMB)
		if sizeMB <= 0 {
			continue
		}
		m, ok := spec.Maps[c.mapName]
		if !ok {
			continue
		}
		sizeBytes := uint32(sizeMB) * 1024 * 1024
		if sizeBytes&(sizeBytes-1) != 0 {
			slog.Warn("ring buffer size must be a power of 2, ignoring", "map", c.mapName, "sizeMB", sizeMB)
			continue
		}
		m.MaxEntries = sizeBytes
		slog.Info("ring buffer size overridden", "map", c.mapName, "sizeMB", sizeMB)
	}
}

// replaceStrictRemotePortFilter gates socket_data on conn_info->port (remote / dest port in BPF).
// When TRAFFIC_STRICT_REMOTE_PORT_FILTER is true, events for connections whose port != STRICT_REMOTE_PORT
// are dropped (default port 10275).
func replaceStrictRemotePortFilter(spec *ebpf.CollectionSpec) {
	var filterOn bool
	trafficUtils.InitVar("TRAFFIC_STRICT_REMOTE_PORT_FILTER", &filterOn)
	if v, ok := spec.Variables["filter_strict_remote_port"]; ok {
		if err := v.Set(filterOn); err != nil {
			slog.Warn("failed to set filter_strict_remote_port variable", "error", err)
		}
	}

	strictPort := 10275
	trafficUtils.InitVar("TRAFFIC_STRICT_REMOTE_PORT", &strictPort)
	if strictPort < 0 {
		strictPort = 0
	}
	if strictPort > 65535 {
		strictPort = 65535
	}
	if v, ok := spec.Variables["strict_remote_port"]; ok {
		if err := v.Set(uint16(strictPort)); err != nil {
			slog.Warn("failed to set strict_remote_port variable", "error", err)
		}
	}
}

// replaceDisableRingSubmit sets the BPF global disable_ring_submit to true/false.
// When true (env TRAFFIC_DISABLE_PERF_SUBMIT), BPF skips all ringbuf_output calls.
func replaceDisableRingSubmit(spec *ebpf.CollectionSpec) {
	var disableRingSubmit bool
	trafficUtils.InitVar("TRAFFIC_DISABLE_PERF_SUBMIT", &disableRingSubmit)
	if v, ok := spec.Variables["disable_ring_submit"]; ok {
		if err := v.Set(disableRingSubmit); err != nil {
			slog.Warn("failed to set disable_ring_submit variable", "error", err)
		}
	}
}

// startSocketDataSubmitStatsReporter reads BPF submit counters every 10s when
// TRAFFIC_LOG_BPF_SOCKET_DATA_SUBMITS=true. The kernel increments these around
// ringbuf_output, so failures indicate event loss before userspace can read.
func startSocketDataSubmitStatsReporter(coll *ebpf.Collection) {
	var logBPFSubmits bool
	trafficUtils.InitVar("TRAFFIC_LOG_BPF_SOCKET_DATA_SUBMITS", &logBPFSubmits)
	if !logBPFSubmits {
		return
	}

	type counterSpec struct {
		name string
		m    *ebpf.Map
		prev uint64
		seen bool
	}
	counterNames := []string{
		"socket_data_submit_total",
		"socket_data_submit_failed_total",
		"socket_open_submit_total",
		"socket_open_submit_failed_total",
		"socket_close_submit_total",
		"socket_close_submit_failed_total",
	}
	counters := make([]counterSpec, 0, len(counterNames))
	for _, name := range counterNames {
		m, ok := coll.Maps[name]
		if !ok {
			slog.Warn("BPF submit counter map not found; rebuild kernel/module.bpf.o with latest module.bpf.c", "map", name)
			continue
		}
		counters = append(counters, counterSpec{name: name, m: m})
	}
	if len(counters) == 0 {
		return
	}

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		key := uint32(0)
		for range ticker.C {
			args := make([]any, 0, 2+len(counters)*2)
			for i := range counters {
				var total uint64
				if err := counters[i].m.Lookup(key, &total); err != nil {
					continue
				}
				delta := uint64(0)
				if counters[i].seen {
					delta = total - counters[i].prev
				}
				counters[i].prev = total
				counters[i].seen = true
				args = append(args,
					counters[i].name+"Delta", delta,
					counters[i].name+"Total", total,
				)
			}
			if len(args) == 0 {
				continue
			}
			slog.Warn("BPF ringbuf submit stats", args...)
		}
	}()
}

func startEBPFMapMemoryReporter(coll *ebpf.Collection) {
	var logMapMemory bool
	trafficUtils.InitVar("TRAFFIC_LOG_EBPF_MAP_MEMORY", &logMapMemory)
	if !logMapMemory {
		return
	}

	interval := 30 * time.Second
	trafficUtils.InitVar("TRAFFIC_EBPF_MAP_MEMORY_INTERVAL", &interval)

	mapNames := []string{
		"socket_data_events_0",
		"socket_data_events_1",
		"socket_data_events_2",
		"socket_data_events_3",
		"socket_data_events_4",
		"socket_data_events_5",
		"socket_data_events_6",
		"socket_data_events_7",
		"socket_open_events",
		"socket_close_events",
		"socket_data_submit_total",
		"socket_data_submit_failed_total",
		"socket_open_submit_total",
		"socket_open_submit_failed_total",
		"socket_close_submit_total",
		"socket_close_submit_failed_total",
		"system_cpu_ingest_paused",
		"conn_info_map",
		"conn_info_map_keys",
		"active_ssl_read_args_map",
		"active_ssl_write_args_map",
		"node_tlswrap_symaddrs_map",
		"active_TLSWrap_memfn_this",
		"node_ssl_tls_wrap_map",
		"go_symaddrs_table",
		"active_tls_conn_op_map",
	}

	logEBPFMapMemorySnapshot(coll, mapNames)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			logEBPFMapMemorySnapshot(coll, mapNames)
		}
	}()
}

func logEBPFMapMemorySnapshot(coll *ebpf.Collection, mapNames []string) {
	var totalMemlockBytes uint64
	var totalMemorySizeBytes uint64
	var mapsReported int

	for _, name := range mapNames {
		m, ok := coll.Maps[name]
		if !ok {
			continue
		}

		info, err := m.Info()
		if err != nil {
			slog.Warn("failed to read BPF map info", "map", name, "error", err)
			continue
		}

		memlockBytes, hasMemlock := info.Memlock()
		if hasMemlock {
			totalMemlockBytes += memlockBytes
		}

		var memorySizeBytes uint32
		hasMemory := false
		if memory, err := m.Memory(); err == nil {
			memorySizeBytes = memory.Size()
			hasMemory = true
			totalMemorySizeBytes += uint64(memorySizeBytes)
		}

		mapsReported++
		slog.Warn("BPF map memory stats",
			"map", name,
			"type", info.Type,
			"keySize", info.KeySize,
			"valueSize", info.ValueSize,
			"maxEntries", info.MaxEntries,
			"flags", info.Flags,
			"memlockBytes", memlockBytes,
			"hasMemlock", hasMemlock,
			"memorySizeBytes", memorySizeBytes,
			"hasMemory", hasMemory,
		)
	}

	slog.Warn("BPF map memory stats summary",
		"mapsReported", mapsReported,
		"totalMemlockBytes", totalMemlockBytes,
		"totalMemorySizeBytes", totalMemorySizeBytes,
	)
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
	var bpfObjPathOverride string
	trafficUtils.InitVar("BPF_OBJ_PATH", &bpfObjPathOverride)
	if bpfObjPathOverride != "" {
		bpfObjPath = bpfObjPathOverride
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
	replaceRingBufSizes(spec)
	replaceStrictRemotePortFilter(spec)
	replaceDisableRingSubmit(spec)

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

	startSocketDataSubmitStatsReporter(coll)
	startEBPFMapMemoryReporter(coll)

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

	startHostSystemCPULimitMonitor(coll)

	// -----------------------------------------------------------------------
	// Ring-buffer consumers — launched before kprobes so buffers are ready.
	// -----------------------------------------------------------------------
	callbacks := []*bpfwrapper.ProbeChannel{
		bpfwrapper.NewProbeChannel("socket_open_events", bpfwrapper.SocketOpenEventCallback),
		bpfwrapper.NewProbeChannel("socket_close_events", bpfwrapper.SocketCloseEventCallback),
	}
	for i := 0; i < socketDataRingbufShardCount; i++ {
		callbacks = append(callbacks, bpfwrapper.NewProbeChannel(
			fmt.Sprintf("socket_data_events_%d", i),
			bpfwrapper.SocketDataEventCallback,
		))
	}
	if err := bpfwrapper.LaunchPerfBufferConsumers(coll, connectionFactory, callbacks); err != nil {
		slog.Error("failed to launch perf buffer consumers", "error", err)
		panic(err)
	}

	// -----------------------------------------------------------------------
	// Kprobe attachment.
	// -----------------------------------------------------------------------
	captureSsl := ""
	captureEgress := ""
	captureAll := "true"
	trafficUtils.InitVar("CAPTURE_SSL", &captureSsl)
	trafficUtils.InitVar("CAPTURE_EGRESS", &captureEgress)
	trafficUtils.InitVar("CAPTURE_ALL", &captureAll)

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
	if captureSsl == "true" || captureAll == "true" {
		go func() {
			slog.Debug("Starting uprobe process ticker")
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
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			captureMemoryProfile()
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
