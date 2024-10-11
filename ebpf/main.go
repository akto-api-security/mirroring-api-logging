package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"strconv"
	"sync"

	"log"
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
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/db"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/kafkaUtil"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/trafficMetrics"
	trafficUtils "github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

var source string = ""

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
	fmt.Printf("arch type detected: %v\n", arch)
	if strings.Contains(arch, "arm") {
		return true
	}
	return false
}

func isAmdArch() bool {
	arch := runtime.GOARCH
	fmt.Printf("arch type detected: %v\n", arch)
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

	byteString, err := os.ReadFile("./kernel/module.cc")
	if err != nil {
		log.Panic(err)
	}
	source = string(byteString)

	replaceBpfLogsMacros()
	replaceMaxConnectionMapSize()
	replaceArchType()

	bpfwrapper.DeleteExistingAktoKernelProbes()

	bpfModule := bcc.NewModule(source, []string{})
	if bpfModule == nil {
		log.Panic("bpf is nil")
	}
	defer bpfModule.Close()

	db.InitMongoClient()
	defer db.CloseMongoClient()
	kafkaUtil.InitKafka()

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
		log.Panic(err)
	}

	if err := bpfwrapper.AttachKprobes(bpfModule, hooks); err != nil {
		fmt.Errorf("Error in attaching kprobes %v", err)
	}

	processFactory := process.NewFactory()

	var isRunning_2 bool
	var mu_2 = &sync.Mutex{}

	pollInterval := 5 * time.Minute

	trafficUtils.InitVar("UPROBE_POLL_INTERVAL", &pollInterval)

	ssl.InitMaps(bpfModule)

	if captureSsl == "true" || captureAll == "true" {
		go func() {
			for {
				if !isRunning_2 {
					mu_2.Lock()
					if isRunning_2 {
						mu_2.Unlock()
						return
					}
					isRunning_2 = true
					mu_2.Unlock()

					fmt.Printf("Starting to attach to processes\n")
					processFactory.AddNewProcessesToProbe(bpfModule)
					fmt.Printf("Ended attaching to processes\n")
					mu_2.Lock()
					isRunning_2 = false
					mu_2.Unlock()
				}
				time.Sleep(pollInterval)
			}
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

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)
	log.Println("Sniffer is ready")
	<-sig
	log.Println("Signaled to terminate")
}

func captureMemoryProfile() {
	f, _ := os.Create("mem.prof") // Create memory profile file
	defer f.Close()

	pprof.WriteHeapProfile(f) // Write memory profile
}
