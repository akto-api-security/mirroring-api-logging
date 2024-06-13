package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strconv"

	"log"
	"strings"
	"sync"
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

func replaceBpfLogsMacros(source string) string {

	printBpfLogsEnv := os.Getenv("PRINT_BPF_LOGS")
	printBpfLogs := "false"
	if len(printBpfLogsEnv) > 0 && strings.EqualFold(printBpfLogsEnv, "true") {
		printBpfLogs = "true"
	}

	source = strings.Replace(source, "PRINT_BPF_LOGS", printBpfLogs, -1)
	return source
}

func replaceMaxConnectionMapSize(source string) string {
	maxConnectionSizeMapSize := 131072
	trafficUtils.InitVar("TRAFFIC_MAX_CONNECTION_MAP_SIZE", &maxConnectionSizeMapSize)
	maxConnectionSizeMapSizeStr := strconv.Itoa(maxConnectionSizeMapSize)
	source = strings.Replace(source, "TRAFFIC_MAX_CONNECTION_MAP_SIZE", maxConnectionSizeMapSizeStr, -1)
	return source
}

func replaceArchType(source string) string {
	arch := runtime.GOARCH
	archStr := "TARGET_ARCH_X86_64"
	if strings.Contains(arch, "arm") {
		archStr = "TARGET_ARCH_AARCH64"
	}
	fmt.Printf("arch type detected: %v\n", arch)
	source = strings.Replace(source, "ARCH_TYPE", archStr, -1)
	return source
}

func main() {
	run()
}

func run() {

	byteString, err := os.ReadFile("./kernel/module.cc")
	if err != nil {
		log.Panic(err)
	}
	source := string(byteString)

	source = replaceArchType(source)
	source = replaceBpfLogsMacros(source)
	source = replaceMaxConnectionMapSize(source)

	bpfwrapper.DeleteExistingAktoKernelProbes()

	bpfModule := bcc.NewModule(source, []string{})
	if bpfModule == nil {
		log.Panic("bpf is nil")
	}
	defer bpfModule.Close()

	db.InitMongoClient()
	defer db.CloseMongoClient()
	kafkaUtil.InitKafka()
	defer kafkaUtil.Close()

	connectionFactory := connections.NewFactory()

	var isRunning bool
	var mu = &sync.Mutex{}

	trafficMetrics.InitTrafficMaps()
	trafficMetrics.StartMetricsTicker()

	kafkaPollInterval := 500 * time.Millisecond

	trafficUtils.InitVar("KAFKA_POLL_INTERVAL", &kafkaPollInterval)

	callbacks := make([]*bpfwrapper.ProbeChannel, 0)

	captureSsl := os.Getenv("CAPTURE_SSL")
	captureEgress := os.Getenv("CAPTURE_EGRESS")

	hooks := make([]bpfwrapper.Kprobe, 0)
	callbacks = append(callbacks, bpfwrapper.NewProbeChannel("socket_open_events", bpfwrapper.SocketOpenEventCallback))
	hooks = append(hooks, bpfwrapper.Level1hooks...)
	hooks = append(hooks, bpfwrapper.Level1hooksType2...)
	callbacks = append(callbacks, bpfwrapper.NewProbeChannel("socket_data_events", bpfwrapper.SocketDataEventCallback))
	if len(captureSsl) == 0 || captureSsl == "false" {
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
		log.Panic(err)
	}

	processFactory := process.NewFactory()

	var isRunning_2 bool
	var mu_2 = &sync.Mutex{}

	pollInterval := 5 * time.Minute

	trafficUtils.InitVar("UPROBE_POLL_INTERVAL", &pollInterval)

	ssl.InitMaps(bpfModule)

	if captureSsl == "true" {
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

					fmt.Printf("Entering\n")
					processFactory.AddNewProcessesToProbe(bpfModule)
					fmt.Printf("Exiting\n")
					mu_2.Lock()
					isRunning_2 = false
					mu_2.Unlock()
				}
				time.Sleep(pollInterval)
			}
		}()
	}

	stopped := false
	go func() {
		for {
			time.Sleep(kafkaPollInterval)
			if stopped {
				log.Println("resetting probe")
				kafkaUtil.InitKafka()
				connectionFactory.StartAgain()
				stopped = false
				continue
			}
			if !isRunning {

				mu.Lock()
				if isRunning {
					mu.Unlock()
					return
				}
				isRunning = true
				mu.Unlock()

				err := connectionFactory.HandleReadyConnections()
				if err != nil {
					fmt.Printf("Error: %v\n", err.Error())
					stopped = true
					kafkaUtil.Close()
					trafficMetrics.InitTrafficMaps()
					log.Println("sleeping....")
					time.Sleep(10 * time.Second)
					log.Println("SLEPT")
				} else {
					kafkaUtil.LogKafkaError()
				}

				mu.Lock()
				isRunning = false
				mu.Unlock()
			}
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)
	log.Println("Sniffer is ready")
	<-sig
	log.Println("Signaled to terminate")
}
