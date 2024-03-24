package main

import (
	"os"
	"os/signal"

	"log"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	// need an unreleased version of the gobpf library, using from a specific branch, reasoning in the thread below.
	// https://stackoverflow.com/questions/73714654/not-enough-arguments-in-call-to-c2func-bcc-func-load

	"github.com/iovisor/gobpf/bcc"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/bpfwrapper"
	"github.com/akto-api-security/mirroring-api-logging/ebpf/connections"
	"github.com/akto-api-security/mirroring-api-logging/ebpf/utils"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/db"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/kafkaUtil"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/trafficMetrics"
	trafficUtils "github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

var source string = ""

func replaceOpensslMacros() {
	opensslVersion := os.Getenv("OPENSSL_VERSION_AKTO")
	fixed := false
	if len(opensslVersion) > 0 {
		split := strings.Split(opensslVersion, ".")
		if len(split) == 3 {
			if split[0] == "1" && (split[1] == "0" || strings.HasPrefix(split[2], "0")) {
				source = strings.Replace(source, "RBIO_NUM_OFFSET", "0x28", 1)
				fixed = true
			}
		}
	}
	if !fixed {
		source = strings.Replace(source, "RBIO_NUM_OFFSET", "0x30", 1)
	}
}

func replaceBpfLogsMacros() {

	printBpfLogsEnv := os.Getenv("PRINT_BPF_LOGS")
	printBpfLogs := "false"
	if len(printBpfLogsEnv) > 0 && strings.EqualFold(printBpfLogsEnv, "true") {
		printBpfLogs = "true"
	}

	source = strings.Replace(source, "PRINT_BPF_LOGS", printBpfLogs, -1)
}

func main() {
	run()
}

func run() {

	byteString, err := os.ReadFile("./kernel/module.cc")
	if err != nil {
		log.Panic(err)
	}
	source = string(byteString)

	replaceOpensslMacros()
	replaceBpfLogsMacros()

	bpfwrapper.DeleteExistingAktoKernelProbes()

	bpfModule := bcc.NewModule(source, []string{})
	if bpfModule == nil {
		log.Panic("bpf is nil")
	}
	defer bpfModule.Close()

	db.InitMongoClient()
	defer db.CloseMongoClient()
	kafkaUtil.InitKafka()

	logLevel := os.Getenv("LOG_LEVEL")
	if len(logLevel) > 0 {
		logLevelNum, err := strconv.Atoi(logLevel)
		if err == nil {
			utils.SetLogLevel(logLevelNum)
		} else {
			utils.SetLogLevel(1)
		}
	} else {
		utils.SetLogLevel(1)
	}

	inactivityThreshold := 5 * time.Second
	completeThreshold := 5 * time.Second
	maxActiveConnections := 4096
	maxBufferPerTracker := 1 * 1024 * 1024 // 1 MB
	sampleBufferPerMin := -1               // value in MB
	disableEgress := false

	trafficUtils.InitIgnoreVar("TRAFFIC_INACTIVITY_THRESHOLD", &inactivityThreshold)
	trafficUtils.InitIgnoreVar("TRAFFIC_COMPLETE_THRESHOLD", &completeThreshold)
	trafficUtils.InitIgnoreVar("TRAFFIC_MAX_ACTIVE_CONN", &maxActiveConnections)
	trafficUtils.InitIgnoreVar("TRAFFIC_MAX_BUFFER_PER_TRACKER", &maxBufferPerTracker)
	trafficUtils.InitIgnoreVar("TRAFFIC_SAMPLE_BUFFER_PER_MINUTE", &sampleBufferPerMin)
	trafficUtils.InitIgnoreVar("TRAFFIC_DISABLE_EGRESS", &disableEgress)

	connectionFactory := connections.NewFactory(inactivityThreshold, completeThreshold,
		maxActiveConnections, maxBufferPerTracker, sampleBufferPerMin, disableEgress)

	var isRunning bool
	var mu = &sync.Mutex{}

	trafficMetrics.InitTrafficMaps()
	trafficUtils.InitIgnoreVars()
	trafficUtils.InitMemThresh()
	trafficMetrics.StartMetricsTicker()

	kafkaPollInterval := 5 * time.Second

	trafficUtils.InitIgnoreVar("KAFKA_POLL_INTERVAL", &kafkaPollInterval)

	go func() {
		for {
			time.Sleep(kafkaPollInterval)
			if !isRunning {

				mu.Lock()
				if isRunning {
					mu.Unlock()
					return
				}
				isRunning = true
				mu.Unlock()

				connectionFactory.HandleReadyConnections()
				kafkaUtil.LogKafkaError()

				mu.Lock()
				isRunning = false
				mu.Unlock()

			}
		}
	}()

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

	if captureSsl == "true" {
		opensslPath := os.Getenv("OPENSSL_PATH_AKTO")
		if len(opensslPath) > 0 {
			opensslPath = strings.Replace(opensslPath, "usr", "usr_host", 1)
			if len(captureEgress) > 0 && captureEgress == "true" {
				if err := bpfwrapper.AttachUprobes(opensslPath, -1, bpfModule, bpfwrapper.SslHooksEgress); err != nil {
					log.Printf("%s", err.Error())
				}
			} else {
				if err := bpfwrapper.AttachUprobes(opensslPath, -1, bpfModule, bpfwrapper.SslHooks); err != nil {
					log.Printf("%s", err.Error())
				}
			}
		}

		boringLibsslPath := os.Getenv("BSSL_PATH_AKTO")
		if len(boringLibsslPath) > 0 {
			boringLibsslPath = strings.Replace(boringLibsslPath, "usr", "usr_host", 1)
			if err := bpfwrapper.AttachUprobes(boringLibsslPath, -1, bpfModule, bpfwrapper.BoringsslHooks); err != nil {
				log.Printf("%s", err.Error())
			}
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)
	log.Println("Sniffer is ready")
	<-sig
	log.Println("Signaled to terminate")
}