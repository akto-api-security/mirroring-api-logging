package main

import (
	"fmt"
	"os"
	"os/signal"
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

func replaceMaxConnectionMapSize() {
	maxConnectionSizeMapSize := 131072
	trafficUtils.InitVar("TRAFFIC_MAX_CONNECTION_MAP_SIZE", &maxConnectionSizeMapSize)
	maxConnectionSizeMapSizeStr := strconv.Itoa(maxConnectionSizeMapSize)
	source = strings.Replace(source, "TRAFFIC_MAX_CONNECTION_MAP_SIZE", maxConnectionSizeMapSizeStr, -1)
}

func main() {
	run()
}

type go_symaddrs struct {
	a int64
	b int64
	c uint32
	d uint64
}

func run() {

	byteString, err := os.ReadFile("./kernel/module.cc")
	if err != nil {
		log.Panic(err)
	}
	source = string(byteString)

	replaceOpensslMacros()
	replaceBpfLogsMacros()
	replaceMaxConnectionMapSize()

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

	var isRunning bool
	var mu = &sync.Mutex{}

	trafficMetrics.InitTrafficMaps()
	trafficMetrics.StartMetricsTicker()

	kafkaPollInterval := 500 * time.Millisecond

	trafficUtils.InitVar("KAFKA_POLL_INTERVAL", &kafkaPollInterval)

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

	processFactory := process.NewFactory()

	var isRunning_2 bool
	var mu_2 = &sync.Mutex{}

	pollInterval := 1 * time.Minute

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

	// fmt.Printf("TableSize : %v %v", bpfModule.TableSize(), bpfModule.TableId("two_way_map"))

	// str := go_symaddrs{
	// 	a: 1,
	// 	b: -23,
	// 	c: 231232,
	// 	d: 231,
	// }

	// const sz = int(unsafe.Sizeof(go_symaddrs{}))
	// var asByteSlice []byte = (*(*[sz]byte)(unsafe.Pointer(&str)))[:]

	// // ptr := unsafe.Pointer(&str)

	// key, _ := table.KeyStrToBytes("1")

	// key2, _ := table.KeyStrToBytes("1232424")
	// // leaf, _ := table.LeafStrToBytes("11")
	// // key1 := 1
	// // keyPtr := unsafe.Pointer(&key1)

	// if err := table.Set(key, asByteSlice); err != nil {
	// 	fmt.Errorf("table.Set key 1 failed: %v", err)
	// }

	// str.c = 1223
	// str.a = -234
	// asByteSlice = (*(*[sz]byte)(unsafe.Pointer(&str)))[:]

	// if err := table.Set(key2, asByteSlice); err != nil {
	// 	fmt.Errorf("table.Set key 1232424 failed: %v", err)
	// }

	goTLSPath := os.Getenv("GO_TLS_PATH")
	if len(goTLSPath) > 0 {
		if err := bpfwrapper.AttachUprobes(goTLSPath, -1, bpfModule, bpfwrapper.GoTlsHooks); err != nil {
			log.Printf("%s", err.Error())
		}
	}

	if captureSsl == "true" {
		opensslPath := os.Getenv("OPENSSL_PATH_AKTO")
		if len(opensslPath) > 0 {
			// opensslPath = strings.Replace(opensslPath, "usr", "usr_host", 1)
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

		opensslPath = os.Getenv("OPENSSL_PATH_AKTO_2")
		if len(opensslPath) > 0 {
			// opensslPath = strings.Replace(opensslPath, "usr", "usr_host", 1)
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
			// boringLibsslPath = strings.Replace(boringLibsslPath, "usr", "usr_host", 1)
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
