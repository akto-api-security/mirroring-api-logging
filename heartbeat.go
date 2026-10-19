package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/utils"
	"github.com/segmentio/kafka-go"
)

// Heartbeats tell the Akto dashboard this traffic collector is alive. Same message format and topic as the
// k8s_ebpf collector, so mini-runtime's heartbeat consumer and the dashboard module view handle it unchanged.

const heartbeatTopic = "akto.daemonset.producer.heartbeats"
const heartbeatModuleType = "TRAFFIC_COLLECTOR"

var heartbeatIntervalSeconds = 60

// Env keys the dashboard shows for TRAFFIC_COLLECTOR modules (ModuleInfoConstants.ALLOWED_ENV_KEYS_BY_MODULE).
// Only these are sent, so secrets in the environment (e.g. KAFKA_PASSWORD) never leave the collector.
var heartbeatEnvAllowlist = []string{
	"AKTO_KAFKA_BROKER_MAL", "AKTO_KAFKA_BROKER_URL", "AKTO_TRAFFIC_BATCH_SIZE", "AKTO_TRAFFIC_BATCH_TIME_SECS",
	"AKTO_LOG_LEVEL", "DEBUG_URLS", "AKTO_K8_METADATA_CAPTURE", "AKTO_THREAT_ENABLED",
	"AKTO_IGNORE_ENVOY_PROXY_CALLS", "AKTO_IGNORE_IP_TRAFFIC", "AKTO_SYSTEM_CPU_SOFT_CORES",
	"AKTO_SYSTEM_CPU_HARD_CORES", "AKTO_SYSTEM_CPU_SOFT_ADD_CORES", "AKTO_SYSTEM_CPU_HARD_ADD_CORES",
	"AKTO_SYSTEM_CPU_CHECK_INTERVAL_SEC", "AKTO_PAUSE_INGESTION",
}

var heartbeatOnce sync.Once

var (
	lastCPUTime     float64
	lastMeasureTime time.Time
	cpuMutex        sync.Mutex
)

func init() {
	utils.InitVar("KAFKA_HEARTBEAT_INTERVAL_SECONDS", &heartbeatIntervalSeconds)
}

func getDaemonPodName() string {
	if aktoAgentName := os.Getenv("AKTO_AGENT_NAME"); aktoAgentName != "" {
		return fmt.Sprintf("akto-tc:%s", aktoAgentName)
	}
	podName, nodeName := os.Getenv("POD_NAME"), os.Getenv("NODE_NAME")
	if podName != "" && nodeName != "" {
		return fmt.Sprintf("akto-tc:%s:%s", podName, nodeName)
	}
	hostname := os.Getenv("HOSTNAME")
	if hostname == "" && len(collectorId) >= 8 {
		hostname = fmt.Sprintf("daemon-%s", collectorId[:8])
	}
	return fmt.Sprintf("akto-tc:%s", hostname)
}

func getImageVersion() string {
	if imageVersion := os.Getenv("AKTO_IMAGE_VERSION"); imageVersion != "" {
		return imageVersion
	}
	return "aktosecurity/mirror-api-logging:k8s_agent"
}

func getHeartbeatEnv() map[string]string {
	env := make(map[string]string)
	for _, key := range heartbeatEnvAllowlist {
		if value, ok := os.LookupEnv(key); ok {
			env[key] = value
		}
	}
	return env
}

func getCPUUsage() (cpuPercent float64, cpuCoresUsed float64) {
	var rusage syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &rusage)

	totalCPUSec := float64(rusage.Utime.Sec+rusage.Stime.Sec) +
		float64(rusage.Utime.Usec+rusage.Stime.Usec)/1000000

	cpuMutex.Lock()
	defer cpuMutex.Unlock()

	now := time.Now()
	if !lastMeasureTime.IsZero() {
		elapsed := now.Sub(lastMeasureTime).Seconds()
		cpuDelta := totalCPUSec - lastCPUTime
		cpuPercent = (cpuDelta / elapsed) * 100
		cpuCoresUsed = cpuDelta / elapsed
	}
	lastCPUTime = totalCPUSec
	lastMeasureTime = now
	return cpuPercent, cpuCoresUsed
}

func getProfilingData() map[string]interface{} {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	cpuPercent, cpuCoresUsed := getCPUUsage()
	return map[string]interface{}{
		"memory_used_mb":       float64(memStats.Alloc) / 1024 / 1024,
		"memory_total_mb":      float64(memStats.Sys) / 1024 / 1024,
		"memory_cumulative_mb": float64(memStats.TotalAlloc) / 1024 / 1024,
		"cpu_percent":          cpuPercent,
		"cpu_cores_used":       cpuCoresUsed,
		"cpu_cores_total":      runtime.NumCPU(),
		"goroutines":           runtime.NumGoroutine(),
		"num_gc":               memStats.NumGC,
	}
}

func buildHeartbeatMessage(daemonPodName, imageVersion string) map[string]string {
	additionalDataJSON, err := json.Marshal(map[string]interface{}{
		"env":       getHeartbeatEnv(),
		"profiling": getProfilingData(),
	})
	if err != nil {
		slog.Error("Failed to marshal heartbeat additionalData", "error", err)
		additionalDataJSON = []byte("{}")
	}
	return map[string]string{
		"type":           "heartbeat",
		"daemonId":       collectorId,
		"daemonPodName":  daemonPodName,
		"timestamp":      fmt.Sprint(time.Now().Unix()),
		"moduleType":     heartbeatModuleType,
		"imageVersion":   imageVersion,
		"additionalData": string(additionalDataJSON),
	}
}

func sendHeartbeatMessage(ctx context.Context, writer *kafka.Writer, daemonPodName, imageVersion string) {
	out, err := json.Marshal(buildHeartbeatMessage(daemonPodName, imageVersion))
	if err != nil {
		slog.Error("Failed to marshal heartbeat", "error", err)
		return
	}
	if err := writer.WriteMessages(ctx, kafka.Message{Topic: heartbeatTopic, Value: out}); err != nil {
		slog.Error("Failed to send heartbeat to Kafka", "topic", heartbeatTopic, "error", err)
	}
}

// startKafkaHeartbeat starts the heartbeat loop once per process. It uses its own writer, since the traffic
// writer is replaced on every capture reconnect.
func startKafkaHeartbeat() {
	heartbeatOnce.Do(func() {
		if heartbeatIntervalSeconds <= 0 {
			slog.Info("Kafka heartbeat disabled", "interval", heartbeatIntervalSeconds)
			return
		}
		writer := GetKafkaWriter(getKafkaUrl(), heartbeatTopic, 1, 5*time.Second)
		daemonPodName, imageVersion := getDaemonPodName(), getImageVersion()
		slog.Info("Starting Kafka heartbeat", "interval_seconds", heartbeatIntervalSeconds, "daemonPod", daemonPodName, "daemonId", collectorId)

		go func() {
			ctx := context.Background()
			for {
				sendHeartbeatMessage(ctx, writer, daemonPodName, imageVersion)
				jitter := time.Duration(1+rand.Intn(5)) * time.Second
				time.Sleep(time.Duration(heartbeatIntervalSeconds)*time.Second + jitter)
			}
		}()
	})
}
