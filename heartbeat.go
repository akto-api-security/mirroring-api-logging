package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/utils"
	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"
)

const moduleType = "TRAFFIC_COLLECTOR"

var (
	heartbeatIntervalSeconds = 60
	uniqueDaemonsetId        = uuid.New().String()

	lastCPUTime     float64
	lastMeasureTime time.Time
	cpuMutex        sync.Mutex
)

func init() {
	utils.InitVar("KAFKA_HEARTBEAT_INTERVAL_SECONDS", &heartbeatIntervalSeconds)
}

func getEnvData() map[string]string {
	envMap := make(map[string]string)
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}
	return envMap
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

// getDaemonPodName derives a stable-ish identity for this agent instance.
func getDaemonPodName() string {
	if aktoAgentName := os.Getenv("AKTO_AGENT_NAME"); aktoAgentName != "" {
		return fmt.Sprintf("akto-tc:%s", aktoAgentName)
	}
	podName := os.Getenv("POD_NAME")
	nodeName := os.Getenv("NODE_NAME")
	if podName != "" && nodeName != "" {
		return fmt.Sprintf("akto-tc:%s:%s", podName, nodeName)
	}
	hostname := os.Getenv("HOSTNAME")
	if hostname == "" {
		hostname = fmt.Sprintf("daemon-%s", uniqueDaemonsetId[:8])
	}
	return fmt.Sprintf("akto-tc:%s", hostname)
}

func getImageVersion() string {
	imageVersion := os.Getenv("AKTO_IMAGE_VERSION")
	if imageVersion == "" {
		imageVersion = "aktosecurity/mirror-api-logging:filter-header"
	}
	return imageVersion
}

// ProduceHeartbeat writes a heartbeat to the heartbeat topic using the shared writer.
func ProduceHeartbeat(ctx context.Context, heartbeatData map[string]string) error {
	writer := kafkaWriter
	if writer == nil {
		slog.Warn("Kafka writer not ready, skipping heartbeat")
		return nil
	}

	out, err := json.Marshal(heartbeatData)
	if err != nil {
		return err
	}

	topic := "akto.daemonset.producer.heartbeats"
	msg := kafka.Message{
		Topic: topic,
		Value: out,
	}

	if err := writer.WriteMessages(ctx, msg); err != nil {
		slog.Error("ERROR while writing heartbeat messages", "topic", topic, "error", err)
		return err
	}
	return nil
}

func sendHeartbeatMessage(ctx context.Context, daemonPodName, imageVersion string) {
	additionalData := map[string]interface{}{
		"env":       getEnvData(),
		"profiling": getProfilingData(),
	}

	additionalDataJSON, err := json.Marshal(additionalData)
	if err != nil {
		slog.Error("Failed to marshal additionalData", "error", err)
		additionalDataJSON = []byte("{}")
	}

	heartbeatMessage := map[string]string{
		"type":           "heartbeat",
		"daemonId":       uniqueDaemonsetId,
		"daemonPodName":  daemonPodName,
		"timestamp":      fmt.Sprint(time.Now().Unix()),
		"moduleType":     moduleType,
		"imageVersion":   imageVersion,
		"additionalData": string(additionalDataJSON),
	}

	slog.Debug("Sending Kafka heartbeat", "daemonPod", daemonPodName, "imageVersion", imageVersion)
	if err := ProduceHeartbeat(ctx, heartbeatMessage); err != nil {
		slog.Error("Failed to send heartbeat to Kafka", "error", err)
	}
}

// sendKafkaHeartbeat periodically ships env + profiling data as a heartbeat.
// Runs forever; intended to be launched as a goroutine.
func sendKafkaHeartbeat() {
	if heartbeatIntervalSeconds <= 0 {
		slog.Info("Kafka heartbeat disabled", "interval", heartbeatIntervalSeconds)
		return
	}

	daemonPodName := getDaemonPodName()
	imageVersion := getImageVersion()
	ctx := context.Background()

	slog.Info("Starting Kafka heartbeat routine", "interval_seconds", heartbeatIntervalSeconds, "daemonPod", daemonPodName, "daemonId", uniqueDaemonsetId)
	sendHeartbeatMessage(ctx, daemonPodName, imageVersion)

	for {
		jitter := time.Duration(1+rand.Intn(5)) * time.Second
		sleepDuration := time.Duration(heartbeatIntervalSeconds)*time.Second + jitter
		time.Sleep(sleepDuration)
		sendHeartbeatMessage(ctx, daemonPodName, imageVersion)
	}
}
