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
)

// Heartbeat, ported from trafficUtil/kafkaUtil/ebpf_telemetry.go on feature/k8s_ebpf.

var (
	lastCPUTime     float64
	lastMeasureTime time.Time
	cpuMutex        sync.Mutex
)

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

	allocMB := float64(memStats.Alloc) / 1024 / 1024
	sysMB := float64(memStats.Sys) / 1024 / 1024
	totalAllocMB := float64(memStats.TotalAlloc) / 1024 / 1024

	cpuPercent, cpuCoresUsed := getCPUUsage()

	profiling := map[string]interface{}{
		"memory_used_mb":       allocMB,
		"memory_total_mb":      sysMB,
		"memory_cumulative_mb": totalAllocMB,
		"cpu_percent":          cpuPercent,
		"cpu_cores_used":       cpuCoresUsed,
		"cpu_cores_total":      runtime.NumCPU(),
		"goroutines":           runtime.NumGoroutine(),
		"num_gc":               memStats.NumGC,
	}

	return profiling
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

	slog.Debug("Sending Kafka heartbeat", "daemonPod", daemonPodName, "imageVersion", imageVersion, "heartbeatMessage", heartbeatMessage)
	err = ProduceHeartbeat(ctx, heartbeatMessage)
	if err != nil {
		slog.Error("Failed to send heartbeat to Kafka", "error", err)
	}
}

func sendKafkaHeartbeat() {
	if heartbeatIntervalSeconds <= 0 {
		slog.Info("Kafka heartbeat disabled", "interval", heartbeatIntervalSeconds)
		return
	}

	daemonPodName := getDaemonPodName()
	imageVersion := getImageVersion()

	slog.Debug("Starting Kafka heartbeat routine", "interval_seconds", heartbeatIntervalSeconds, "daemonPod", daemonPodName, "daemonId", uniqueDaemonsetId)
	ctx := context.Background()

	slog.Info("Sending initial heartbeat")
	sendHeartbeatMessage(ctx, daemonPodName, imageVersion)

	for {
		jitter := time.Duration(1+rand.Intn(5)) * time.Second
		sleepDuration := time.Duration(heartbeatIntervalSeconds)*time.Second + jitter

		slog.Debug("Sleeping before next heartbeat", "base_interval", heartbeatIntervalSeconds, "jitter_seconds", jitter.Seconds(), "total_sleep", sleepDuration.Seconds())
		time.Sleep(sleepDuration)

		sendHeartbeatMessage(ctx, daemonPodName, imageVersion)
	}
}
