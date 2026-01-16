package kafkaUtil

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

	"github.com/segmentio/kafka-go"
)

type MessageType string

const (
	MessageTypeEnvReload MessageType = "ENV_RELOAD"
	MessageTypeRestart   MessageType = "RESTART"
)

type TrafficAgentCommandMessage struct {
	MessageType MessageType       `json:"messageType"`
	DaemonNames []string          `json:"daemonNames"`
	Env         map[string]string `json:"env"`
	Timestamp   int64             `json:"timestamp"`
}

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

	cpuPercent, cpuCoresUsed := getCPUUsage()

	profiling := map[string]interface{}{
		"memory_used_mb":  allocMB,
		"memory_total_mb": sysMB,
		"cpu_percent":     cpuPercent,
		"cpu_cores_used":  cpuCoresUsed,
		"cpu_cores_total": runtime.NumCPU(),
		"goroutines":      runtime.NumGoroutine(),
		"num_gc":          memStats.NumGC,
	}

	return profiling
}

func restartSelf() {
	exe, err := os.Executable()
	if err != nil {
		slog.Error("Failed to get executable path", "error", err)
		return
	}

	slog.Warn("Restarting process with new environment...")

	// Replace current process with fresh instance using updated environment
	err = syscall.Exec(exe, os.Args, os.Environ())
	if err != nil {
		slog.Error("Failed to restart process", "error", err)
	}
	// Never reaches here if Exec succeeds
	slog.Debug("Check if the restart enters here")
}

// processCommandMessage handles a single command message
func processCommandMessage(command TrafficAgentCommandMessage) {
	daemonPodName := getDaemonPodName()

	// Check if this message is for this daemon
	isForThisDaemon := false
	for _, daemonName := range command.DaemonNames {
		if daemonName == daemonPodName || daemonName == "ALL" {
			isForThisDaemon = true
			break
		}
	}

	if !isForThisDaemon {
		slog.Debug("Command not for this daemon, ignoring",
			"targetDaemonNames", command.DaemonNames,
			"thisDaemonPodName", daemonPodName)
		return
	}

	slog.Info("Processing command message",
		"messageType", command.MessageType,
		"envCount", len(command.Env))

	if command.MessageType == MessageTypeRestart {
		slog.Info("Restarting process...")
		restartSelf()
		return
	}

	// For ENV_RELOAD: Apply environment variable updates
	if len(command.Env) > 0 {
		for key, value := range command.Env {
			oldValue := os.Getenv(key)
			if oldValue != value {
				slog.Warn("Updating environment variable",
					"key", key,
					"oldValue", oldValue,
					"newValue", value)
				os.Setenv(key, value)
			}
		}
		slog.Info("Environment variables updated successfully restart, Restarting process...")
		restartSelf()
	} else {
		slog.Warn("ENV_RELOAD with no environment variables provided")
	}
}

func StartConfigConsumer() {
	kafka_url := os.Getenv("AKTO_KAFKA_BROKER_MAL")
	if len(kafka_url) == 0 {
		kafka_url = os.Getenv("AKTO_KAFKA_BROKER_URL")
	}

	if kafka_url == "" {
		slog.Warn("Kafka URL not configured, config consumer disabled")
		return
	}

	topic := "akto.config.updates"
	groupID := fmt.Sprintf("ebpf-config-consumer-%s", uniqueDaemonsetId)

	slog.Info("Starting config consumer", "topic", topic, "groupID", groupID, "daemonId", uniqueDaemonsetId)

	// Create Kafka reader (consumer)
	readerConfig := kafka.ReaderConfig{
		Brokers:        []string{kafka_url},
		Topic:          topic,
		GroupID:        groupID,
		MinBytes:       1,
		MaxBytes:       10e6,
		CommitInterval: time.Second,
		StartOffset:    kafka.LastOffset,
	}

	// Apply common TLS and SASL configuration
	readerConfig.Dialer = getKafkaDialer()

	reader := kafka.NewReader(readerConfig)

	// Start consumer goroutine
	go func() {
		defer reader.Close()

		ctx := context.Background()
		for {
			msg, err := reader.ReadMessage(ctx)
			if err != nil {
				slog.Error("Error reading config update message", "error", err)
				continue
			}

			slog.Debug("Received command message", "value", string(msg.Value))

			var command TrafficAgentCommandMessage
			err = json.Unmarshal(msg.Value, &command)
			if err != nil {
				slog.Error("Failed to parse command message", "error", err)
				continue
			}

			processCommandMessage(command)
		}
	}()

	slog.Info("Config consumer started successfully")
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
