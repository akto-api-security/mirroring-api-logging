package kafkaUtil

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
	"github.com/segmentio/kafka-go"
)

type MessageType string

const (
	MessageTypeEnvReload MessageType = "ENV_RELOAD"
	MessageTypeRestart   MessageType = "RESTART"
)

type TrafficAgentCommandMessage struct {
	MessageType  MessageType                  `json:"messageType"`
	DaemonNames  []string                     `json:"daemonNames"`
	Env          map[string]string            `json:"env"`
	DaemonEnvMap map[string]map[string]string `json:"daemonEnvMap"`
	Timestamp    int64                        `json:"timestamp"`
}

var (
	lastCPUTime     float64
	lastMeasureTime time.Time
	cpuMutex        sync.Mutex
)

var hostSystemCPUSampler = utils.NewHostSystemCPUSampler()

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
	systemCPUPct, _, _ := hostSystemCPUSampler.Step()

	profiling := map[string]interface{}{
		"memory_used_mb":       allocMB,
		"memory_total_mb":      sysMB,
		"memory_cumulative_mb": totalAllocMB,
		"cpu_percent":          cpuPercent,
		"cpu_cores_used":       cpuCoresUsed,
		"cpu_cores_total":      runtime.NumCPU(),
		"goroutines":           runtime.NumGoroutine(),
		"num_gc":               memStats.NumGC,
		"system_cpu_percent":   systemCPUPct,
	}

	return profiling
}

func writeEnvFile() error {
	dir := "/ebpf"
	finalPath := "/ebpf/.env"
	tmpPath := "/ebpf/.env.tmp"

	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	var content strings.Builder

	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		key := parts[0]
		val := parts[1]

		// Proper shell escaping
		escapedVal := strconv.Quote(val)

		content.WriteString("export ")
		content.WriteString(key)
		content.WriteString("=")
		content.WriteString(escapedVal)
		content.WriteString("\n")
	}

	err := os.WriteFile(tmpPath, []byte(content.String()), 0644)
	if err != nil {
		slog.Error("Failed to write environment file", "path", tmpPath, "error", err)
		return err
	}
	slog.Debug("Environment variables written to file", "path", tmpPath)
	// Atomic replace
	err = os.Rename(tmpPath, finalPath)
	if err != nil {
		slog.Error("Failed to rename environment file", "path", tmpPath, "error", err)
		return err
	}
	slog.Debug("Environment variables renamed to file", "path", finalPath)
	return nil
}

func restartSelf() {
	slog.Warn("Restarting process with new environment...")

	// Write current environment to file so shell script can source it on next restart
	writeEnvFile()

	// Exit and let shell script restart with fresh process
	os.Exit(0)
}

// processCommandMessage handles a single command message
func processCommandMessage(command TrafficAgentCommandMessage) {
	daemonPodName := getDaemonPodName()

	if command.MessageType == MessageTypeRestart {
		_, ok := command.DaemonEnvMap[daemonPodName]
		if !ok {
			_, ok = command.DaemonEnvMap["ALL"]
		}
		if !ok {
			slog.Debug("Restart command not for this daemon, ignoring",
				"thisDaemonPodName", daemonPodName)
			return
		}
		slog.Warn("Restarting process...")
		restartSelf()
		return
	}

	if command.MessageType == MessageTypeEnvReload {
		// Resolve env vars for this daemon: prefer pod-specific entry, fall back to "ALL"
		envVars, ok := command.DaemonEnvMap[daemonPodName]
		if !ok {
			envVars, ok = command.DaemonEnvMap["ALL"]
		}
		if !ok {
			slog.Debug("ENV_RELOAD not targeted at this daemon, ignoring",
				"thisDaemonPodName", daemonPodName)
			return
		}

		slog.Info("Processing ENV_RELOAD command",
			"thisDaemonPodName", daemonPodName,
			"envCount", len(envVars))

		if len(envVars) == 0 {
			slog.Warn("ENV_RELOAD with no environment variables provided for this daemon")
			return
		}

		for key, value := range envVars {
			oldValue := os.Getenv(key)
			if oldValue != value {
				slog.Warn("Updating environment variable",
					"key", key,
					"oldValue", oldValue,
					"newValue", value)
				os.Setenv(key, value)
			}
		}
		slog.Info("Environment variables updated, restarting process...")
		restartSelf()
		return
	}

	slog.Warn("Unknown message type, ignoring", "messageType", command.MessageType)
}

func StartConfigConsumer() {
	if KafkaDisabled() {
		slog.Warn("Kafka disabled (AKTO_KAFKA_DISABLED), config consumer not started")
		return
	}

	kafka_url := KafkaBrokerURL()

	if kafka_url == "" {
		slog.Warn("Kafka URL not configured, config consumer disabled")
		return
	}

	topic := "akto.config.updates"
	groupID := fmt.Sprintf("ebpf-config-consumer-%s", getDaemonPodName())

	utils.PrintLog("Starting config consumer", "topic", topic, "groupID", groupID, "daemonId", uniqueDaemonsetId)

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
			msg, err := reader.FetchMessage(ctx)
			if err != nil {
				slog.Error("Error reading config update message", "error", err)
				continue
			}

			slog.Debug("Received command message", "value", string(msg.Value))

			var command TrafficAgentCommandMessage
			err = json.Unmarshal(msg.Value, &command)
			if err != nil {
				slog.Error("Failed to parse command message", "error", err)
				if err := reader.CommitMessages(ctx, msg); err != nil {
					slog.Error("Failed to commit unparseable message", "error", err)
				}
				continue
			}

			if err := reader.CommitMessages(ctx, msg); err != nil {
				slog.Error("Failed to commit message offset", "error", err)
			}

			slog.Debug("Received command message", "value", string(msg.Value))
			processCommandMessage(command)
		}
	}()

	utils.PrintLog("Config consumer started successfully")
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

	utils.PrintLog("Sending Kafka heartbeat", "daemonPod", daemonPodName, "imageVersion", imageVersion, "heartbeatMessage", heartbeatMessage)
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

	utils.PrintLog("Starting Kafka heartbeat routine", "interval_seconds", heartbeatIntervalSeconds, "daemonPod", daemonPodName, "daemonId", uniqueDaemonsetId)
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
