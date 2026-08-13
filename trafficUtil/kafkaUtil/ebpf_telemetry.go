package kafkaUtil

import (
	"context"
	"encoding/json"
	"errors"
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

// shellSingleQuote wraps s in single quotes so it can be safely sourced by a
// POSIX shell. Values containing $, backticks, spaces, etc. are treated
// literally; an embedded single quote is escaped as '\'' (close-quote, an
// escaped literal quote, reopen-quote).
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
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
		if len(parts) != 2 {
			continue
		}
		key := parts[0]
		val := parts[1]

		content.WriteString("export ")
		content.WriteString(key)
		content.WriteString("=")
		content.WriteString(shellSingleQuote(val))
		content.WriteString("\n")
	}

	// 0600: this file contains the full process environment, including secrets.
	if err := os.WriteFile(tmpPath, []byte(content.String()), 0600); err != nil {
		slog.Error("Failed to write environment file", "path", tmpPath, "error", err)
		return err
	}
	slog.Debug("Environment variables written to file", "path", tmpPath)
	// Atomic replace
	if err := os.Rename(tmpPath, finalPath); err != nil {
		slog.Error("Failed to rename environment file", "path", tmpPath, "error", err)
		return err
	}
	slog.Debug("Environment variables renamed to file", "path", finalPath)
	return nil
}

// closeReaderWithTimeout closes the consumer-group reader — which sends a
// LeaveGroup to the coordinator so the next generation isn't starved waiting
// for this member's session to expire — without blocking shutdown longer than d.
func closeReaderWithTimeout(reader *kafka.Reader, d time.Duration) {
	done := make(chan struct{})
	go func() {
		if err := reader.Close(); err != nil {
			slog.Error("Error closing config reader", "error", err)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
		slog.Warn("Timed out waiting for config reader to close (LeaveGroup)")
	}
}

// processCommandMessage applies a single command message and reports whether
// the process should restart. It performs no Kafka I/O and never exits, so the
// caller can persist the effect and commit the offset before restarting.
func processCommandMessage(command TrafficAgentCommandMessage) (restart bool) {
	daemonPodName := getDaemonPodName()

	if command.MessageType == MessageTypeRestart {
		_, ok := command.DaemonEnvMap[daemonPodName]
		if !ok {
			_, ok = command.DaemonEnvMap["ALL"]
		}
		if !ok {
			slog.Debug("Restart command not for this daemon, ignoring",
				"thisDaemonPodName", daemonPodName)
			return false
		}
		slog.Info("Restart command received")
		return true
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
			return false
		}

		slog.Info("Processing ENV_RELOAD command",
			"thisDaemonPodName", daemonPodName,
			"envCount", len(envVars))

		if len(envVars) == 0 {
			slog.Warn("ENV_RELOAD with no environment variables provided for this daemon")
			return false
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
		slog.Info("Environment variables updated")
		return true
	}

	slog.Warn("Unknown message type, ignoring", "messageType", command.MessageType)
	return false
}

// ensureConfigTopic creates the config topic before the consumer subscribes.
// If the consumer joins the group before the topic (and its partition) exists,
// it gets a zero-partition assignment and silently never rebalances onto the
// partition once it appears. Creating the topic up front makes that race
// impossible. Uses the same TLS/SASL transport as the rest of the client.
func ensureConfigTopic(kafkaURL, topic string) {
	client := &kafka.Client{
		Addr:      kafka.TCP(kafkaURL),
		Transport: getGlobalTransport(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := client.CreateTopics(ctx, &kafka.CreateTopicsRequest{
		Topics: []kafka.TopicConfig{{
			Topic:             topic,
			NumPartitions:     1,
			ReplicationFactor: 1,
		}},
	})
	if err != nil {
		slog.Error("Failed to create config topic", "topic", topic, "error", err)
		return
	}
	if topicErr := resp.Errors[topic]; topicErr != nil && !errors.Is(topicErr, kafka.TopicAlreadyExists) {
		slog.Error("Config topic creation returned error", "topic", topic, "error", topicErr)
		return
	}
	slog.Info("Config topic ensured", "topic", topic)
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
	groupID := fmt.Sprintf("ebpf-config-consumer-%s", getDaemonPodName())

	slog.Info("Starting config consumer", "topic", topic, "groupID", groupID, "daemonId", uniqueDaemonsetId)

	// Create the topic before subscribing to avoid the zero-partition
	// assignment race on a not-yet-created topic.
	ensureConfigTopic(kafka_url, topic)

	// Create Kafka reader (consumer).
	// CommitInterval 0 => synchronous commits, so an offset is durably
	// committed before we restart. LastOffset only applies at cold-start (no
	// committed offset); across the internal restart the same group id resumes
	// from the committed offset, so no command is dropped.
	readerConfig := kafka.ReaderConfig{
		Brokers:                []string{kafka_url},
		Topic:                  topic,
		GroupID:                groupID,
		MinBytes:               1,
		MaxBytes:               10e6,
		CommitInterval:         0,
		StartOffset:            kafka.LastOffset,
		WatchPartitionChanges:  true,
		PartitionWatchInterval: 5 * time.Second,
	}

	// Apply common TLS and SASL configuration
	readerConfig.Dialer = getKafkaDialer()

	reader := kafka.NewReader(readerConfig)

	// Start consumer goroutine
	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		for {
			msg, err := reader.FetchMessage(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				slog.Error("Error reading config update message", "error", err)
				time.Sleep(time.Second)
				continue
			}

			slog.Debug("Received command message", "value", string(msg.Value))

			var command TrafficAgentCommandMessage
			if err := json.Unmarshal(msg.Value, &command); err != nil {
				slog.Error("Failed to parse command message", "error", err)
				// Skip the poison message so it doesn't block the partition.
				if err := reader.CommitMessages(ctx, msg); err != nil {
					slog.Error("Failed to commit unparseable message", "error", err)
				}
				continue
			}

			if processCommandMessage(command) {
				// Persist the effect (env file) BEFORE committing/leaving/exiting:
				// once the file is written the change survives a crash, so
				// committing after it is safe. On failure, log and keep running
				// rather than exiting into a state the wrapper can't restore.
				if err := writeEnvFile(); err != nil {
					slog.Error("Failed to persist environment file, aborting restart", "error", err)
					continue
				}
				if err := reader.CommitMessages(ctx, msg); err != nil {
					slog.Error("Failed to commit message offset", "error", err)
				}
				// Leave the group cleanly before exiting.
				cancel()
				closeReaderWithTimeout(reader, 5*time.Second)
				slog.Warn("Restarting process with new environment...")
				os.Exit(0)
			}

			// Non-restart messages: commit and continue.
			if err := reader.CommitMessages(ctx, msg); err != nil {
				slog.Error("Failed to commit message offset", "error", err)
			}
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
