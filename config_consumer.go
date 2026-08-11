package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl/plain"
)

type MessageType string

const (
	MessageTypeEnvReload MessageType = "ENV_RELOAD"
	MessageTypeRestart   MessageType = "RESTART"
)

// envFilePath is where the current environment is persisted so run.sh can
// source it and the freshly-restarted process inherits the updated vars.
// Keep this in sync with run.sh.
func envFilePath() string {
	if p := os.Getenv("AKTO_ENV_FILE"); p != "" {
		return p
	}
	return "/app/.env"
}

// TrafficAgentCommandMessage mirrors the akto.config.updates command payload.
// filter_header has no daemon/pod identity, so only the flat Env map is used;
// DaemonNames / DaemonEnvMap are accepted for wire-compatibility but ignored.
type TrafficAgentCommandMessage struct {
	MessageType  MessageType                  `json:"messageType"`
	DaemonNames  []string                     `json:"daemonNames"`
	Env          map[string]string            `json:"env"`
	DaemonEnvMap map[string]map[string]string `json:"daemonEnvMap"`
	Timestamp    int64                        `json:"timestamp"`
}

// writeEnvFile serializes the current process environment into a shell-sourceable
// file, written atomically so run.sh never sees a partial file.
func writeEnvFile() error {
	finalPath := envFilePath()
	tmpPath := finalPath + ".tmp"

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
		content.WriteString(strconv.Quote(val)) // shell-safe escaping
		content.WriteString("\n")
	}

	if err := os.WriteFile(tmpPath, []byte(content.String()), 0644); err != nil {
		slog.Error("Failed to write environment file", "path", tmpPath, "error", err)
		return err
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		slog.Error("Failed to rename environment file", "path", tmpPath, "error", err)
		return err
	}
	slog.Debug("Environment variables written to file", "path", finalPath)
	return nil
}

// restartSelf persists the current environment then exits, letting run.sh's
// supervising loop spawn a fresh process that sources the updated env.
func restartSelf() {
	slog.Warn("Restarting process with new environment...")
	if err := writeEnvFile(); err != nil {
		slog.Error("Failed to persist environment before restart", "error", err)
	}
	os.Exit(0)
}

// processCommandMessage handles a single command message.
func processCommandMessage(command TrafficAgentCommandMessage) {
	switch command.MessageType {
	case MessageTypeRestart:
		slog.Info("Received RESTART command, restarting process...")
		restartSelf()

	case MessageTypeEnvReload:
		if len(command.Env) == 0 {
			slog.Warn("ENV_RELOAD with no environment variables provided, ignoring")
			return
		}

		slog.Info("Processing ENV_RELOAD command", "envCount", len(command.Env))

		changed := false
		for key, value := range command.Env {
			oldValue := os.Getenv(key)
			if oldValue != value {
				slog.Warn("Updating environment variable", "key", key, "oldValue", oldValue, "newValue", value)
				os.Setenv(key, value)
				changed = true
			}
		}

		if !changed {
			slog.Info("ENV_RELOAD produced no changes, skipping restart")
			return
		}

		slog.Info("Environment variables updated, restarting process...")
		restartSelf()

	default:
		slog.Warn("Unknown message type, ignoring", "messageType", command.MessageType)
	}
}

// getConfigKafkaDialer builds a dialer with the same TLS/SASL settings used by
// the rest of the Kafka clients in this agent.
func getConfigKafkaDialer() *kafka.Dialer {
	dialer := &kafka.Dialer{}
	if useTLS {
		if tlsConfig, err := NewTLSConfig(tlsCACertPath); err == nil {
			dialer.TLS = tlsConfig
		} else {
			slog.Error("Failed to build TLS config for config consumer", "error", err)
		}
	}
	if isAuthImplemented && kafkaUsername != "" && kafkaPassword != "" {
		dialer.SASLMechanism = plain.Mechanism{Username: kafkaUsername, Password: kafkaPassword}
	}
	return dialer
}

// StartConfigConsumer subscribes to akto.config.updates and applies ENV_RELOAD /
// RESTART commands. Each process uses a unique consumer group so every agent
// receives every command (broadcast semantics).
func StartConfigConsumer() {
	kafkaURL := getKafkaUrl()
	if kafkaURL == "" {
		slog.Warn("Kafka URL not configured, config consumer disabled")
		return
	}

	topic := "akto.config.updates"
	// Unique per process so commands are not load-balanced away from any agent.
	hostname, _ := os.Hostname()
	groupID := fmt.Sprintf("mirroring-config-consumer-%s-%s", collectorId, hostname)

	slog.Info("Starting config consumer", "topic", topic, "groupID", groupID)

	readerConfig := kafka.ReaderConfig{
		Brokers:        []string{kafkaURL},
		Topic:          topic,
		GroupID:        groupID,
		MinBytes:       1,
		MaxBytes:       10e6,
		CommitInterval: time.Second,
		StartOffset:    kafka.LastOffset,
		Dialer:         getConfigKafkaDialer(),
	}

	reader := kafka.NewReader(readerConfig)

	go func() {
		defer reader.Close()

		ctx := context.Background()
		for {
			msg, err := reader.FetchMessage(ctx)
			if err != nil {
				slog.Error("Error reading config update message", "error", err)
				time.Sleep(time.Second)
				continue
			}

			slog.Debug("Received command message", "value", string(msg.Value))

			var command TrafficAgentCommandMessage
			if err := json.Unmarshal(msg.Value, &command); err != nil {
				slog.Error("Failed to parse command message", "error", err)
				if err := reader.CommitMessages(ctx, msg); err != nil {
					slog.Error("Failed to commit unparseable message", "error", err)
				}
				continue
			}

			if err := reader.CommitMessages(ctx, msg); err != nil {
				slog.Error("Failed to commit message offset", "error", err)
			}

			processCommandMessage(command)
		}
	}()

	slog.Info("Config consumer started successfully")
}
