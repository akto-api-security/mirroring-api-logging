package kafkaUtil

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/apiProcessor"
	trafficpb "github.com/akto-api-security/mirroring-api-logging/trafficUtil/protobuf/traffic_payload"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"

	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl/plain"
	"google.golang.org/protobuf/proto"
)

var kafkaWriter *kafka.Writer
var kafkaWriterMutex sync.RWMutex
var KafkaErrMsgCount = 0
var KafkaErrMsgEpoch = time.Now()
var BytesInThreshold = 500 * 1024 * 1024

var useTLS = false
var InsecureSkipVerify = true
var tlsCACertPath = "./ca.crt"

var isAuthImplemented = false
var kafkaUsername = ""
var kafkaPassword = ""

var kafkaErrorThreshold = 500
var kafkaReconnectIntervalMinutes = -1
var heartbeatIntervalSeconds = 60
var kafkaDisabled = false
var uniqueDaemonsetId = uuid.New().String()
var moduleType = "TRAFFIC_COLLECTOR"

var globalTransport *kafka.Transport
var transportOnce sync.Once

var (
	kafkaBrokerMAL     string
	kafkaBrokerURL     string
	kafkaBatchSize     = 100
	kafkaBatchTimeSecs = 10
	aktoAgentName      string
	kubePodName        string
	kubeNodeName       string
	kubeHostname       string
	aktoImageVersion   string
)

func init() {

	utils.InitVar("USE_TLS", &useTLS)
	utils.InitVar("INSECURE_SKIP_VERIFY", &InsecureSkipVerify)
	utils.InitVar("TLS_CA_CERT_PATH", &tlsCACertPath)

	utils.InitVar("IS_AUTH_IMPLEMENTED", &isAuthImplemented)
	utils.InitVar("KAFKA_USERNAME", &kafkaUsername)
	utils.InitVar("KAFKA_PASSWORD", &kafkaPassword)

	utils.InitVar("KAFKA_ERROR_THRESHOLD", &kafkaErrorThreshold)
	utils.InitVar("KAFKA_RECONNECT_INTERVAL_MINUTES", &kafkaReconnectIntervalMinutes)
	utils.InitVar("KAFKA_HEARTBEAT_INTERVAL_SECONDS", &heartbeatIntervalSeconds)
	utils.InitVar("AKTO_KAFKA_DISABLED", &kafkaDisabled)

	utils.InitVar("AKTO_KAFKA_BROKER_MAL", &kafkaBrokerMAL)
	utils.InitVar("AKTO_KAFKA_BROKER_URL", &kafkaBrokerURL)
	utils.InitVar("AKTO_BYTES_IN_THRESHOLD", &BytesInThreshold)
	utils.InitVar("AKTO_TRAFFIC_BATCH_SIZE", &kafkaBatchSize)
	utils.InitVar("AKTO_TRAFFIC_BATCH_TIME_SECS", &kafkaBatchTimeSecs)
	utils.InitVar("AKTO_AGENT_NAME", &aktoAgentName)
	utils.InitVar("POD_NAME", &kubePodName)
	utils.InitVar("NODE_NAME", &kubeNodeName)
	utils.InitVar("HOSTNAME", &kubeHostname)
	utils.InitVar("AKTO_IMAGE_VERSION", &aktoImageVersion)
}

// KafkaBrokerURL returns AKTO_KAFKA_BROKER_MAL if set, otherwise AKTO_KAFKA_BROKER_URL.
func KafkaBrokerURL() string {
	if kafkaBrokerMAL != "" {
		return kafkaBrokerMAL
	}
	return kafkaBrokerURL
}

// KafkaDisabled is true when AKTO_KAFKA_DISABLED=true: no producer, heartbeat, or config consumer.
func KafkaDisabled() bool {
	return kafkaDisabled
}

// KafkaWriteAvailable is true when Kafka init succeeded and writes may be sent.
func KafkaWriteAvailable() bool {
	return !kafkaDisabled && kafkaWriter != nil
}

func InitKafka() {
	if apiProcessor.CloudTrafficProcessorModeEnabled {
		return
	}

	if kafkaDisabled {
		slog.Warn("Kafka disabled (AKTO_KAFKA_DISABLED), skipping broker connection and producer init")
		return
	}

	kafka_url := KafkaBrokerURL()
	if kafka_url == "" {
		slog.Warn("Kafka broker URL empty and Kafka is required when not disabled; skipping Kafka init")
		return
	}
	slog.Info("kafka_url: " + kafka_url)

	kafka_batch_time_secs_duration := time.Duration(kafkaBatchTimeSecs)

	for {
		kafkaWriterMutex.Lock()
		kafkaWriter = getKafkaWriter(kafka_url, kafkaBatchSize, kafka_batch_time_secs_duration*time.Second)
		kafkaWriterMutex.Unlock()

		utils.LogMemoryStats()
		utils.PrintLog("logging kafka stats before pushing message")
		LogKafkaStats()
		value := map[string]string{
			"testConnectionString": "kafkaInit",
		}

		out, _ := json.Marshal(value)
		ctx := context.Background()
		err := ProduceStr(ctx, string(out), "testKafkaConnection", "testKafkaConnectionHost", "")
		utils.PrintLog("logging kafka stats post pushing message")
		LogKafkaStats()
		if err != nil {
			slog.Error("error establishing connection with kafka, sending message failed, retrying in 2 seconds", "error", err)
			kafkaWriterMutex.Lock()
			kafkaWriter.Close()
			kafkaWriterMutex.Unlock()
			if globalTransport != nil {
				globalTransport.CloseIdleConnections()
			}
			time.Sleep(time.Second * 2)
		} else {
			slog.Info("connection establishing with kafka successfully")
			kafkaWriterMutex.Lock()
			kafkaWriter.Completion = kafkaCompletion()
			kafkaWriterMutex.Unlock()

			// Start periodic reconnection routine
			go periodicKafkaReconnect(kafka_url, kafkaBatchSize, kafka_batch_time_secs_duration*time.Second)
			slog.Info("Started Kafka periodic reconnection routine", "interval_minutes", kafkaReconnectIntervalMinutes)

			// Start heartbeat routine
			go sendKafkaHeartbeat()
			slog.Info("Started Kafka heartbeat routine", "interval_seconds", heartbeatIntervalSeconds)
			break
		}
	}
}

func kafkaCompletion() func(messages []kafka.Message, err error) {
	return func(messages []kafka.Message, err error) {
		if err != nil {
			KafkaErrMsgCount += len(messages)
			slog.Error("kafka error message", "err", err, "count", KafkaErrMsgCount, "messagesCount", len(messages))

			if KafkaErrMsgCount > kafkaErrorThreshold {
				slog.Error("kafka error count exceeded threshold, restarting module", "count", KafkaErrMsgCount, "threshold", kafkaErrorThreshold)
				os.Exit(1)
			}
		} else {
			utils.PrintLog("kafka messages sent successfully", "messagesCount", len(messages))
		}
	}
}

func periodicKafkaReconnect(kafka_url string, kafka_batch_size int, kafka_batch_time_secs_duration time.Duration) {
	if kafkaReconnectIntervalMinutes <= 0 {
		slog.Info("Kafka reconnection disabled", "interval", kafkaReconnectIntervalMinutes)
		return
	}

	ticker := time.NewTicker(time.Duration(kafkaReconnectIntervalMinutes) * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		slog.Info("Starting periodic Kafka reconnection", "interval_minutes", kafkaReconnectIntervalMinutes)

		// Create new writer
		newWriter := getKafkaWriter(kafka_url, kafka_batch_size, kafka_batch_time_secs_duration)
		newWriter.Completion = kafkaCompletion()

		// Test the new connection
		ctx := context.Background()
		value := map[string]string{
			"testConnectionString": "periodicReconnect",
		}
		out, _ := json.Marshal(value)
		testMsg := kafka.Message{
			Topic: "akto.api.logs",
			Value: out,
		}

		err := newWriter.WriteMessages(ctx, testMsg)
		if err != nil {
			slog.Error("Failed to test new Kafka connection during periodic reconnect, keeping old connection", "error", err)
			newWriter.Close()
			continue
		}

		// Replace old writer with new one
		kafkaWriterMutex.Lock()
		oldWriter := kafkaWriter
		kafkaWriter = newWriter
		kafkaWriterMutex.Unlock()

		// Close old writer
		if oldWriter != nil {
			slog.Info("Closing old Kafka writer")
			oldWriter.Close()
		}

		slog.Info("Kafka reconnection completed successfully")
	}
}

func getDaemonPodName() string {
	if aktoAgentName != "" {
		return fmt.Sprintf("akto-tc:%s", aktoAgentName)
	}

	if kubePodName != "" && kubeNodeName != "" {
		return fmt.Sprintf("akto-tc:%s:%s", kubePodName, kubeNodeName)
	}

	hostname := kubeHostname
	if hostname == "" {
		hostname = fmt.Sprintf("daemon-%s", uniqueDaemonsetId[:8])
	}
	return fmt.Sprintf("akto-tc:%s", hostname)
}

func getImageVersion() string {
	if aktoImageVersion != "" {
		return aktoImageVersion
	}
	return "aktosecurity/mirror-api-logging:k8s-ebpf"
}

// Heartbeat and config consumer functions moved to ebpf_telemetry.go

func LogKafkaStats() {
	kafkaWriterMutex.RLock()
	defer kafkaWriterMutex.RUnlock()
	if kafkaWriter == nil {
		return
	}
	stats := kafkaWriter.Stats()
	slog.Debug("Kafka Stats",
		"dials", stats.Dials,
		"writes", stats.Writes,
		"messages", stats.Messages,
		"bytes", stats.Bytes,
		"errors", stats.Errors,
		"dialTime", stats.DialTime,
		"batchTime", stats.BatchTime,
		"writeTime", stats.WriteTime,
		"waitTime", stats.WaitTime,
		"retries", stats.Retries,
		"batchSize", stats.BatchSize,
		"batchBytes", stats.BatchBytes,
		"maxAttempts", stats.MaxAttempts,
		"maxBatchSize", stats.MaxBatchSize,
		"batchTimeout", stats.BatchTimeout,
		"readTimeout", stats.ReadTimeout,
		"writeTimeout", stats.WriteTimeout,
		"requiredAcks", stats.RequiredAcks,
		"async", stats.Async,
		"topic", stats.Topic,
	)
}

func LogKafkaError() {
	if time.Since(KafkaErrMsgEpoch).Seconds() >= 10 {

		if KafkaErrMsgCount > 1000 {
			slog.Error("kafka error messages exceeded threshold, sleeping for 10 sec ", "count", KafkaErrMsgCount, "time", time.Now())
			time.Sleep(10 * time.Second)
		}
		KafkaErrMsgCount = 0
		KafkaErrMsgEpoch = time.Now()
	}
}

var CLIENT_IP_HEADERS = []string{
	"x-forwarded-for",
	"x-real-ip",
	"x-cluster-client-ip",
	"true-client-ip",
	"x-original-forwarded-for",
	"x-client-ip",
	"client-ip",
}

func ProducePodMapping(ctx context.Context, podName string) error {
	message := map[string]string{
		"podName":       podName,
		"aktoDaemonSet": kubePodName,
		"nodeName":      kubeNodeName,
		"lastUpdated":   fmt.Sprint(time.Now().Format(time.RFC3339)),
	}

	out, _ := json.Marshal(message)
	slog.Debug("Producing pod mapping", "podName", podName, "message", string(out))
	go ProduceLogs(ctx, string(out), LogTypeDebug)
	return nil
}

func Produce(ctx context.Context, value *trafficpb.HttpResponseParam) error {

	if !utils.ThreatEnabled {
		return nil
	}

	if !KafkaWriteAvailable() {
		return nil
	}

	protoBytes, err := proto.Marshal(value)
	if err != nil {
		slog.Error("Failed to serialize protobuf message", "error", err)
		return err
	}

	if value.Ip == "" {
		slog.Warn("ip is empty, avoiding kafka push")
		return nil
	}
	topic := "akto.api.logs2"
	msg := kafka.Message{
		Topic: topic,
		Key:   []byte(value.Ip), // what to do when ip is empty?
		Value: protoBytes,
	}

	kafkaWriterMutex.RLock()
	writer := kafkaWriter
	kafkaWriterMutex.RUnlock()

	err = writer.WriteMessages(ctx, msg)
	if err != nil {
		slog.Error("Kafka write for threat failed", "topic", topic, "error", err)
		return err
	}
	return nil
}

func GetSourceIp(reqHeaders map[string]*trafficpb.StringList, packetIp string) string {

	for _, header := range CLIENT_IP_HEADERS {
		if headerValues, exists := reqHeaders[header]; exists {
			for _, headerValue := range headerValues.Values {
				parts := strings.Split(headerValue, ",")
				for _, part := range parts {
					ip := strings.TrimSpace(part)
					if ip != "" {
						slog.Debug("Ip found in", "the header", header)
						return ip
					}
				}
			}
		}
	}

	return packetIp
}

const (
	LogTypeError = "ERROR"
	LogTypeInfo  = "INFO"
	LogTypeDebug = "DEBUG"
)

func ProduceHeartbeat(ctx context.Context, heartbeatData map[string]string) error {
	if !KafkaWriteAvailable() {
		return nil
	}

	out, err := json.Marshal(heartbeatData)
	if err != nil {
		return err
	}

	topic := "akto.daemonset.producer.heartbeats"
	msg := kafka.Message{
		Topic: topic,
		Value: []byte(string(out)),
	}

	kafkaWriterMutex.RLock()
	writer := kafkaWriter
	kafkaWriterMutex.RUnlock()

	err = writer.WriteMessages(ctx, msg)

	if err != nil {
		slog.Error("ERROR while writing heartbeat messages", "topic", topic, "error", err)
		return err
	}
	return nil
}

func ProduceLogs(ctx context.Context, message string, logType string) error {
	if !KafkaWriteAvailable() {
		return nil
	}

	value := map[string]string{
		"message": message,
		"logType": logType,
		"source":  "AKTO_K8S_EBPF",
		"time":    fmt.Sprint(time.Now().Unix()),
	}

	out, _ := json.Marshal(value)

	topic := "akto.api.producer.logs"
	msg := kafka.Message{
		Topic: topic,
		Value: []byte(string(out)),
	}

	kafkaWriterMutex.RLock()
	writer := kafkaWriter
	kafkaWriterMutex.RUnlock()

	err := writer.WriteMessages(ctx, msg)

	if err != nil {
		slog.Error("ERROR while writing messages", "topic", topic, "error", err)
		return err
	}
	return nil
}

// buildCollectionDetailsHeader creates the collection_details Kafka header
// Format: "host|method|url"
// Returns nil if any parameter is empty (skip header for incomplete messages)
func buildCollectionDetailsHeader(host, method, url string) []kafka.Header {
	if host == "" || method == "" || url == "" {
		return nil
	}

	headerValue := fmt.Sprintf("%s|%s|%s", host, method, url)
	return []kafka.Header{
		{
			Key:   "collection_details",
			Value: []byte(headerValue),
		},
	}
}

func ProduceStr(ctx context.Context, message string, url, reqHost, method string) error {
	if !KafkaWriteAvailable() {
		return nil
	}

	topic := "akto.api.logs"

	msg := kafka.Message{
		Topic:   topic,
		Value:   []byte(message),
		Headers: buildCollectionDetailsHeader(reqHost, method, url),
	}

	kafkaWriterMutex.RLock()
	writer := kafkaWriter
	kafkaWriterMutex.RUnlock()

	err := writer.WriteMessages(ctx, msg)

	if err != nil {
		slog.Error("ERROR while writing messages", "topic", topic, "error", err)
		return err
	}
	checkDebugUrlAndPrint(url, reqHost, "Kafka write successful: ")

	return nil
}

func NewTLSConfig(caPath string) (*tls.Config, error) {
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	return &tls.Config{
		RootCAs:            caCertPool,
		InsecureSkipVerify: InsecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
	}, nil
}

func getKafkaDialer() *kafka.Dialer {
	dialer := &kafka.Dialer{}

	// Add TLS config if enabled
	if useTLS {
		tlsConfig, err := NewTLSConfig(tlsCACertPath)
		if err != nil {
			slog.Error("Failed to create TLS config", "error", err)
		} else {
			dialer.TLS = tlsConfig
		}
	}

	// Add SASL auth if enabled
	if isAuthImplemented && kafkaUsername != "" && kafkaPassword != "" {
		slog.Info("Configuring SASL plain authentication", "username", kafkaUsername)
		dialer.SASLMechanism = plain.Mechanism{
			Username: kafkaUsername,
			Password: kafkaPassword,
		}
	}

	return dialer
}

func getGlobalTransport() *kafka.Transport {
	transportOnce.Do(func() {
		dialer := getKafkaDialer()
		globalTransport = &kafka.Transport{
			TLS:         dialer.TLS,
			SASL:        dialer.SASLMechanism,
			IdleTimeout: 30 * time.Second,
			MetadataTTL: 60 * time.Second,
		}
	})
	return globalTransport
}

func getKafkaWriter(kafkaURL string, batchSize int, batchTimeout time.Duration) *kafka.Writer {
	kafkaWriter := kafka.Writer{
		Addr:         kafka.TCP(kafkaURL),
		BatchSize:    batchSize,
		BatchTimeout: batchTimeout,
		MaxAttempts:  1,
		ReadTimeout:  batchTimeout,
		WriteTimeout: batchTimeout,
		Async:        true,
		Balancer:     &kafka.Hash{},
		Compression:  kafka.Lz4,
	}

	kafkaWriter.Transport = getGlobalTransport()
	return &kafkaWriter
}

func Close() {
	kafkaWriterMutex.Lock()
	defer kafkaWriterMutex.Unlock()
	if kafkaWriter != nil {
		kafkaWriter.Close()
		kafkaWriter = nil
	}
}
