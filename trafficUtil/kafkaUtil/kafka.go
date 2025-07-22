package kafkaUtil

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/apiProcessor"
	trafficpb "github.com/akto-api-security/mirroring-api-logging/trafficUtil/protobuf/traffic_payload"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"

	"github.com/segmentio/kafka-go"
	"google.golang.org/protobuf/proto"
)

var kafkaWriter *kafka.Writer
var KafkaErrMsgCount = 0
var KafkaErrMsgEpoch = time.Now()
var BytesInThreshold = 500 * 1024 * 1024

var useTLS = false
var InsecureSkipVerify = true
var tlsCACertPath = "./ca.crt"

func init() {

	utils.InitVar("USE_TLS", &useTLS)
	utils.InitVar("INSECURE_SKIP_VERIFY", &InsecureSkipVerify)
	utils.InitVar("TLS_CA_CERT_PATH", &tlsCACertPath)

}

func InitKafka() {
	if apiProcessor.CloudTrafficProcessorModeEnabled {
		return
	}

	kafka_url := os.Getenv("AKTO_KAFKA_BROKER_MAL")

	if len(kafka_url) == 0 {
		kafka_url = os.Getenv("AKTO_KAFKA_BROKER_URL")
	}
	utils.PrintLog("kafka_url: " + kafka_url)

	bytesInThresholdInput := os.Getenv("AKTO_BYTES_IN_THRESHOLD")
	if len(bytesInThresholdInput) > 0 {
		bytesInThreshold, err := strconv.Atoi(bytesInThresholdInput)
		if err != nil {
			utils.PrintLog("AKTO_BYTES_IN_THRESHOLD should be valid integer. Found " + bytesInThresholdInput)
			return
		} else {
			utils.PrintLog("Setting bytes in threshold at " + strconv.Itoa(bytesInThreshold))
		}

	}

	kafka_batch_size, e := strconv.Atoi(os.Getenv("AKTO_TRAFFIC_BATCH_SIZE"))
	if e != nil {
		utils.PrintLog("AKTO_TRAFFIC_BATCH_SIZE should be valid integer")
		return
	}

	kafka_batch_time_secs, e := strconv.Atoi(os.Getenv("AKTO_TRAFFIC_BATCH_TIME_SECS"))
	if e != nil {
		utils.PrintLog("AKTO_TRAFFIC_BATCH_TIME_SECS should be valid integer")
		return
	}
	kafka_batch_time_secs_duration := time.Duration(kafka_batch_time_secs)

	for {
		kafkaWriter = getKafkaWriter(kafka_url, kafka_batch_size, kafka_batch_time_secs_duration*time.Second)
		utils.LogMemoryStats()
		utils.PrintLog("logging kafka stats before pushing message")
		LogKafkaStats()
		value := map[string]string{
			"testConnectionString": "kafkaInit",
		}

		out, _ := json.Marshal(value)
		ctx := context.Background()
		err := ProduceStr(ctx, string(out), "testKafkaConnection", "testKafkaConnectionHost")
		utils.PrintLog("logging kafka stats post pushing message")
		LogKafkaStats()
		if err != nil {
			slog.Error("error establishing connection with kafka, sending message failed, retrying in 2 seconds", "error", err)
			kafkaWriter.Close()
			time.Sleep(time.Second * 2)
		} else {
			utils.PrintLog("connection establishing with kafka successfully")
			kafkaWriter.Completion = kafkaCompletion()
			break
		}
	}
}

func kafkaCompletion() func(messages []kafka.Message, err error) {
	return func(messages []kafka.Message, err error) {
		if err != nil {
			KafkaErrMsgCount += len(messages)
			slog.Error("kafka error message", "err", err, "count", KafkaErrMsgCount, "messagesCount", len(messages))
		} else {
			utils.PrintLog("kafka messages sent successfully", "messagesCount", len(messages))
		}
	}
}

func Close() {
	kafkaWriter.Close()
}

func LogKafkaStats() {
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
		"aktoDaemonSet": os.Getenv("POD_NAME"),
		"nodeName":      os.Getenv("NODE_NAME"),
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

	err = kafkaWriter.WriteMessages(ctx, msg)
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

func ProduceLogs(ctx context.Context, message string, logType string) error {
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

	err := kafkaWriter.WriteMessages(ctx, msg)

	if err != nil {
		slog.Error("ERROR while writing messages", "topic", topic, "error", err)
		return err
	}
	return nil
}

func ProduceStr(ctx context.Context, message string, url, reqHost string) error {
	// initialize the writer with the broker addresses, and the topic
	topic := "akto.api.logs"
	msg := kafka.Message{
		Topic: topic,
		Value: []byte(message),
	}

	err := kafkaWriter.WriteMessages(ctx, msg)

	if err != nil {
		slog.Error("ERROR while writing messages", "topic", topic, "error", err)
		return err
	}
	checkDebugUrlAndPrint(url, reqHost, "Kafka write successful: "+message)

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

	if useTLS {
		tlsConfig, _ := NewTLSConfig(tlsCACertPath)
		kafkaWriter.Transport = &kafka.Transport{
			TLS: tlsConfig,
		}
	}
	return &kafkaWriter
}
