package kafkaUtil

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	trafficpb "github.com/akto-api-security/mirroring-api-logging/trafficUtil/protobuf/traffic_payload"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"

	"github.com/segmentio/kafka-go"
	"google.golang.org/protobuf/proto"
)

var kafkaWriter *kafka.Writer
var KafkaErrMsgCount = 0
var KafkaErrMsgEpoch = time.Now()
var BytesInThreshold = 500 * 1024 * 1024

func InitKafka() {
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
		kafkaWriter = getKafkaWriter(kafka_url, "akto.api.logs", kafka_batch_size, kafka_batch_time_secs_duration*time.Second)
		utils.LogMemoryStats()
		utils.PrintLog("logging kafka stats before pushing message")
		LogKafkaStats()
		value := map[string]string{
			"testConnectionString": "kafkaInit",
		}

		out, _ := json.Marshal(value)
		ctx := context.Background()
		err := ProduceStr(ctx, string(out))
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
			slog.Error("kafka error message", "count", KafkaErrMsgCount, "messagesCount", len(messages))
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

func Produce(kafkaWriter *kafka.Writer, ctx context.Context, value *trafficpb.HttpResponseParam) error {
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
		slog.Error("Kafka write for runtime failed", "topic", topic, "error", err)
	}
	return err
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

	slog.Debug("No ip found in headers returning", "packetIp", packetIp)
	return packetIp
}

func ProduceStr(ctx context.Context, message string) error {
	// intialize the writer with the broker addresses, and the topic
	msg := kafka.Message{
		Value: []byte(message),
	}
	err := kafkaWriter.WriteMessages(ctx, msg)

	if err != nil {
		slog.Error("ERROR while writing messages", "error", err)
		return err
	}
	return nil
}

func getKafkaWriter(kafkaURL, topic string, batchSize int, batchTimeout time.Duration) *kafka.Writer {
	return &kafka.Writer{
		Addr:         kafka.TCP(kafkaURL),
		Topic:        topic,
		BatchSize:    batchSize,
		BatchTimeout: batchTimeout,
		MaxAttempts:  1,
		ReadTimeout:  batchTimeout,
		WriteTimeout: batchTimeout,
		Async:        true,
		Balancer:     &kafka.Hash{},
		Compression:  kafka.Zstd,
	}
}
