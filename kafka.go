package main

import (
	"context"
	trafficpb "github.com/akto-api-security/mirroring-api-logging/protobuf/traffic_payload"
	"github.com/segmentio/kafka-go"
	"google.golang.org/protobuf/proto"
	"log"
	"log/slog"
	"strings"
	"time"
)

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
	// intialize the writer with the broker addresses, and the topic
	protoBytes, err := proto.Marshal(value)
	if err != nil {
		slog.Error("Failed to serialize protobuf message", "error", err)
		return err
	}

	if value.Ip == "" {
		slog.Warn("ip is empty, avoiding kafka push")
		return nil
	}
	// Send serialized message to Kafka
	topic := "akto.api.logs2"
	msg := kafka.Message{
		Topic: topic,
		Key:   []byte(value.Ip), // what to do when ip is empty?
		Value: protoBytes,
	}

	err = kafkaWriter.WriteMessages(ctx, msg)

	if err != nil {
		slog.Error("Kafka write for threat failed", "topic", topic, "error", err)
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

func ProduceStr(kafkaWriter *kafka.Writer, ctx context.Context, message string) error {
	// intialize the writer with the broker addresses, and the topic
	topic := "akto.api.logs"
	msg := kafka.Message{
		Topic: topic,
		Value: []byte(message),
	}
	err := kafkaWriter.WriteMessages(ctx, msg)

	if err != nil {
		log.Println("ERROR while writing messages: ", err)
		slog.Error("Kafka write for runtime failed", "topic", topic, "error", err)
		return err
	}

	return nil
}

func GetKafkaWriter(kafkaURL string, batchSize int, batchTimeout time.Duration) *kafka.Writer {
	return &kafka.Writer{
		Addr:         kafka.TCP(kafkaURL),
		BatchSize:    batchSize,
		BatchTimeout: batchTimeout,
	}
}
