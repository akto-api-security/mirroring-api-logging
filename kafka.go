package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	trafficpb "github.com/akto-api-security/mirroring-api-logging/protobuf/traffic_payload"
	"github.com/akto-api-security/mirroring-api-logging/utils"
	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl/plain"
	"google.golang.org/protobuf/proto"
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

var useTLS = false
var InsecureSkipVerify = true
var tlsCACertPath = "./ca.crt"

var isAuthImplemented = false
var kafkaUsername = ""
var kafkaPassword = ""

func init() {

	utils.InitVar("USE_TLS", &useTLS)
	utils.InitVar("INSECURE_SKIP_VERIFY", &InsecureSkipVerify)
	utils.InitVar("TLS_CA_CERT_PATH", &tlsCACertPath)

	// Initialize SASL authentication variables
	utils.InitVar("IS_AUTH_IMPLEMENTED", &isAuthImplemented)
	utils.InitVar("KAFKA_USERNAME", &kafkaUsername)
	utils.InitVar("KAFKA_PASSWORD", &kafkaPassword)

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

func ProduceStr(kafkaWriter *kafka.Writer, ctx context.Context, message string,  url, reqHost string) error {
	// intialize the writer with the broker addresses, and the topic
	topic := "akto.api.logs"
	utils.CheckDebugUrlAndPrint(url, reqHost, "begin kafka write to akto.api.logs topic")
	msg := kafka.Message{
		Topic: topic,
		Value: []byte(message),
	}
	err := kafkaWriter.WriteMessages(ctx, msg)

	if err != nil {
		slog.Error("Kafka write for runtime failed", "topic", topic, "error", err)
		utils.CheckDebugUrlAndPrint(url, reqHost, fmt.Sprintf("Kafka write failed: %v", err))
		return err
	}

	utils.CheckDebugUrlAndPrint(url, reqHost, "Kafka write successful: ")
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

func GetKafkaWriter(kafkaURL, topic string, batchSize int, batchTimeout time.Duration) *kafka.Writer {

	kafkaWriter := kafka.Writer{
		Addr:         kafka.TCP(kafkaURL),
		BatchSize:    batchSize,
		BatchTimeout: batchTimeout,
		MaxAttempts:  1,
		ReadTimeout:  batchTimeout,
		WriteTimeout: batchTimeout,
		Balancer:     &kafka.Hash{},
		Compression:  kafka.Zstd,
	}

	// Configure transport with TLS and/or SASL authentication
	transport := &kafka.Transport{}

	if useTLS {
		tlsConfig, _ := NewTLSConfig(tlsCACertPath)
		transport.TLS = tlsConfig
	}

	// Add SASL authentication if enabled
	if isAuthImplemented && kafkaUsername != "" && kafkaPassword != "" {
		slog.Info("Configuring SASL plain authentication", "username", kafkaUsername)
		transport.SASL = plain.Mechanism{
			Username: kafkaUsername,
			Password: kafkaPassword,
		}
	}

	kafkaWriter.Transport = transport
	return &kafkaWriter
}

func GetCredential(kafkaURL string, groupID string, topic string) Credential {
	// Create a new Kafka reader

	config := kafka.ReaderConfig{
		Brokers:  []string{kafkaURL},
		GroupID:  groupID,
		Topic:    topic,
		MinBytes: 10e3, // 10KB
		MaxBytes: 10e6, // 10MB
	}

	// Configure dialer with TLS and/or SASL authentication
	dialer := &kafka.Dialer{}

	if useTLS {
		tlsConfig, _ := NewTLSConfig(tlsCACertPath)
		dialer.TLS = tlsConfig
	}

	// Add SASL authentication if enabled
	if isAuthImplemented && kafkaUsername != "" && kafkaPassword != "" {
		slog.Info("Configuring SASL plain authentication for reader", "username", kafkaUsername)
		dialer.SASLMechanism = plain.Mechanism{
			Username: kafkaUsername,
			Password: kafkaPassword,
		}
	}

	config.Dialer = dialer

	r := kafka.NewReader(config)

	// Set up a context with a timeout
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	defer func(r *kafka.Reader) {
		err := r.Close()
		if err != nil {
			slog.Error("could not close kafka reader", "error", err)
		}
	}(r)

	var msg Credential

	// Use a select statement to either get the message or hit the timeout
	for {
		select {
		case <-ctx.Done():
			slog.Error("Timeout reached, no message received.")
			return msg // Return empty Credential if timeout occurs
		default:
			// Attempt to read a message from the Kafka topic
			m, err := r.ReadMessage(ctx)
			if err != nil {
				if err == context.DeadlineExceeded {
					slog.Error("Timeout reached, no message received.")
					return msg
				}
				slog.Error("Kafka Read failed for", "topic", topic, "error", err)
				return msg // Return empty Credential on read error
			}

			slog.Debug("Found message: " + string(m.Value))

			err = json.Unmarshal(m.Value, &msg)
			if err != nil {
				slog.Error("could not unmarshal kafka message", "error", err)
				return msg // Return empty Credential on unmarshal error
			}

			return msg // Return early if a message is received
		}
	}
}

type Credential struct {
	ID    string `json:"id"`
	Token string `json:"token"`
	URL   string `json:"url"`
}
