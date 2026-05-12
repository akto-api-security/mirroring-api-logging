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
	"github.com/segmentio/kafka-go/sasl"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"
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

// kafkaSaslMechanism controls which SASL mechanism to use when IS_AUTH_IMPLEMENTED=true.
// Accepted values: "PLAIN", "SCRAM-SHA-512".
// When empty (default), SCRAM-SHA-512 is tried first; if the initial connection test fails,
// the retry loop in main.go falls back to PLAIN for backwards compatibility.
// Set AKTO_KAFKA_SASL_MECHANISM explicitly to pin a mechanism and disable auto-detection.
var kafkaSaslMechanism = ""

func init() {

	utils.InitVar("USE_TLS", &useTLS)
	utils.InitVar("INSECURE_SKIP_VERIFY", &InsecureSkipVerify)
	utils.InitVar("TLS_CA_CERT_PATH", &tlsCACertPath)

	utils.InitVar("IS_AUTH_IMPLEMENTED", &isAuthImplemented)
	utils.InitVar("KAFKA_USERNAME", &kafkaUsername)
	utils.InitVar("KAFKA_PASSWORD", &kafkaPassword)
	utils.InitVar("AKTO_KAFKA_SASL_MECHANISM", &kafkaSaslMechanism)
}

// buildSASLMechanism returns the configured SASL mechanism.
// Defaults to SCRAM-SHA-512 when kafkaSaslMechanism is empty.
func buildSASLMechanism() sasl.Mechanism {
	if !isAuthImplemented || kafkaUsername == "" || kafkaPassword == "" {
		return nil
	}
	if strings.ToUpper(kafkaSaslMechanism) == "PLAIN" {
		slog.Info("Configuring SASL PLAIN authentication", "username", kafkaUsername)
		return plain.Mechanism{Username: kafkaUsername, Password: kafkaPassword}
	}
	slog.Info("Configuring SASL SCRAM-SHA-512 authentication", "username", kafkaUsername)
	mechanism, err := scram.Mechanism(scram.SHA512, kafkaUsername, kafkaPassword)
	if err != nil {
		slog.Error("Failed to create SCRAM-SHA-512 mechanism", "error", err)
		return nil
	}
	return mechanism
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

func ProduceStr(kafkaWriter *kafka.Writer, ctx context.Context, message string, url, reqHost string) error {
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

	transport := &kafka.Transport{
		SASL: buildSASLMechanism(),
	}

	if useTLS {
		tlsConfig, _ := NewTLSConfig(tlsCACertPath)
		transport.TLS = tlsConfig
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

	dialer := &kafka.Dialer{
		SASLMechanism: buildSASLMechanism(),
	}

	if useTLS {
		tlsConfig, _ := NewTLSConfig(tlsCACertPath)
		dialer.TLS = tlsConfig
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
