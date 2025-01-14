package main

import (
	"context"
	"encoding/json"
	"fmt"
	trafficpb "github.com/akto-api-security/mirroring-api-logging/protobuf/traffic_payload"
	"github.com/segmentio/kafka-go"
	"google.golang.org/protobuf/proto"
	"log"
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
		log.Println("Failed to serialize protobuf message: ", err)
		return err
	}

	ip := GetSourceIp(value)
	if ip == "" {
		fmt.Print("ip is empty, avoiding kafka push")
		return nil
	}
	// Send serialized message to Kafka
	msg := kafka.Message{
		Topic: "akto.api.logs2",
		Key:   []byte(ip), // what to do when ip is empty?
		Value: protoBytes,
	}

	err = kafkaWriter.WriteMessages(ctx, msg)
	if err != nil {
		log.Println("ERROR while writing messages: ", err)
	}
	return err
}

func GetSourceIp(value *trafficpb.HttpResponseParam) string {

	for _, header := range CLIENT_IP_HEADERS {
		if headerValues, exists := value.ResponseHeaders[header]; exists {
			for _, value := range headerValues.Values {
				parts := strings.Split(value, ",")
				for _, part := range parts {
					ip := strings.TrimSpace(part)
					if ip != "" {
						return ip
					}
				}
			}
		}
	}

	// if no headers found
	return value.Ip
}

func ProduceStr(kafkaWriter *kafka.Writer, ctx context.Context, message string) error {
	// intialize the writer with the broker addresses, and the topic
	msg := kafka.Message{
		Topic: "akto.api.logs",
		Value: []byte(message),
	}
	err := kafkaWriter.WriteMessages(ctx, msg)

	if err != nil {
		log.Println("ERROR while writing messages: ", err)
		return err
	}

	return nil

}

func GetKafkaWriter(kafkaURL, topic string, batchSize int, batchTimeout time.Duration) *kafka.Writer {
	return &kafka.Writer{
		Addr:         kafka.TCP(kafkaURL),
		BatchSize:    batchSize,
		BatchTimeout: batchTimeout,
		MaxAttempts:  1,
		ReadTimeout:  batchTimeout,
		WriteTimeout: batchTimeout,
	}
}

func GetCredential(kafkaURL string, groupID string, topic string) Credential {
	// Create a new Kafka reader
	r := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  []string{kafkaURL},
		GroupID:  groupID,
		Topic:    topic,
		MinBytes: 10e3, // 10KB
		MaxBytes: 10e6, // 10MB
	})

	// Set up a context with a timeout
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	defer func(r *kafka.Reader) {
		err := r.Close()
		if err != nil {
			log.Printf("could not close reader: %v", err)
		}
	}(r)

	var msg Credential

	// Use a select statement to either get the message or hit the timeout
	for {
		select {
		case <-ctx.Done():
			log.Println("Timeout reached, no message received.")
			return msg // Return empty Credential if timeout occurs
		default:
			// Attempt to read a message from the Kafka topic
			m, err := r.ReadMessage(ctx)
			if err != nil {
				if err == context.DeadlineExceeded {
					log.Println("Timeout reached, no message received.")
					return msg
				}
				log.Printf("could not read message: %v", err)
				return msg // Return empty Credential on read error
			}

			log.Println("Found message: " + string(m.Value))

			err = json.Unmarshal(m.Value, &msg)
			if err != nil {
				log.Printf("could not unmarshal message: %v", err)
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
