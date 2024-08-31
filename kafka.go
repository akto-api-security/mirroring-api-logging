package main

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/segmentio/kafka-go"
)

func Produce(kafkaWriter *kafka.Writer, ctx context.Context, message string) error {
	// intialize the writer with the broker addresses, and the topic
	msg := kafka.Message{
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
		Topic:        topic,
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
			log.Fatalf("could not close reader: %v", err)
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
				log.Fatalf("could not read message: %v", err)
			}

			log.Println("Found message: " + string(m.Value))

			err = json.Unmarshal(m.Value, &msg)
			if err != nil {
				log.Fatalf("could not unmarshal message: %v", err)
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
