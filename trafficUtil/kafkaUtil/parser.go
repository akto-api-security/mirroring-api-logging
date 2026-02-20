package kafkaUtil

import (
	"context"
	"encoding/json"
	"log"
)

func ParseAndProduce(value map[string]string) {
	out, _ := json.Marshal(value)
	ctx := context.Background()
	go Produce(ctx, string(out))
}

func SendRawMessage(message string) {
	ctx := context.Background()
	// Send synchronously to ensure message is actually written to Kafka
	err := Produce(ctx, message)
	if err != nil {
		log.Printf("ERROR: Failed to send to Kafka: %v", err)
	}
}
