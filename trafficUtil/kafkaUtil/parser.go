package kafkaUtil

import (
	"context"
	"encoding/json"
	"log"

	"github.com/akto-api-security/api-gateway-logging/trafficUtil/utils"
)

func ParseAndProduce(value map[string]string) {
	path := value["path"]
	method := value["method"]
	log.Printf("Queueing traffic message for Kafka path=%s method=%s", path, method)
	out, _ := json.Marshal(value)
	ctx := context.Background()
	go Produce(ctx, string(out))
}

func SendRawMessage(message string) {
	ctx := context.Background()
	// Send synchronously to ensure message is actually written to Kafka
	err := Produce(ctx, message)
	if err != nil {
		utils.LogToCyborg("error", "Failed to send to Kafka: "+err.Error())
	}
}
