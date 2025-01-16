package kafkaUtil

import (
	"context"
	"encoding/json"
)

func ParseAndProduce(value map[string]string) {
	out, _ := json.Marshal(value)
	ctx := context.Background()
	go Produce(ctx, string(out))
}
