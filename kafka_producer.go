package main

import (
	"context"
	trafficpb "github.com/akto-api-security/mirroring-api-logging/protobuf/traffic_payload"
	"log"
	"time"

	"github.com/segmentio/kafka-go"
	"google.golang.org/protobuf/proto"
)

// Produce serializes protobuf messages and sends to Kafka
func Produce(kafkaWriter *kafka.Writer, ctx context.Context, value *trafficpb.HttpResponseParam) {

	// Serialize to protobuf
	protoBytes, err := proto.Marshal(value)
	if err != nil {
		log.Println("Failed to serialize protobuf message: ", err)
		return
	}

	// Send serialized message to Kafka
	msg := kafka.Message{
		Key:   []byte("testkey"),
		Value: protoBytes,
	}

	err = kafkaWriter.WriteMessages(ctx, msg)
	if err != nil {
		log.Println("ERROR while writing messages: ", err)
	} else {
		log.Println("Message written successfully")
	}
}

// GetKafkaWriter initializes Kafka writer
func GetKafkaWriter(kafkaURL, topic string, batchSize int, batchTimeout time.Duration) *kafka.Writer {
	return &kafka.Writer{
		Addr:         kafka.TCP(kafkaURL),
		Topic:        topic,
		BatchSize:    batchSize,
		BatchTimeout: batchTimeout,
	}
}

//func main() {
//	kafkaURL := "192.168.1.11:29092"
//	topic := "akto.api.logs"
//	writer := GetKafkaWriter(kafkaURL, topic, 10, 10*time.Second)
//	defer writer.Close()
//
//	ctx := context.Background()
//	reqHeader := make(map[string]*trafficpb.StringList)
//	reqHeader["key"] = &trafficpb.StringList{
//		Values: []string{"val1"},
//	}
//	respHeader := make(map[string]*trafficpb.StringList)
//	reqHeader["key"] = &trafficpb.StringList{
//		Values: []string{"val1"},
//	}
//	payload := &trafficpb.HttpResponseParam{
//		Method:          "Method",
//		Path:            "https://example.com",
//		RequestHeaders:  reqHeader,
//		ResponseHeaders: respHeader,
//		RequestPayload:  "payload1",
//		ResponsePayload: "payload2",
//		Ip:              "172.31.4.22",
//		Time:            int32(time.Now().Unix()),
//		StatusCode:      200,
//		Type:            "type1",
//		Status:          "ok",
//		AktoAccountId:   fmt.Sprint(1000000),
//		AktoVxlanId:     "1000000",
//		IsPending:       false,
//	}
//	Produce(writer, ctx, payload)
//}

//
//func main() {
//	kafkaURL := "192.168.1.11:29092"
//	topic := "akto.api.logs"
//	writer := GetKafkaWriter(kafkaURL, topic, 10, 10*time.Second)
//	defer writer.Close()
//
//	ctx := context.Background()
//	reqHeader := make(map[string]*trafficpb.StringList)
//	reqHeader["key"] = &trafficpb.StringList{
//		Values: []string{"val1"},
//	}
//	respHeader := make(map[string]*trafficpb.StringList)
//	reqHeader["key"] = &trafficpb.StringList{
//		Values: []string{"val1"},
//	}
//	payload := &trafficpb.HttpResponseParam{
//		Method:          "Method",
//		Path:            "https://example.com",
//		RequestHeaders:  reqHeader,
//		ResponseHeaders: respHeader,
//		RequestPayload:  "payload1",
//		ResponsePayload: "payload2",
//		Ip:              "172.31.4.22",
//		Time:            int32(time.Now().Unix()),
//		StatusCode:      422,
//		Type:            "type1",
//		Status:          "ok",
//		AktoAccountId:   fmt.Sprint(1000000),
//		AktoVxlanId:     "1000000",
//		IsPending:       false,
//	}
//	Produce(writer, ctx, payload)
//	Produce(writer, ctx, payload)
//	Produce(writer, ctx, payload)
//	Produce(writer, ctx, payload)
//	//if handle, err := pcap.OpenLive("eth0", 33554392, true, pcap.BlockForever); err != nil {
//	//	log.Fatal(err)
//	//} else {
//	//	run(handle, -1)
//	//}
//}
