package db

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
)

type LogDocument struct {
	Log       string `bson:"log"`
	Key       string `bson:"key"`
	Timestamp int64  `bson:"timestamp"`
}

var (
	logBuffer      []LogDocument
	bufferLock     sync.Mutex
	batchSize      = 1000
	logCollection  *mongo.Collection
	insertInterval = time.Second * 60
)

func init() {
	collection, err := logsInstance()
	if err != nil {
		log.Fatalf("Error while getting mongo client for logs: %v", err)
	}
	logCollection = collection

	go periodicInsert()
}

func logsInstance() (*mongo.Collection, error) {
	client, err := GetMongoClient()
	if err != nil {
		fmt.Println("Error while getting mongo client for logs: " + err.Error())
		return nil, err
	}

	return client.Database(AccountID).Collection(LogsCollectionName), nil
}

func InsertLog(logString string, key string) {
	log.Println(logString)

	logString += "MIRRORING: " + logString

	logDoc := LogDocument{
		Log:       logString,
		Key:       key,
		Timestamp: time.Now().Unix(),
	}

	bufferLock.Lock()
	logBuffer = append(logBuffer, logDoc)
	if len(logBuffer) >= batchSize {
		flushLogs()
	}
	bufferLock.Unlock()
}

func flushLogs() {
	if len(logBuffer) == 0 {
		return
	}

	_, err := logCollection.InsertMany(context.Background(), toInterfaceSlice(logBuffer))
	if err != nil {
		fmt.Println("Error while inserting logs: " + err.Error())
	} else {
		fmt.Println("Logs inserted successfully")
	}
	logBuffer = logBuffer[:0] // reset the buffer
}

func toInterfaceSlice(logs []LogDocument) []interface{} {
	interfaceSlice := make([]interface{}, len(logs))
	for i, d := range logs {
		interfaceSlice[i] = d
	}
	return interfaceSlice
}

func periodicInsert() {
	for {
		time.Sleep(insertInterval)
		bufferLock.Lock()
		flushLogs()
		bufferLock.Unlock()
	}
}
