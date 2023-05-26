package db

import (
	"context"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"os"
	"strconv"
	"sync"
)

var (
	clientInstance      *mongo.Client
	clientInstanceError error
	once                sync.Once
)

var AccountID = strconv.Itoa(1_000_000)
var TrafficMetricsCollectionName = "traffic_metrics"
var AccountSettingsCollectionName = "accounts_settings"

func GetMongoClient() (*mongo.Client, error) {
	once.Do(func() {

		//os.Setenv("AKTO_MONGO_CONN", "mongodb://localhost:27017/admini")
		mongoUrl := os.Getenv("AKTO_MONGO_CONN")

		// Define MongoDB client options
		clientOptions := options.Client().ApplyURI(mongoUrl)

		// Connect to MongoDB
		client, err := mongo.Connect(context.Background(), clientOptions)
		if err != nil {
			clientInstanceError = err
		}
		clientInstance = client
	})

	return clientInstance, clientInstanceError
}
