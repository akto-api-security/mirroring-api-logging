package db

import (
	"context"
	"strconv"
	"sync"

	trafficUtils "github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
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
		mongoUrl := "mongodb://0.0.0.0:27017/admini"
		trafficUtils.InitVar("AKTO_MONGO_CONN", mongoUrl)

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
