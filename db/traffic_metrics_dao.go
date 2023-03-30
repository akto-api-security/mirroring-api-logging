package db

import "go.mongodb.org/mongo-driver/mongo"

func TrafficMetricsInstance() *mongo.Collection {
	client, err := GetMongoClient()
	if err != nil {
		// Handle error
	}

	return client.Database("1000000").Collection("traffic_metrics")

}
