package db

import (
	"fmt"
	"go.mongodb.org/mongo-driver/mongo"
)

func TrafficMetricsInstance() (*mongo.Collection, error) {
	client, err := GetMongoClient()
	if err != nil {
		fmt.Println("Error while getting mongo client for traffic metrics: " + err.Error())
		return nil, err
	}

	return client.Database("1000000").Collection("traffic_metrics"), nil

}
