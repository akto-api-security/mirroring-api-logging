package db

import (
	"context"
	"log/slog"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func accountSettingsInstance() (*mongo.Collection, error) {
	client, err := GetMongoClient()
	if err != nil {
		slog.Error("Error while getting mongo client for account settings", "error", err)
		return nil, err
	}

	return client.Database(AccountID).Collection(AccountSettingsCollectionName), nil

}

func FetchFilterHeaderMap() map[string]string {
	var filterHeaderValueMap = make(map[string]string)

	filter := bson.M{}
	accountSettingsCollection, err := accountSettingsInstance()
	if err != nil {
		slog.Error("Error while getting account settings", "error", err)
		return filterHeaderValueMap
	}

	var result bson.M
	err = accountSettingsCollection.FindOne(context.Background(), filter).Decode(&result)
	if err != nil {
		slog.Error("Error while getting account settings", "error", err)
		return filterHeaderValueMap
	}

	if result["filterHeaderValueMap"] != nil {
		rawFilterHeaderValueMap := result["filterHeaderValueMap"].(primitive.M)
		for k, v := range rawFilterHeaderValueMap {
			filterHeaderValueMap[k] = v.(string)
		}
	}

	slog.Debug("Filter header map", "map", filterHeaderValueMap)

	return filterHeaderValueMap
}
