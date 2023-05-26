package db

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func accountSettingsInstance() (*mongo.Collection, error) {
	client, err := GetMongoClient()
	if err != nil {
		fmt.Println("Error while getting mongo client for account settings: " + err.Error())
		return nil, err
	}

	return client.Database(AccountID).Collection(AccountSettingsCollectionName), nil

}

func FetchFilterHeaderMap() map[string]string {
	var filterHeaderValueMap = make(map[string]string)

	filter := bson.M{}
	accountSettingsCollection, err := accountSettingsInstance()
	if err != nil {
		return filterHeaderValueMap
	}

	var result bson.M
	err = accountSettingsCollection.FindOne(context.Background(), filter).Decode(&result)
	if err != nil {
		fmt.Println(err)
		return filterHeaderValueMap
	}

	rawFilterHeaderValueMap := result["filterHeaderValueMap"].(primitive.M)

	for k, v := range rawFilterHeaderValueMap {
		filterHeaderValueMap[k] = v.(string)
	}

	fmt.Println("********************************")
	fmt.Println(filterHeaderValueMap)
	fmt.Println("********************************")

	return filterHeaderValueMap
}
