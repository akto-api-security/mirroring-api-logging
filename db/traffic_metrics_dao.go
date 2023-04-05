package db

import (
	"context"
	"fmt"
	"github.com/akto-api-security/mirroring-api-logging/utils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"log"
	"strconv"
)

func trafficMetricsInstance() (*mongo.Collection, error) {
	client, err := GetMongoClient()
	if err != nil {
		fmt.Println("Error while getting mongo client for traffic metrics: " + err.Error())
		return nil, err
	}

	return client.Database(AccountID).Collection(TrafficMetricsCollectionName), nil

}

func TrafficMetricsDbUpdates(incomingCountMap map[string]utils.IncomingCounter, outgoingCountMap map[string]utils.OutgoingCounter) {
	// Insert the document into the MongoDB collection
	trafficMetricsCollection, err := trafficMetricsInstance()
	if err != nil {
		return
	}
	var incomingOperations []mongo.WriteModel

	fmt.Printf("incoming count map: %d", len(incomingCountMap))
	fmt.Printf("outgoing count map: %d", len(outgoingCountMap))

	for _, value := range incomingCountMap {
		filter := buildFilter(value.VxlanID, value.Ip, "", "INCOMING_PACKETS_MIRRORING", value.BucketStartEpoch, value.BucketEndEpoch)
		operation := buildOperation(filter, value.PacketHoursToCountMap)
		incomingOperations = append(incomingOperations, operation)
	}

	var outgoingPacketOperations []mongo.WriteModel
	var outgoingRequestOperations []mongo.WriteModel
	for _, value := range outgoingCountMap {
		filter1 := buildFilter(value.VxlanID, value.Ip, value.Host, "OUTGOING_PACKETS_MIRRORING", value.BucketStartEpoch, value.BucketEndEpoch)

		outgoingPacketOperation := buildOperation(filter1, value.PacketHoursToCountMap)
		outgoingPacketOperations = append(outgoingPacketOperations, outgoingPacketOperation)

		filter2 := buildFilter(value.VxlanID, value.Ip, value.Host, "OUTGOING_REQUESTS_MIRRORING", value.BucketStartEpoch, value.BucketEndEpoch)
		outgoingRequestOperation := buildOperation(filter2, value.RequestsHoursToCountMap)
		outgoingRequestOperations = append(outgoingRequestOperations, outgoingRequestOperation)
	}

	// Execute the update operation
	executeBulkUpdateOperation(incomingOperations, trafficMetricsCollection)
	executeBulkUpdateOperation(outgoingPacketOperations, trafficMetricsCollection)
	executeBulkUpdateOperation(outgoingRequestOperations, trafficMetricsCollection)
}

func buildFilter(vxlanID int, ip string, host string, name string, bucketStartEpoch int, bucketEndEpoch int) bson.M {
	filter := []interface{}{
		bson.M{"_id.vxlanID": vxlanID},
		bson.M{"_id.ip": ip},
		bson.M{"_id.name": name},
		bson.M{"_id.bucketStartEpoch": bucketStartEpoch},
		bson.M{"_id.bucketEndEpoch": bucketEndEpoch},
	}

	if len(host) > 0 {
		filter = append(filter, bson.M{"_id.host": host})
	}

	return bson.M{"$and": filter}
}

func executeBulkUpdateOperation(operations []mongo.WriteModel, collection *mongo.Collection) {
	if len(operations) > 0 {
		result, err := collection.BulkWrite(context.Background(), operations)

		if err != nil {
			log.Printf("Error while updating collection: %s", err.Error())
		} else {
			log.Printf("Successfully updated: %d; inserted: %d; deleted: %d; upserted: %d", result.ModifiedCount, result.InsertedCount, result.DeletedCount, result.UpsertedCount)
		}
	} else {
		log.Println("Skipping updates because nothing in list")
	}
}

func buildOperation(filter bson.M, countMap utils.HoursToCountMap) *mongo.UpdateOneModel {
	fields := make(map[string]int)
	for k, v := range countMap {
		fields["countMap."+strconv.Itoa(k)] = v
	}

	update := bson.M{"$inc": fields}

	operation := mongo.NewUpdateOneModel().SetFilter(filter).SetUpdate(update).SetUpsert(true)
	return operation
}
