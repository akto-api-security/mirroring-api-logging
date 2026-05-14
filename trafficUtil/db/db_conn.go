package db

import (
	"context"
	"log/slog"
	"time"

	"go.mongodb.org/mongo-driver/mongo/readpref"

	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

var disableOnDbFlag = false

func init() {
	utils.InitVar("AKTO_DISABLE_ON_DB", &disableOnDbFlag)
}

func InitMongoClient() {
	slog.Debug("Disable flag", "flag", disableOnDbFlag)

	client, err := GetMongoClient()
	mongoPingErr := client.Ping(context.Background(), readpref.Primary())
	if err != nil || mongoPingErr != nil {
		slog.Error("Failed connecting to mongo", "error", err)
		if disableOnDbFlag {
			slog.Debug("Exiting....")
			time.Sleep(time.Second * 60)
			panic("Failed connecting to mongo") // this will get restarted by docker
		}
	} else {
		slog.Info("Connected to mongo")
	}
}

func CloseMongoClient() {
	client, _ := GetMongoClient()

	if err := client.Disconnect(context.Background()); err != nil {
		// Handle error
		slog.Error("Unable to disconnect mongo client")
	}
}
