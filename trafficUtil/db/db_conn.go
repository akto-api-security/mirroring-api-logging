package db

import (
	"context"
	"log"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/mongo/readpref"
)

func InitMongoClient() {
	disableOnDb := os.Getenv("AKTO_DISABLE_ON_DB")
	disableOnDbFlag := disableOnDb == "true"

	log.Printf("Disable flag : %t", disableOnDbFlag)

	client, err := GetMongoClient()
	mongoPingErr := client.Ping(context.Background(), readpref.Primary())
	if err != nil || mongoPingErr != nil {
		log.Printf("Failed connecting to mongo %s", err)
		if disableOnDbFlag {
			log.Println("Exiting....")
			time.Sleep(time.Second * 60)
			panic("Failed connecting to mongo") // this will get restarted by docker
		}
	} else {
		log.Printf("Connected to mongo")
	}
}

func CloseMongoClient() {
	client, _ := GetMongoClient()

	if err := client.Disconnect(context.Background()); err != nil {
		// Handle error
		log.Printf("Unable to disconnect mongo client")
	}
}
