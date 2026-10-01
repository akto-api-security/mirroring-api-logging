//go:build cgo && !windows

package main

import "C"

import (
	"log"
	"os"

	"github.com/google/gopacket/pcap"
)

//export readTcpDumpFile
func readTcpDumpFile(filepath string, kafkaURL string, apiCollectionId int) {
	os.Setenv("AKTO_KAFKA_BROKER_URL", kafkaURL)
	os.Setenv("AKTO_TRAFFIC_BATCH_SIZE", "1")
	os.Setenv("AKTO_TRAFFIC_BATCH_TIME_SECS", "1")

	initKafka()

	if handle, err := pcap.OpenOffline(filepath); err != nil {
		log.Fatal(err)
	} else if packets, err := pcapPackets(handle); err != nil {
		log.Fatal(err)
	} else {
		run(packets, apiCollectionId, "PCAP")
	}
}
