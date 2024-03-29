package trafficMetrics

import (
	"log"
	"sync"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/db"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

var incomingCountMap = make(map[string]utils.IncomingCounter)
var outgoingCountMap = make(map[string]utils.OutgoingCounter)

var outgoingCountMapMutex = sync.RWMutex{}

func InitTrafficMaps() {
	incomingCountMap = make(map[string]utils.IncomingCounter)
	outgoingCountMap = make(map[string]utils.OutgoingCounter)
}

func SubmitIncomingTrafficMetrics(ic utils.IncomingCounter, payloadLength int) {
	existingIC, ok := incomingCountMap[ic.IncomingCounterKey()]
	if ok {
		existingIC.Inc(payloadLength)
	} else {
		ic.Inc(payloadLength)
		incomingCountMap[ic.IncomingCounterKey()] = ic
	}
}

func SubmitOutgoingTrafficMetrics(oc utils.OutgoingCounter, outgoingBytes int) {
	outgoingCountMapMutex.Lock()
	defer outgoingCountMapMutex.Unlock()
	existingOc, ok := outgoingCountMap[oc.OutgoingCounterKey()]
	if ok {
		existingOc.Inc(outgoingBytes, 1)
	} else {
		oc.Inc(outgoingBytes, 1)
		outgoingCountMap[oc.OutgoingCounterKey()] = oc
	}
}

var FilterHeaderValueMap = make(map[string]string)

func tickerCode() {
	log.Println("Running ticker")
	db.TrafficMetricsDbUpdates(incomingCountMap, outgoingCountMap)
	InitTrafficMaps()
	FilterHeaderValueMap = db.FetchFilterHeaderMap()
}

func StartMetricsTicker() {
	// Set up a ticker to run every 2 minutes
	ticker := time.NewTicker(2 * time.Minute)

	tickerCode() // to run this immediately
	go func() {
		for range ticker.C {
			tickerCode()
		}
	}()
}
