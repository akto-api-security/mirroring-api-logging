package connections

import (
	"fmt"
	"sort"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/structs"
	metaUtils "github.com/akto-api-security/mirroring-api-logging/ebpf/utils"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/kafkaUtil"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"

	"sync"
	"time"
)

// Factory is a routine-safe container that holds a trackers with unique ID, and able to create new tracker.
type Factory struct {
	connections          map[structs.ConnID]*Tracker
	inactivityThreshold  time.Duration
	completeThreshold    time.Duration
	mutex                *sync.RWMutex
	maxActiveConnections int
	disableEgress        bool
}

// NewFactory creates a new instance of the factory.
func NewFactory(inactivityThreshold time.Duration, completeThreshold time.Duration,
	maxActiveConnections int, disableEgress bool) *Factory {
	return &Factory{
		connections:          make(map[structs.ConnID]*Tracker),
		mutex:                &sync.RWMutex{},
		inactivityThreshold:  inactivityThreshold,
		completeThreshold:    completeThreshold,
		maxActiveConnections: maxActiveConnections,
		disableEgress:        disableEgress,
	}
}

var validVerbs = map[string]bool{"GET": true, "POS": true, "PUT": true, "DEL": true, "PAT": true, "HEA": true, "OPT": true, "CON": true, "TRA": true, "HTT": true}

func convertToSingleByteArr(bufMap map[int][]byte) []byte {

	if len(bufMap) == 0 {
		return make([]byte, 0)
	}

	var keys []int
	for k := range bufMap {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	// Append []byte values into a single slice
	var combined []byte

	kPrev := -1
	for _, k := range keys {
		if kPrev == -1 {
			if k != 1 {
				fmt.Printf("Bad start sequence: %v - %v \n", k, string(bufMap[k]))
				break
			}
			kPrev = k
		} else {
			if kPrev+1 != k {
				fmt.Printf("Missing sequence: %v %v - %v - %v\n", kPrev, k, string(bufMap[k]), string(bufMap[kPrev]))
				break
			}
			kPrev = k
		}
		combined = append(combined, bufMap[k]...)
	}

	return combined

}

func calcSize(bufMap map[int][]byte) int {
	ret := 0
	for _, v := range bufMap {
		ret += len(v)
	}
	return ret
}

func ProcessTrackerData(connID structs.ConnID, tracker *Tracker, trackersToDelete map[structs.ConnID]struct{}, isComplete bool) {
	trackersToDelete[connID] = struct{}{}
	if len(tracker.sentBuf) == 0 || len(tracker.recvBuf) == 0 {
		return
	}
	receiveBuffer := convertToSingleByteArr(tracker.recvBuf)
	sentBuffer := convertToSingleByteArr(tracker.sentBuf)

	go tryReadFromBD(receiveBuffer, sentBuffer, isComplete)
	// if !factory.disableEgress {
	// attempt to parse the egress as well by switching the recv and sent buffers.
	go tryReadFromBD(sentBuffer, receiveBuffer, isComplete)
	// }
}

func (factory *Factory) HandleReadyConnections() {
	trackersToDelete := make(map[structs.ConnID]struct{})

	metaUtils.Debugf("Connections before processing: %v\n", len(factory.connections))
	utils.LogMemoryStats()
	factory.mutex.Lock()
	defer factory.mutex.Unlock()

	totalSize := 0

	for connID, tracker := range factory.connections {
		totalSize += calcSize(tracker.sentBuf) + calcSize(tracker.recvBuf) + 20
		isInactive := tracker.IsInactive(factory.inactivityThreshold)
		isComplete := tracker.IsComplete() && tracker.lastAccessTimestamp != 0
		isInvalid := tracker.lastAccessTimestamp == 0

		if isInactive {
			fmt.Printf("Inactive stream : %v %v lens: %v %v\n", connID.Fd, connID.Id, len(tracker.sentBuf), len(tracker.recvBuf))
			ProcessTrackerData(connID, tracker, trackersToDelete, isComplete)
		}

		if isComplete {
			fmt.Printf("Complete stream : %v %v lens: %v %v\n", connID.Fd, connID.Id, len(tracker.sentBuf), len(tracker.recvBuf))
			ProcessTrackerData(connID, tracker, trackersToDelete, isComplete)
		}

		if isInvalid {
			fmt.Printf("Invalid stream marker : %v %v lens: %v %v\n", connID.Fd, connID.Id, len(tracker.sentBuf), len(tracker.recvBuf))
		}
	}
	fmt.Printf("Connections before processing: %v\n", len(factory.connections))
	fmt.Printf("Total size: %v\n", totalSize)

	if totalSize >= 600_000_000 {
		fmt.Printf("Deleting all trackers: %v\n", totalSize)
		for k, _ := range factory.connections {
			trackersToDelete[k] = struct{}{}
		}
	}

	for key := range trackersToDelete {
		delete(factory.connections, key)
	}
	// fmt.Printf("Deleted connections: %v\n", len(trackersToDelete))
	// fmt.Printf("Connections after processing: %v\n", len(factory.connections))
	utils.LogMemoryStats()
	kafkaUtil.LogKafkaError()
}

// GetOrCreate returns a tracker that related to the given connection and transaction ids.
// If there is no such tracker we create a new one.
func (factory *Factory) GetOrCreate(connectionID structs.ConnID) *Tracker {
	factory.mutex.Lock()
	defer factory.mutex.Unlock()
	tracker, ok := factory.connections[connectionID]
	if !ok {
		factory.connections[connectionID] = NewTracker(connectionID)
		return factory.connections[connectionID]
	}
	return tracker
}

func (factory *Factory) CanBeFilled() bool {
	factory.mutex.RLock()
	defer factory.mutex.RUnlock()

	maxConnCheck := len(factory.connections) < factory.maxActiveConnections
	return maxConnCheck
}

var (
	sampleBufferPerMin        = -1 // value in mb
	currentTotalBuffer int64  = 0
	lastPrint          int64  = 0
	bufferMutex               = sync.RWMutex{}
	lastReset          uint64 = uint64(time.Now().UnixMilli())
)

func init() {
	utils.InitVar("TRAFFIC_SAMPLE_BUFFER_PER_MINUTE", &sampleBufferPerMin)
}

func BufferCheck() bool {
	bufferMutex.Lock()
	defer bufferMutex.Unlock()

	if (uint64(time.Now().UnixMilli()) - lastReset) > uint64(time.Minute.Milliseconds()) {
		lastReset = uint64(time.Now().UnixMilli())
		currentTotalBuffer = int64(0)
		lastPrint = int64(0)
		fmt.Printf("Buffer reset: %v %v\n", currentTotalBuffer, lastPrint)
	}

	bufferSampleCheck := (sampleBufferPerMin == -1) || currentTotalBuffer < int64(sampleBufferPerMin*1024*1024)
	return bufferSampleCheck
}

func UpdateBufferSize(bufferSize uint64) {
	bufferMutex.Lock()
	defer bufferMutex.Unlock()

	if sampleBufferPerMin != -1 && currentTotalBuffer < int64(sampleBufferPerMin*1024*1024) {
		currentTotalBuffer += int64(bufferSize)
		if currentTotalBuffer/(1024*1024) > lastPrint {
			lastPrint = currentTotalBuffer / (1024 * 1024)
			fmt.Printf("Current total buffer: %v %v\n", currentTotalBuffer, lastPrint)
		}
	}
}

// Get returns a tracker that related to the given connection and transaction ids.
func (factory *Factory) Get(connectionID structs.ConnID) *Tracker {
	factory.mutex.Lock()
	defer factory.mutex.Unlock()
	return factory.connections[connectionID]
}
