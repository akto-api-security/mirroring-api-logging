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
			kPrev = k
		} else {
			if kPrev+1 != k {
				fmt.Printf("Missing sequence: %v %v - %v - %v\n", kPrev, k, string(bufMap[k]), string(bufMap[kPrev]))
				if string(bufMap[kPrev][:4]) != "HTTP" {
					break
				}
			}
			kPrev = k
		}
		combined = append(combined, bufMap[k]...)
	}

	return combined

}

func (factory *Factory) HandleReadyConnections() {
	trackersToDelete := make(map[structs.ConnID]struct{})

	metaUtils.Debugf("Connections before processing: %v\n", len(factory.connections))
	// utils.LogMemoryStats()
	factory.mutex.Lock()
	defer factory.mutex.Unlock()
	for connID, tracker := range factory.connections {
		if tracker.IsComplete() ||
			tracker.IsInactive(factory.inactivityThreshold) {
			fmt.Printf("Processing request : %v %v\n", connID.Fd, connID.Id)
			trackersToDelete[connID] = struct{}{}
			if len(tracker.sentBuf) == 0 || len(tracker.recvBuf) == 0 {
				continue
			}
			receiveBuffer := convertToSingleByteArr(tracker.recvBuf)
			sentBuffer := convertToSingleByteArr(tracker.sentBuf)

			go tryReadFromBD(receiveBuffer, sentBuffer)
			if !factory.disableEgress {
				// attempt to parse the egress as well by switching the recv and sent buffers.
				go tryReadFromBD(sentBuffer, receiveBuffer)
			}
		}
	}
	// fmt.Printf("Connections before processing: %v\n", len(factory.connections))

	for key := range trackersToDelete {
		delete(factory.connections, key)
	}
	// fmt.Printf("Deleted connections: %v\n", len(trackersToDelete))
	// fmt.Printf("Connections after processing: %v\n", len(factory.connections))
	// utils.LogMemoryStats()
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
