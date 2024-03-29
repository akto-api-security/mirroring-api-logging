package connections

import (
	"fmt"

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

func (factory *Factory) HandleReadyConnections() {
	trackersToDelete := make(map[structs.ConnID]struct{})

	metaUtils.Debugf("Connections before processing: %v\n", len(factory.connections))
	// utils.LogMemoryStats()
	factory.mutex.Lock()
	defer factory.mutex.Unlock()
	for connID, tracker := range factory.connections {
		if tracker.IsComplete(factory.completeThreshold) ||
			tracker.IsBufferOverflow() {
			trackersToDelete[connID] = struct{}{}
			if len(tracker.sentBuf) == 0 || len(tracker.recvBuf) == 0 {
				continue
			}

			wg := new(sync.WaitGroup)
			for seq, receiveBuffer := range tracker.recvBuf {
				sentBuffer, exists := tracker.sentBuf[seq]
				if exists {
					metaUtils.Debugf("Processing: %v\n", seq)
					wg.Add(1)
					go tryReadFromBD(receiveBuffer, sentBuffer, wg, seq)
					if !factory.disableEgress {
						// attempt to parse the egress as well by switching the recv and sent buffers.
						wg.Add(1)
						go tryReadFromBD(sentBuffer, receiveBuffer, wg, seq)
					}
				}
			}
			wg.Wait()
		} else if tracker.IsInactive(factory.inactivityThreshold) {
			trackersToDelete[connID] = struct{}{}
		}
	}
	for key := range trackersToDelete {
		delete(factory.connections, key)
	}
	metaUtils.Debugf("Deleted connections: %v\n", len(trackersToDelete))
	metaUtils.Debugf("Connections after processing: %v\n", len(factory.connections))
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
