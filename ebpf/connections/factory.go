package connections

import (
	"fmt"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/structs"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/kafkaUtil"

	// "fmt"
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
	maxBufferPerTracker  int
	sampleBufferPerMin   int
	disableEgress        bool
	currentTotalBuffer   int64
	bufferStartTime      uint64
}

// NewFactory creates a new instance of the factory.
func NewFactory(inactivityThreshold time.Duration, completeThreshold time.Duration,
	maxActiveConnections int, maxBufferPerTracker int, sampleBufferPerMin int, disableEgress bool) *Factory {
	return &Factory{
		connections:          make(map[structs.ConnID]*Tracker),
		mutex:                &sync.RWMutex{},
		inactivityThreshold:  inactivityThreshold,
		completeThreshold:    completeThreshold,
		maxActiveConnections: maxActiveConnections,
		maxBufferPerTracker:  maxBufferPerTracker,
		sampleBufferPerMin:   sampleBufferPerMin,
		disableEgress:        disableEgress,
	}
}

func (factory *Factory) HandleReadyConnections() {
	trackersToDelete := make(map[structs.ConnID]struct{})
	// factory.mutex.Lock()
	// defer factory.mutex.Unlock()
	var bytesIn = 0
	for connID, tracker := range factory.connections {
		if tracker.IsComplete(factory.completeThreshold) {
			trackersToDelete[connID] = struct{}{}
			if len(tracker.sentBuf) == 0 || len(tracker.recvBuf) == 0 {
				continue
			}
			fmt.Printf("Tracker info: %v %v %v %v %v", tracker.connID.Conn_start_ns, tracker.connID.Fd, tracker.connID.Id, tracker.connID.Ip, tracker.connID.Port)
			tryReadFromBD(tracker)
			if !factory.disableEgress {
				// attempt to parse the egress as well by switching the recv and sent buffers.
				// TODO: change this approach (use local vars.) as it gives simultaneous read-write error, on a specific set of params.
				temp := tracker.recvBuf
				tracker.recvBuf = tracker.sentBuf
				tracker.sentBuf = temp
				tryReadFromBD(tracker)
			}
			bytesIn += len(tracker.recvBuf) + len(tracker.sentBuf)

		} else if tracker.IsInactive(factory.inactivityThreshold) || tracker.IsBufferOverflow(factory.maxBufferPerTracker) {
			trackersToDelete[connID] = struct{}{}
		}
	}
	factory.mutex.Lock()
	defer factory.mutex.Unlock()
	for key := range trackersToDelete {
		delete(factory.connections, key)
	}

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

	bufferSampleCheck := (factory.sampleBufferPerMin == -1) || factory.currentTotalBuffer < int64(factory.sampleBufferPerMin*1024*1024)

	return maxConnCheck && bufferSampleCheck
}

func (factory *Factory) UpdateBufferSize(bufferSize uint64) {
	factory.mutex.RLock()
	defer factory.mutex.RUnlock()

	if factory.sampleBufferPerMin != -1 && factory.currentTotalBuffer < int64(factory.sampleBufferPerMin*1024*1024) {
		factory.currentTotalBuffer += int64(bufferSize)
		fmt.Printf("Current total buffer:%v\n", factory.currentTotalBuffer)
	}

	if uint64(time.Now().UnixNano())-factory.bufferStartTime > uint64(time.Minute.Nanoseconds()) {
		factory.bufferStartTime = uint64(time.Now().UnixNano())
		factory.currentTotalBuffer = 0
	}
}

// Get returns a tracker that related to the given connection and transaction ids.
func (factory *Factory) Get(connectionID structs.ConnID) *Tracker {
	factory.mutex.Lock()
	defer factory.mutex.Unlock()
	return factory.connections[connectionID]
}
