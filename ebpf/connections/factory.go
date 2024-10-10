package connections

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"

	"sync"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/structs"
	metaUtils "github.com/akto-api-security/mirroring-api-logging/ebpf/utils"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/kafkaUtil"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

// Factory is a routine-safe container that holds a trackers with unique ID, and able to create new tracker.
type Factory struct {
	connections map[structs.ConnID]*Tracker
	mutex       *sync.RWMutex
}

// NewFactory creates a new instance of the factory.
func NewFactory() *Factory {
	return &Factory{
		connections: make(map[structs.ConnID]*Tracker),
		mutex:       &sync.RWMutex{},
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
			if k != 1 {
				metaUtils.LogProcessing("Bad start sequence: %v - %v \n", k, string(bufMap[k]))
				break
			}
			kPrev = k
		} else {
			if kPrev+1 != k {
				metaUtils.LogProcessing("Missing sequence: %v %v - %v - %v\n", kPrev, k, string(bufMap[k]), string(bufMap[kPrev]))
				break
			}
			kPrev = k
		}
		combined = append(combined, bufMap[k]...)
	}

	return combined

}

var (
	disableEgress        = false
	maxActiveConnections = 4096
	inactivityThreshold  = 3 * time.Second
	// Value in MB
	bufferMemThreshold = 400
)

func init() {
	utils.InitVar("TRAFFIC_DISABLE_EGRESS", &disableEgress)
	utils.InitVar("TRAFFIC_MAX_ACTIVE_CONN", &maxActiveConnections)
	utils.InitVar("TRAFFIC_INACTIVITY_THRESHOLD", &inactivityThreshold)
	utils.InitVar("TRAFFIC_BUFFER_THRESHOLD", &bufferMemThreshold)
	utils.InitVar("AKTO_MEM_SOFT_LIMIT", &bufferMemThreshold)
}

func ProcessTrackerData(connID structs.ConnID, tracker *Tracker, isComplete bool) {
	if len(tracker.sentBuf) == 0 || len(tracker.recvBuf) == 0 {
		return
	}
	receiveBuffer := convertToSingleByteArr(tracker.recvBuf)
	sentBuffer := convertToSingleByteArr(tracker.sentBuf)

	originalInt := uint32(connID.Ip)
	// Convert integer to little-endian byte slice
	byteSlice := make([]byte, 4)
	binary.LittleEndian.PutUint32(byteSlice, originalInt)
	// Convert the byte slice to an IP address
	ip := net.IP(byteSlice)
	destIpStr := ip.String() + ":" + fmt.Sprint(connID.Port)

	originalInt = uint32(tracker.srcIp)
	byteSlice = make([]byte, 4)
	binary.LittleEndian.PutUint32(byteSlice, originalInt)
	ip = net.IP(byteSlice)
	srcIpStr := ip.String() + ":" + fmt.Sprint(tracker.srcPort)

	tryReadFromBD(destIpStr, srcIpStr, receiveBuffer, sentBuffer, isComplete, 1)
	if !disableEgress {
		// attempt to parse the egress as well by switching the recv and sent buffers.
		tryReadFromBD(srcIpStr, destIpStr, sentBuffer, receiveBuffer, isComplete, 2)
	}
}

func (factory *Factory) HandleReadyConnections() {
	trackersToDelete := make(map[structs.ConnID]struct{})

	metaUtils.LogProcessing("Connections before processing: %v\n", len(factory.connections))
	factory.mutex.Lock()
	defer factory.mutex.Unlock()

	totalSize := 0
	for connID, tracker := range factory.connections {
		totalSize += int(tracker.sentBytes) + int(tracker.recvBytes) + 20
		isInactive := tracker.MarkInactive(inactivityThreshold)
		isComplete := tracker.IsComplete() && tracker.openTimestamp != 0
		isInvalid := tracker.openTimestamp == 0

		if isInactive {
			metaUtils.LogProcessing("Inactive stream : %v %v %v lens: %v %v\n", connID.Fd, connID.Id, connID.Conn_start_ns, len(tracker.sentBuf), len(tracker.recvBuf))
			ProcessTrackerData(connID, tracker, isComplete)
			trackersToDelete[connID] = struct{}{}
			continue
		}

		if isComplete {
			metaUtils.LogProcessing("Complete stream : %v %v %v lens: %v %v\n", connID.Fd, connID.Id, connID.Conn_start_ns, len(tracker.sentBuf), len(tracker.recvBuf))
			ProcessTrackerData(connID, tracker, isComplete)
			trackersToDelete[connID] = struct{}{}
			continue
		}

		if isInvalid {
			metaUtils.LogProcessing("Invalid stream : %v %v %v lens: %v %v\n", connID.Fd, connID.Id, connID.Conn_start_ns, len(tracker.sentBuf), len(tracker.recvBuf))
			trackersToDelete[connID] = struct{}{}
		}
	}
	metaUtils.LogProcessing("Connections before processing: %v\n", len(factory.connections))
	metaUtils.LogProcessing("Total processed data size: %v\n", totalSize)

	mem := utils.LogMemoryStats()
	if mem >= bufferMemThreshold {
		metaUtils.LogProcessing("Deleting all trackers at mem: %v \n", mem)
		for k := range factory.connections {
			trackersToDelete[k] = struct{}{}
		}
	}

	for key := range trackersToDelete {
		delete(factory.connections, key)
	}
	metaUtils.LogProcessing("Deleted connections: %v\n", len(trackersToDelete))
	metaUtils.LogProcessing("Connections after processing: %v\n", len(factory.connections))
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
		now := uint64(time.Now().UnixNano())
		factory.connections[connectionID].openTimestamp = now
		return factory.connections[connectionID]
	}
	return tracker
}

func (factory *Factory) CanBeFilled() bool {
	factory.mutex.RLock()
	defer factory.mutex.RUnlock()

	maxConnCheck := len(factory.connections) < maxActiveConnections
	return maxConnCheck
}

var (
	// default sampling of 100mb / min
	sampleBufferPerMin        = 100
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
		metaUtils.LogIngest("Buffer reset: %v %v\n", currentTotalBuffer, lastPrint)
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
			metaUtils.LogIngest("Current total buffer: %v %v\n", currentTotalBuffer, lastPrint)
		}
	}
}

// Get returns a tracker that related to the given connection and transaction ids.
func (factory *Factory) Get(connectionID structs.ConnID) *Tracker {
	factory.mutex.Lock()
	defer factory.mutex.Unlock()
	return factory.connections[connectionID]
}

func (factory *Factory) ProcessAndDelete(connectionID structs.ConnID) {
	factory.mutex.Lock()
	defer factory.mutex.Unlock()
	_, ok := factory.connections[connectionID]
	if ok {
		ProcessTrackerData(connectionID, factory.connections[connectionID], true)
		delete(factory.connections, connectionID)
	}
}
