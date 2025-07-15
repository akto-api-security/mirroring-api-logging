package connections

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/structs"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/kafkaUtil"
	"github.com/google/uuid"
)

var httpBytes = []byte("HTTP")

// Factory is a routine-safe container that holds a trackers with unique ID, and able to create new tracker.
type Factory struct {
	processor        map[structs.ConnID]chan interface{}
	connections      map[structs.ConnID]*Tracker
	mutex            *sync.RWMutex
	trackersToDelete sync.Map
}

// NewFactory creates a new instance of the factory.
func NewFactory() *Factory {
	f := &Factory{
		processor:        make(map[structs.ConnID]chan interface{}),
		connections:      make(map[structs.ConnID]*Tracker),
		mutex:            &sync.RWMutex{},
		trackersToDelete: sync.Map{},
	}

	f.StartCleanupWorker()
	return f
}

func (factory *Factory) StartCleanupWorker() {
	go func() {
		for {
			time.Sleep(100 * time.Millisecond)

			now := time.Now()
			factory.trackersToDelete.Range(func(key, value interface{}) bool {
				connID := key.(structs.ConnID)
				markedAt := value.(time.Time)

				if now.Sub(markedAt) > time.Duration(trackerDataProcessInterval)*time.Millisecond {
					factory.ProcessAndStopWorker(connID)
					factory.forceDeleteWorker(connID)
					factory.trackersToDelete.Delete(connID)
				}
				return true
			})
		}
	}()
}

func (factory *Factory) forceDeleteWorker(connectionID structs.ConnID) {
	factory.mutex.Lock()
	defer factory.mutex.Unlock()

	if ch, exists := factory.processor[connectionID]; exists {
		close(ch)
		delete(factory.processor, connectionID)
		slog.Debug("Deleted event channel", "fd", connectionID.Fd, "id", connectionID.Id, "timestamp", connectionID.Conn_start_ns, "ip", connectionID.Ip, "port", connectionID.Port)
	}

	if _, exists := factory.connections[connectionID]; exists {
		delete(factory.connections, connectionID)
		slog.Debug("Deleted connection", "fd", connectionID.Fd, "id", connectionID.Id, "timestamp", connectionID.Conn_start_ns, "ip", connectionID.Ip, "port", connectionID.Port)
		requestProcessCount++
	}

	if (time.Now().UnixMilli())-lastMemCheck > int64(memCheckInterval) {
		lastMemCheck = time.Now().UnixMilli()
		mem := utils.LogMemoryStats()

		utils.PrintLog("Requests processed", "count", requestProcessCount, "lastMemCheck", lastMemCheck)
		utils.PrintLog("connection factory size", "connections", len(factory.connections), "processors", len(factory.processor), "lastMemCheck", lastMemCheck)
		requestProcessCount = 0
		if mem >= bufferMemThreshold {
			trackersToDelete := make(map[structs.ConnID]struct{})
			for k := range factory.connections {
				trackersToDelete[k] = struct{}{}
			}
			for key := range trackersToDelete {
				if ch, exists := factory.processor[key]; exists {
					close(ch)
					delete(factory.processor, key)
				}
				delete(factory.connections, key)
			}
		}
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
				utils.LogProcessing("Bad start sequence", "key", k, "value", string(bufMap[k]))
				break
			}
			kPrev = k
		} else {
			if kPrev+1 != k {
				utils.LogProcessing("Missing sequence", "prev", kPrev, "current", k, "value", string(bufMap[k]), "prevValue", string(bufMap[kPrev]))
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

	// unique id of daemonset
	uniqueDaemonsetId          = uuid.New().String()
	trackerDataProcessInterval = 100
)

func init() {
	utils.InitVar("TRAFFIC_DISABLE_EGRESS", &disableEgress)
	utils.InitVar("TRAFFIC_MAX_ACTIVE_CONN", &maxActiveConnections)
	utils.InitVar("TRAFFIC_INACTIVITY_THRESHOLD", &inactivityThreshold)
	utils.InitVar("TRAFFIC_BUFFER_THRESHOLD", &bufferMemThreshold)
	utils.InitVar("AKTO_MEM_SOFT_LIMIT", &bufferMemThreshold)
	utils.InitVar("TRACKER_DATA_PROCESS_INTERVAL", &trackerDataProcessInterval)
}

func ProcessTrackerData(connID structs.ConnID, tracker *Tracker, isComplete bool) {
	tracker.mutex.Lock()
	defer tracker.mutex.Unlock()

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

	hostName := kafkaUtil.PodInformerInstance.GetPodNameByProcessId(int32(connID.Id>>32))

	if len(sentBuffer) >= len(httpBytes) && (bytes.Equal(sentBuffer[:len(httpBytes)], httpBytes)) {
		tryReadFromBD(destIpStr, srcIpStr, receiveBuffer, sentBuffer, isComplete, 1, connID.Id, connID.Fd, uniqueDaemonsetId, hostName)
	}
	if !disableEgress {
		// attempt to parse the egress as well by switching the recv and sent buffers.
		if len(receiveBuffer) >= len(httpBytes) && (bytes.Equal(receiveBuffer[:len(httpBytes)], httpBytes)) {
			tryReadFromBD(srcIpStr, destIpStr, sentBuffer, receiveBuffer, isComplete, 2, connID.Id, connID.Fd, uniqueDaemonsetId, hostName)
		}
	}
}

func (factory *Factory) CanBeFilled() bool {
	factory.mutex.RLock()
	defer factory.mutex.RUnlock()

	maxConnCheck := len(factory.connections) < maxActiveConnections
	return maxConnCheck
}

var (
	sampleBufferPerMin        = -1
	currentTotalBuffer int64  = 0
	lastPrint          int64  = 0
	bufferMutex               = sync.RWMutex{}
	lastReset          uint64 = uint64(time.Now().UnixMilli())
	// in milliseconds
	memCheckInterval    = 500
	requestProcessCount = 0
	lastMemCheck        = time.Now().UnixMilli()
)

func init() {
	utils.InitVar("TRAFFIC_SAMPLE_BUFFER_PER_MINUTE", &sampleBufferPerMin)
	utils.InitVar("MODULE_MEM_CHECK_INTERVAL", &memCheckInterval)
}

func BufferCheck() bool {
	bufferMutex.Lock()
	defer bufferMutex.Unlock()

	if (uint64(time.Now().UnixMilli()) - lastReset) > uint64(time.Minute.Milliseconds()) {
		lastReset = uint64(time.Now().UnixMilli())
		currentTotalBuffer = int64(0)
		lastPrint = int64(0)
		utils.LogIngest("Buffer reset", "currentTotalBuffer", currentTotalBuffer, "lastPrint", lastPrint)
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
			slog.Debug("Current total buffer", "buffer", currentTotalBuffer, "lastPrint", lastPrint)
		}
	}
}

func (factory *Factory) CreateIfNotExists(connectionID structs.ConnID) {
	factory.mutex.Lock()
	defer factory.mutex.Unlock()

	_, exists := factory.connections[connectionID]
	if !exists {
		utils.LogProcessing("Creating tracker", "fd", connectionID.Fd, "id", connectionID.Id, "timestamp", connectionID.Conn_start_ns, "ip", connectionID.Ip, "port", connectionID.Port)
		tracker := NewTracker(connectionID)
		now := uint64(time.Now().UnixNano())
		tracker.openTimestamp = now
		factory.connections[connectionID] = tracker
		ch := make(chan interface{}, 10)
		factory.processor[connectionID] = ch
		factory.StartWorker(connectionID, tracker, ch)
	}
}

func (factory *Factory) StartWorker(connectionID structs.ConnID, tracker *Tracker, ch chan interface{}) {
	go func(connID structs.ConnID, tracker *Tracker, ch chan interface{}) {

		utils.LogProcessing("Starting go routine", "fd", connID.Fd, "id", connID.Id, "timestamp", connID.Conn_start_ns, "ip", connID.Ip, "port", connID.Port)
		inactivityTimer := time.NewTimer(inactivityThreshold)

		for {
			select {
			case event := <-ch:
				// Handle event based on its type
				switch e := event.(type) {
				case *structs.SocketDataEvent:
					utils.LogProcessing("Received data event", "fd", connID.Fd, "id", connID.Id, "timestamp", connID.Conn_start_ns, "ip", connID.Ip, "port", connID.Port)
					tracker.AddDataEvent(*e)
				case *structs.SocketOpenEvent:
					utils.LogProcessing("Received open event", "fd", connID.Fd, "id", connID.Id, "timestamp", connID.Conn_start_ns, "ip", connID.Ip, "port", connID.Port)
					tracker.AddOpenEvent(*e)
				case *structs.SocketCloseEvent:
					utils.LogProcessing("Received close event", "fd", connID.Fd, "id", connID.Id, "timestamp", connID.Conn_start_ns, "ip", connID.Ip, "port", connID.Port)
					tracker.AddCloseEvent(*e)
					factory.DeleteWorker(connID)
					utils.LogProcessing("Stopping go routine", "fd", connID.Fd, "id", connID.Id, "timestamp", connID.Conn_start_ns, "ip", connID.Ip, "port", connID.Port)
				}

			case <-inactivityTimer.C:
				// Eat the go routine after inactive threshold, process the tracker and stop the worker
				utils.LogProcessing("Inactivity threshold reached, marking connection as inactive and processing", "fd", connID.Fd, "id", connID.Id, "timestamp", connID.Conn_start_ns, "ip", connID.Ip, "port", connID.Port)
				factory.DeleteWorker(connID)
				utils.LogProcessing("Stopping go routine", "fd", connID.Fd, "id", connID.Id, "timestamp", connID.Conn_start_ns, "ip", connID.Ip, "port", connID.Port)
				return
			}
		}
	}(connectionID, tracker, ch)
}

func (factory *Factory) ProcessAndStopWorker(connectionID structs.ConnID) {
	tracker, connExists := factory.getTracker(connectionID)
	if connExists {
		ProcessTrackerData(connectionID, tracker, tracker.IsComplete())
	}
}

// StopWorker gracefully stops the worker for a connectionId.
func (factory *Factory) DeleteWorker(connectionID structs.ConnID) {
	factory.mutex.Lock()
	defer factory.mutex.Unlock()
	factory.trackersToDelete.Store(connectionID, time.Now())
}

func (factory *Factory) getChannel(connectionID structs.ConnID) (chan interface{}, bool) {
	factory.mutex.RLock()
	defer factory.mutex.RUnlock()
	ch, exists := factory.processor[connectionID]
	return ch, exists
}

func (factory *Factory) getTracker(connectionID structs.ConnID) (*Tracker, bool) {
	factory.mutex.RLock()
	defer factory.mutex.RUnlock()
	tracker, exists := factory.connections[connectionID]
	return tracker, exists
}

// SendEvent sends any type of event (open, data, close) to the appropriate worker via the channel.
func (factory *Factory) SendEvent(connectionID structs.ConnID, event interface{}) {
	ch, exists := factory.getChannel(connectionID)

	if exists {
		utils.LogProcessing("Received event", "fd", connectionID.Fd, "id", connectionID.Id, "timestamp", connectionID.Conn_start_ns, "ip", connectionID.Ip, "port", connectionID.Port)
		defer func() {
			if r := recover(); r != nil {
				// Recover from a panic, caused by sending to a closed channel
				utils.LogProcessing("Attempted to send on a closed channel for connectionId", "connectionId", connectionID)
			}
		}()
		select {
		case ch <- event: // Try sending the event to the worker's channel
			utils.LogProcessing("Sent event", "fd", connectionID.Fd, "id", connectionID.Id, "timestamp", connectionID.Conn_start_ns, "ip", connectionID.Ip, "port", connectionID.Port)
		default: // Avoid blocking if the channel is full
			utils.LogProcessing("Dropping event Channel full", "connectionId", connectionID)
		}
	} else {
		utils.LogProcessing("No worker found for", "connectionId", connectionID)
	}
}
