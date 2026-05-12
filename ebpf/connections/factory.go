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
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/kafkaUtil"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
	"github.com/google/uuid"
)

var httpBytes = []byte("HTTP")

// Factory is a routine-safe container that holds a trackers with unique ID, and able to create new tracker.
type Factory struct {
	processor   map[structs.ConnID]chan interface{}
	connections map[structs.ConnID]*Tracker
	mutex       *sync.RWMutex
}

// NewFactory creates a new instance of the factory.
func NewFactory() *Factory {
	return &Factory{
		processor:   make(map[structs.ConnID]chan interface{}),
		connections: make(map[structs.ConnID]*Tracker),
		mutex:       &sync.RWMutex{},
	}
}

func previewFirstChunk(chunks [][]byte) string {
	if len(chunks) == 0 || len(chunks[0]) == 0 {
		return ""
	}
	b := chunks[0]
	if len(b) > 64 {
		return string(b[:64])
	}
	return string(b)
}

// joinPartsMap merges ordered chunks per sequence key into one []byte at flush.
func joinPartsMap(connID structs.ConnID, partsMap map[int][][]byte) []byte {
	if len(partsMap) == 0 {
		return make([]byte, 0)
	}

	var keys []int
	for k := range partsMap {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	var combined []byte
	logEnabled := utils.ProcessLogsEnabled()
	kPrev := -1
	for _, k := range keys {
		if kPrev == -1 {
			if !sequenceCheckSkip && k != 1 {
				if logEnabled {
					utils.LogProcessing("Bad start sequence", append(structs.ConnIDLogArgs(connID), "key", k, "value", previewFirstChunk(partsMap[k]))...)
				}
				break
			}
			kPrev = k
		} else {
			if kPrev+1 != k {
				if logEnabled {
					utils.LogProcessing("Missing sequence", append(structs.ConnIDLogArgs(connID), "prev", kPrev, "current", k, "value", previewFirstChunk(partsMap[k]), "prevValue", previewFirstChunk(partsMap[kPrev]))...)
				}
				break
			}
			kPrev = k
		}
		combined = append(combined, bytes.Join(partsMap[k], nil)...)
	}

	return combined
}

var (
	disableEgress        = false
	maxActiveConnections = 4096
	inactivityThreshold  = 7 * time.Second
	// Value in MB
	bufferMemThreshold = 400

	// unique id of daemonset
	uniqueDaemonsetId          = uuid.New().String()
	trackerDataProcessInterval = 100

	socketDataEventBytesThreshold = 10 * 1024 * 1024
	sequenceCheckSkip             = false
)

func init() {
	utils.InitVar("AKTO_SKIP_SEQUENCE_CHECK", &sequenceCheckSkip)
}

func init() {
	utils.InitVar("TRAFFIC_DISABLE_EGRESS", &disableEgress)
	utils.InitVar("TRAFFIC_MAX_ACTIVE_CONN", &maxActiveConnections)
	utils.InitVar("TRAFFIC_INACTIVITY_THRESHOLD", &inactivityThreshold)
	utils.InitVar("TRAFFIC_BUFFER_THRESHOLD", &bufferMemThreshold)
	utils.InitVar("AKTO_MEM_SOFT_LIMIT", &bufferMemThreshold)
	utils.InitVar("TRACKER_DATA_PROCESS_INTERVAL", &trackerDataProcessInterval)
	utils.InitVar("SOCKET_DATA_EVENT_BYTES_THRESHOLD", &socketDataEventBytesThreshold)
}

func ProcessTrackerData(connID structs.ConnID, tracker *Tracker, isComplete bool) {
	tracker.mutex.Lock()
	defer tracker.mutex.Unlock()

	if len(tracker.sentParts) == 0 || len(tracker.recvParts) == 0 {
		return
	}
	receiveBuffer := joinPartsMap(connID, tracker.recvParts)
	sentBuffer := joinPartsMap(connID, tracker.sentParts)

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

	hostName := ""
	if kafkaUtil.PodInformerInstance != nil {
		hostName = kafkaUtil.PodInformerInstance.GetPodNameByProcessId(int32(connID.Id >> 32))
	}

	if len(sentBuffer) >= len(httpBytes) && (bytes.Equal(sentBuffer[:len(httpBytes)], httpBytes)) {
		tryReadFromBD(destIpStr, srcIpStr, receiveBuffer, sentBuffer, isComplete, 1, connID.Id, connID.Fd, uniqueDaemonsetId, hostName, connID)
	}
	if !disableEgress {
		// attempt to parse the egress as well by switching the recv and sent buffers.
		if len(receiveBuffer) >= len(httpBytes) && (bytes.Equal(receiveBuffer[:len(httpBytes)], httpBytes)) {
			tryReadFromBD(srcIpStr, destIpStr, sentBuffer, receiveBuffer, isComplete, 2, connID.Id, connID.Fd, uniqueDaemonsetId, hostName, connID)
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
	if sampleBufferPerMin == -1 {
		return true
	}

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
	if sampleBufferPerMin == -1 {
		return
	}

	bufferMutex.Lock()
	defer bufferMutex.Unlock()

	if currentTotalBuffer < int64(sampleBufferPerMin*1024*1024) {
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
		if utils.ProcessLogsEnabled() {
			utils.LogProcessing("Creating tracker", structs.ConnIDLogArgs(connectionID)...)
		}
		tracker := NewTracker(connectionID)
		now := uint64(time.Now().UnixNano())
		tracker.openTimestamp = now
		factory.connections[connectionID] = tracker
		ch := make(chan interface{}, 10)
		factory.processor[connectionID] = ch
		factory.StartWorker(connectionID, tracker, ch)
	}
}

// resetTimer stops, drains, and resets the timer to the given duration.
func resetTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}

// Worker lifecycle:
//
//	 ACTIVE:
//	   - socket data/open -> reset inactivity timer on each event
//	   - socket close     -> schedule delayed termination
//	   - inactivity timer -> terminate immediately
//
//	 TERMINATION is final and happens exactly once.
//	either due to inactivityThreshold or due to socker close event
func (factory *Factory) StartWorker(connectionID structs.ConnID, tracker *Tracker, ch chan interface{}) {
	go func(connID structs.ConnID, tracker *Tracker, ch chan interface{}) {
		logEnabled := utils.ProcessLogsEnabled()

		if logEnabled {
			utils.LogProcessing("Starting go routine", structs.ConnIDLogArgs(connID)...)
		}
		inactivityTimer := time.NewTimer(inactivityThreshold)
		delayedDeleteChan := make(chan struct{}, 1)

		for {
			select {
			case event := <-ch:
				switch e := event.(type) {
				case *structs.SocketDataPayload:
					if logEnabled {
						utils.LogProcessing("Received data event", structs.ConnIDLogArgs(connID)...)
					}
					tracker.AddDataPayload(e)
					if tracker.GetSentBytes()+tracker.GetRecvBytes() > uint64(socketDataEventBytesThreshold) {
						if logEnabled {
							utils.LogProcessing("Socket Data threshold data breached, processing current data", structs.ConnIDLogArgs(connID)...)
						}
						factory.StopProcessing(connID)
						return
					} else {
						resetTimer(inactivityTimer, inactivityThreshold)
					}
				case structs.SocketOpenEvent:
					if logEnabled {
						utils.LogProcessing("Received open event", structs.ConnIDLogArgs(connID)...)
					}
					tracker.AddOpenEvent(e)
					resetTimer(inactivityTimer, inactivityThreshold)
				case structs.SocketCloseEvent:
					if logEnabled {
						utils.LogProcessing("Received close event", structs.ConnIDLogArgs(connID)...)
					}
					tracker.AddCloseEvent(e)

					time.AfterFunc(100*time.Millisecond, func() {
						delayedDeleteChan <- struct{}{}
					})
				}

			case <-delayedDeleteChan:
				if logEnabled {
					utils.LogProcessing("Stopping go routine (delayed close)", structs.ConnIDLogArgs(connID)...)
				}
				factory.StopProcessing(connID)
				return

			case <-inactivityTimer.C:
				if logEnabled {
					utils.LogProcessing("Inactivity threshold reached, marking connection as inactive and processing", structs.ConnIDLogArgs(connID)...)
				}
				factory.StopProcessing(connID)
				return
			}
		}
	}(connectionID, tracker, ch)
}

func (factory *Factory) StopProcessing(connID structs.ConnID) {
	factory.ProcessAndStopWorker(connID)
	factory.DeleteWorker(connID)
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

	if ch, exists := factory.processor[connectionID]; exists {
		close(ch)
		delete(factory.processor, connectionID)
		if utils.ProcessLogsEnabled() {
			utils.LogProcessing("Deleted event channel", structs.ConnIDLogArgs(connectionID)...)
		}
	}

	if _, exists := factory.connections[connectionID]; exists {
		delete(factory.connections, connectionID)
		if utils.ProcessLogsEnabled() {
			utils.LogProcessing("Deleted connection", structs.ConnIDLogArgs(connectionID)...)
		}
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
			if utils.ProcessLogsEnabled() {
				utils.LogProcessing("Deleting all trackers at mem", "mem", mem)
			}
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

func (factory *Factory) getTracker(connectionID structs.ConnID) (*Tracker, bool) {
	factory.mutex.RLock()
	defer factory.mutex.RUnlock()
	tracker, exists := factory.connections[connectionID]
	return tracker, exists
}

func (factory *Factory) getChannel(connectionID structs.ConnID) (chan interface{}, bool) {
	factory.mutex.RLock()
	defer factory.mutex.RUnlock()
	ch, exists := factory.processor[connectionID]
	return ch, exists
}

// SendEvent sends any type of event (open, data, close) to the appropriate worker via the channel.
func (factory *Factory) SendEvent(connectionID structs.ConnID, event interface{}) {
	ch, exists := factory.getChannel(connectionID)

	if exists {
		if utils.ProcessLogsEnabled() {
			utils.LogProcessing("Received event", structs.ConnIDLogArgs(connectionID)...)
		}
		defer func() {
			if r := recover(); r != nil {
				if utils.ProcessLogsEnabled() {
					utils.LogProcessing("Attempted to send on a closed channel for connectionId", "connectionId", connectionID)
				}
			}
		}()
		select {
		case ch <- event:
			if utils.ProcessLogsEnabled() {
				utils.LogProcessing("Sent event", structs.ConnIDLogArgs(connectionID)...)
			}
		default:
			if utils.ProcessLogsEnabled() {
				utils.LogProcessing("Dropping event Channel full", "connectionId", connectionID)
			}
		}
	} else {
		if utils.ProcessLogsEnabled() {
			utils.LogProcessing("No worker found for", "connectionId", connectionID)
		}
	}
}
