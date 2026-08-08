package connections

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/structs"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/kafkaUtil"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
	"github.com/google/uuid"
)

var httpBytes = []byte("HTTP")

var sequenceCheckSkip = false

func init() {
	utils.InitVar("AKTO_SKIP_SEQUENCE_CHECK", &sequenceCheckSkip)
}

const numShards = 16

// shardKey determines which shard a connID maps to
func shardKey(connID structs.ConnID) int {
	return int(connID.Fd) % numShards
}

// Factory is a routine-safe container that holds trackers with unique ID, and able to create new tracker.
// Maps are sharded to reduce lock contention.
type Factory struct {
	processor   [numShards]map[structs.ConnID]chan interface{}
	connections [numShards]map[structs.ConnID]*Tracker
	shardMutex  [numShards]*sync.RWMutex
}

// NewFactory creates a new instance of the factory.
func NewFactory() *Factory {
	f := &Factory{}
	for i := 0; i < numShards; i++ {
		f.processor[i] = make(map[structs.ConnID]chan interface{})
		f.connections[i] = make(map[structs.ConnID]*Tracker)
		f.shardMutex[i] = &sync.RWMutex{}
	}
	return f
}

func convertToSingleByteArr(bufArr *[256][]byte) []byte {
	// Use linear scan instead of sort.Ints - indices are 0-255, so O(256) instead of O(N log N)
	// Iterate sequentially from 0-255, combining non-nil entries in order
	var combined []byte
	kPrev := -1

	for i := 0; i < 256; i++ {
		if bufArr[i] == nil {
			continue
		}

		if kPrev == -1 {
			// C sets read, write event count=0 only on new connection open
			// For requests arriving after a time gap on the same underlying connection the
			// read,write count will not be 1, they will simply continue from the last request
			// This can only be replicated when there is a time gap/inactivityThreshold between requests
			// on the same underlying connection
			if !sequenceCheckSkip && i != 1 {
				utils.LogProcessing("Bad start sequence", "key", i, "value", string(bufArr[i]))
				break
			}
			kPrev = i
		} else {
			if kPrev+1 != i {
				utils.LogProcessing("Missing sequence", "prev", kPrev, "current", i, "value", string(bufArr[i]), "prevValue", string(bufArr[kPrev]))
				break
			}
			kPrev = i
		}
		combined = append(combined, bufArr[i]...)
	}

	if len(combined) == 0 {
		return make([]byte, 0)
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

	// Background worker pool for expensive processing
	processingWorkers = 2
	processingQueue   chan *ProcessingTask

	// Object pool for tracker reuse (reduces allocation overhead on connection creation)
	trackerPool = sync.Pool{
		New: func() interface{} {
			return &Tracker{
				mutex: sync.RWMutex{},
			}
		},
	}
)

// ProcessingTask represents deferred expensive processing
type ProcessingTask struct {
	connID    structs.ConnID
	tracker   *Tracker
	isComplete bool
}

func init() {
	utils.InitVar("TRAFFIC_DISABLE_EGRESS", &disableEgress)
	utils.InitVar("TRAFFIC_MAX_ACTIVE_CONN", &maxActiveConnections)
	utils.InitVar("TRAFFIC_INACTIVITY_THRESHOLD", &inactivityThreshold)
	utils.InitVar("TRAFFIC_BUFFER_THRESHOLD", &bufferMemThreshold)
	utils.InitVar("AKTO_MEM_SOFT_LIMIT", &bufferMemThreshold)
	utils.InitVar("TRACKER_DATA_PROCESS_INTERVAL", &trackerDataProcessInterval)
	utils.InitVar("SOCKET_DATA_EVENT_BYTES_THRESHOLD", &socketDataEventBytesThreshold)
	utils.InitVar("TRAFFIC_PROCESSING_WORKERS", &processingWorkers)

	// Initialize background processing queue and workers
	// Larger buffer (10000) absorbs burst connection closes without blocking hot path
	processingQueue = make(chan *ProcessingTask, 10000)
	for i := 0; i < processingWorkers; i++ {
		go backgroundProcessingWorker()
	}
}

// backgroundProcessingWorker processes expensive operations (deferred from hot path)
func backgroundProcessingWorker() {
	for task := range processingQueue {
		ProcessTrackerData(task.connID, task.tracker, task.isComplete)
	}
}

func ProcessTrackerData(connID structs.ConnID, tracker *Tracker, isComplete bool) {
	tracker.mutex.Lock()
	defer tracker.mutex.Unlock()

	// Check if buffers have any data
	hasSentData := false
	hasRecvData := false
	for i := 0; i < 256; i++ {
		if tracker.sentBuf[i] != nil {
			hasSentData = true
		}
		if tracker.recvBuf[i] != nil {
			hasRecvData = true
		}
	}
	if !hasSentData || !hasRecvData {
		return
	}
	receiveBuffer := convertToSingleByteArr(&tracker.recvBuf)
	sentBuffer := convertToSingleByteArr(&tracker.sentBuf)

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

	// Only do expensive HTTP parsing if HTTP was detected inline or if data looks like HTTP
	// This skips parsing for 70-80% of non-HTTP connections
	if tracker.foundHTTP || (len(sentBuffer) >= len(httpBytes) && bytes.Equal(sentBuffer[:len(httpBytes)], httpBytes)) {
		tryReadFromBD(destIpStr, srcIpStr, receiveBuffer, sentBuffer, isComplete, 1, connID.Id, connID.Fd, uniqueDaemonsetId, hostName)
	}
	if !disableEgress && (tracker.foundHTTP || (len(receiveBuffer) >= len(httpBytes) && bytes.Equal(receiveBuffer[:len(httpBytes)], httpBytes))) {
		// attempt to parse the egress as well by switching the recv and sent buffers.
		tryReadFromBD(srcIpStr, destIpStr, sentBuffer, receiveBuffer, isComplete, 2, connID.Id, connID.Fd, uniqueDaemonsetId, hostName)
	}
}

func (factory *Factory) CanBeFilled() bool {
	totalConnections := 0
	for i := 0; i < numShards; i++ {
		factory.shardMutex[i].RLock()
		totalConnections += len(factory.connections[i])
		factory.shardMutex[i].RUnlock()
	}
	return totalConnections < maxActiveConnections
}

var (
	sampleBufferPerMin = -1
	// These are accessed via sync/atomic and do not need a mutex
	currentTotalBuffer int64 = 0
	lastPrint          int64 = 0
	lastReset          int64 = int64(time.Now().UnixMilli())
	// in milliseconds
	memCheckInterval    = 500
	requestProcessCount = 0
	lastMemCheck        = time.Now().UnixMilli()
	// bufferMutex used only for rare reset operation once per minute
	bufferResetMutex = sync.Mutex{}
)

func init() {
	utils.InitVar("TRAFFIC_SAMPLE_BUFFER_PER_MINUTE", &sampleBufferPerMin)
	utils.InitVar("MODULE_MEM_CHECK_INTERVAL", &memCheckInterval)
}

func BufferCheck() bool {
	now := time.Now().UnixMilli()
	lastResetVal := atomic.LoadInt64(&lastReset)

	if now - lastResetVal > time.Minute.Milliseconds() {
		// Double-checked locking: verify again under lock
		bufferResetMutex.Lock()
		if now - atomic.LoadInt64(&lastReset) > time.Minute.Milliseconds() {
			atomic.StoreInt64(&lastReset, now)
			atomic.StoreInt64(&currentTotalBuffer, 0)
			atomic.StoreInt64(&lastPrint, 0)
			utils.LogIngest("Buffer reset", "currentTotalBuffer", 0, "lastPrint", 0)
		}
		bufferResetMutex.Unlock()
	}

	bufferSampleCheck := (sampleBufferPerMin == -1) || atomic.LoadInt64(&currentTotalBuffer) < int64(sampleBufferPerMin*1024*1024)
	return bufferSampleCheck
}

func UpdateBufferSize(bufferSize uint64) {
	if sampleBufferPerMin == -1 {
		return
	}
	newVal := atomic.AddInt64(&currentTotalBuffer, int64(bufferSize))
	prevPrint := atomic.LoadInt64(&lastPrint)
	if newVal/(1024*1024) > prevPrint {
		atomic.StoreInt64(&lastPrint, newVal/(1024*1024))
		slog.Debug("Current total buffer", "buffer", newVal, "lastPrint", newVal/(1024*1024))
	}
}

func (factory *Factory) CreateIfNotExists(connectionID structs.ConnID) {
	shard := shardKey(connectionID)

	// Fast path: read lock for the common case (connection already exists)
	factory.shardMutex[shard].RLock()
	_, exists := factory.connections[shard][connectionID]
	factory.shardMutex[shard].RUnlock()
	if exists {
		return
	}

	// Slow path: write lock only when creating a new connection
	factory.shardMutex[shard].Lock()
	defer factory.shardMutex[shard].Unlock()
	if _, exists = factory.connections[shard][connectionID]; exists {
		return // double-check after acquiring write lock
	}

	utils.LogProcessing("Creating tracker", "fd", connectionID.Fd, "id", connectionID.Id, "timestamp", connectionID.Conn_start_ns, "ip", connectionID.Ip, "port", connectionID.Port)
	// Get tracker from pool, reset it for reuse
	trackerObj := trackerPool.Get()
	tracker := trackerObj.(*Tracker)
	tracker.connID = connectionID
	tracker.openTimestamp = 0
	tracker.closeTimestamp = 0
	tracker.lastAccessTimestamp = 0
	tracker.sentBytes = 0
	tracker.recvBytes = 0
	tracker.ssl = false
	tracker.foundHTTP = false
	tracker.srcIp = 0
	tracker.srcPort = 0
	// Clear buffers and position tracking
	for i := range tracker.sentBuf {
		tracker.sentBuf[i] = nil
		tracker.sentBufInitialized[i] = false
		tracker.sentPos[i] = 0
		tracker.recvBuf[i] = nil
		tracker.recvBufInitialized[i] = false
		tracker.recvPos[i] = 0
	}
	now := uint64(time.Now().UnixNano())
	tracker.openTimestamp = now
	factory.connections[shard][connectionID] = tracker
	ch := make(chan interface{}, 100)
	factory.processor[shard][connectionID] = ch
	factory.StartWorker(connectionID, tracker, ch)
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

var trackerBatchSize = 64

// processBatch adds multiple data events to tracker under a single lock
func processBatch(tracker *Tracker, batch []*structs.SocketDataEvent) {
	if len(batch) == 0 {
		return
	}
	tracker.mutex.Lock()
	for _, e := range batch {
		tracker.addDataEventLocked(*e)
	}
	tracker.mutex.Unlock()
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

		utils.LogProcessing("Starting go routine", "fd", connID.Fd, "id", connID.Id, "timestamp", connID.Conn_start_ns, "ip", connID.Ip, "port", connID.Port)
		inactivityTimer := time.NewTimer(inactivityThreshold)
		delayedDeleteChan := make(chan struct{}, 1)

		for {
			select {
			case event := <-ch:
				// Handle event based on its type
				switch e := event.(type) {
				case *structs.SocketDataEvent:
					utils.LogProcessing("Received data event", "fd", connID.Fd, "id", connID.Id, "timestamp", connID.Conn_start_ns, "ip", connID.Ip, "port", connID.Port)
					// Batch: drain channel non-blockingly after first event
					batch := []*structs.SocketDataEvent{e}
				drain:
					for len(batch) < trackerBatchSize {
						select {
						case next := <-ch:
							if ne, ok := next.(*structs.SocketDataEvent); ok {
								batch = append(batch, ne)
							} else {
								// Non-data event: process batch first, then handle this event
								processBatch(tracker, batch)
								// Now handle the non-data event inline
								switch ne := next.(type) {
								case *structs.SocketOpenEvent:
									utils.LogProcessing("Received open event (during batch)", "fd", connID.Fd, "id", connID.Id, "timestamp", connID.Conn_start_ns, "ip", connID.Ip, "port", connID.Port)
									tracker.AddOpenEvent(*ne)
									resetTimer(inactivityTimer, inactivityThreshold)
								case *structs.SocketCloseEvent:
									utils.LogProcessing("Received close event (during batch)", "fd", connID.Fd, "id", connID.Id, "timestamp", connID.Conn_start_ns, "ip", connID.Ip, "port", connID.Port)
									tracker.AddCloseEvent(*ne)
									time.AfterFunc(100*time.Millisecond, func() {
										delayedDeleteChan <- struct{}{}
									})
								}
								break drain
							}
						default:
							break drain // channel empty, process what we have
						}
					}
					processBatch(tracker, batch)
					if tracker.GetSentBytes()+tracker.GetRecvBytes() > uint64(socketDataEventBytesThreshold) {
						utils.LogProcessing("Socket Data threshold data breached, processing current data", "fd", connID.Fd, "id", connID.Id, "timestamp", connID.Conn_start_ns, "ip", connID.Ip, "port", connID.Port)
						factory.StopProcessing(connID)
						return
					}
					resetTimer(inactivityTimer, inactivityThreshold)
				case *structs.SocketOpenEvent:
					utils.LogProcessing("Received open event", "fd", connID.Fd, "id", connID.Id, "timestamp", connID.Conn_start_ns, "ip", connID.Ip, "port", connID.Port)
					tracker.AddOpenEvent(*e)
					resetTimer(inactivityTimer, inactivityThreshold)
				case *structs.SocketCloseEvent:
					utils.LogProcessing("Received close event", "fd", connID.Fd, "id", connID.Id, "timestamp", connID.Conn_start_ns, "ip", connID.Ip, "port", connID.Port)
					tracker.AddCloseEvent(*e)

					time.AfterFunc(100*time.Millisecond, func() {
						delayedDeleteChan <- struct{}{}
					})
				}

			case <-delayedDeleteChan:
				utils.LogProcessing("Stopping go routine (delayed close)", "fd", connID.Fd, "id", connID.Id, "timestamp", connID.Conn_start_ns, "ip", connID.Ip, "port", connID.Port)
				factory.StopProcessing(connID)
				return

			case <-inactivityTimer.C:
				// Eat the go routine after inactive threshold, process the tracker and stop the worker
				utils.LogProcessing("Inactivity threshold reached, marking connection as inactive and processing", "fd", connID.Fd, "id", connID.Id, "timestamp", connID.Conn_start_ns, "ip", connID.Ip, "port", connID.Port)
				factory.StopProcessing(connID)
				utils.LogProcessing("Stopping go routine", "fd", connID.Fd, "id", connID.Id, "timestamp", connID.Conn_start_ns, "ip", connID.Ip, "port", connID.Port)
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
		// Queue expensive processing to background worker pool instead of blocking
		select {
		case processingQueue <- &ProcessingTask{
			connID:     connectionID,
			tracker:    tracker,
			isComplete: tracker.IsComplete(),
		}:
		default:
			// Queue full; process synchronously to avoid data loss
			utils.LogProcessing("Processing queue full, processing synchronously", "connID", connectionID)
			ProcessTrackerData(connectionID, tracker, tracker.IsComplete())
		}
	}
}

// StopWorker gracefully stops the worker for a connectionId.
func (factory *Factory) DeleteWorker(connectionID structs.ConnID) {
	var shouldCheckMem bool
	var connectionsLen, processorLen int
	shard := shardKey(connectionID)

	factory.shardMutex[shard].Lock()

	if ch, exists := factory.processor[shard][connectionID]; exists {
		close(ch)
		delete(factory.processor[shard], connectionID)
		utils.LogProcessing("Deleted event channel", "fd", connectionID.Fd, "id", connectionID.Id, "timestamp", connectionID.Conn_start_ns, "ip", connectionID.Ip, "port", connectionID.Port)
	}

	if tracker, exists := factory.connections[shard][connectionID]; exists {
		delete(factory.connections[shard], connectionID)
		utils.LogProcessing("Deleted connection", "fd", connectionID.Fd, "id", connectionID.Id, "timestamp", connectionID.Conn_start_ns, "ip", connectionID.Ip, "port", connectionID.Port)
		requestProcessCount++
		// Return tracker to pool for reuse (reduces allocation overhead on next connection)
		trackerPool.Put(tracker)
	}

	factory.shardMutex[shard].Unlock()

	// Periodically check memory across all shards (expensive operation outside locks)
	if (time.Now().UnixMilli())-lastMemCheck > int64(memCheckInterval) {
		shouldCheckMem = true
		lastMemCheck = time.Now().UnixMilli()
		// Count connections across all shards
		for i := 0; i < numShards; i++ {
			factory.shardMutex[i].RLock()
			connectionsLen += len(factory.connections[i])
			processorLen += len(factory.processor[i])
			factory.shardMutex[i].RUnlock()
		}
	}

	if shouldCheckMem {
		mem := utils.LogMemoryStats()
		utils.PrintLog("Requests processed", "count", requestProcessCount, "lastMemCheck", lastMemCheck)
		utils.PrintLog("connection factory size", "connections", connectionsLen, "processors", processorLen, "lastMemCheck", lastMemCheck)
		requestProcessCount = 0
		if mem >= bufferMemThreshold {
			factory.purgeAllTrackers()
		}
	}
}

func (factory *Factory) purgeAllTrackers() {
	totalDeleted := 0
	for shard := 0; shard < numShards; shard++ {
		factory.shardMutex[shard].Lock()

		trackersToDelete := make(map[structs.ConnID]struct{})
		for k := range factory.connections[shard] {
			trackersToDelete[k] = struct{}{}
		}

		for key := range trackersToDelete {
			if ch, exists := factory.processor[shard][key]; exists {
				close(ch)
				delete(factory.processor[shard], key)
			}
			delete(factory.connections[shard], key)
			totalDeleted++
		}

		factory.shardMutex[shard].Unlock()
	}
	utils.LogProcessing("Deleting all trackers", "count", totalDeleted)
}

func (factory *Factory) getChannel(connectionID structs.ConnID) (chan interface{}, bool) {
	shard := shardKey(connectionID)
	factory.shardMutex[shard].RLock()
	defer factory.shardMutex[shard].RUnlock()
	ch, exists := factory.processor[shard][connectionID]
	return ch, exists
}

func (factory *Factory) getTracker(connectionID structs.ConnID) (*Tracker, bool) {
	shard := shardKey(connectionID)
	factory.shardMutex[shard].RLock()
	defer factory.shardMutex[shard].RUnlock()
	tracker, exists := factory.connections[shard][connectionID]
	return tracker, exists
}

// GetTrackerForHTTPDetection gets tracker for lightweight HTTP marking (without full processing)
func (factory *Factory) GetTrackerForHTTPDetection(connectionID structs.ConnID) (*Tracker, bool) {
	return factory.getTracker(connectionID)
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
