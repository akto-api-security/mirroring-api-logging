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

var sequenceCheckSkip = false

func init() {
	utils.InitVar("AKTO_SKIP_SEQUENCE_CHECK", &sequenceCheckSkip)
}

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
			// C sets read, write event count=0 only on new connection open
			// For requests arriving after a time gap on the same underlying connection the 
			// read,write count will not be 1, they will simply continue from the last request
			// This can only be replicated when there is a time gap/inactivityThreshold between requests
			// on the same underlying connection
			if !sequenceCheckSkip && k != 1 {
				slog.Warn("Bad start sequence", "key", k, "value", string(bufMap[k]))
				break
			}
			kPrev = k
		} else {
			if kPrev+1 != k {
				slog.Warn("Missing sequence", "prev", kPrev, "current", k, "value", string(bufMap[k]), "prevValue", string(bufMap[kPrev]))
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
	inactivityThreshold  = 7 * time.Second
	// Value in MB
	bufferMemThreshold = 400

	// unique id of daemonset
	uniqueDaemonsetId          = uuid.New().String()
	trackerDataProcessInterval = 100

	socketDataEventBytesThreshold = 10 * 1024 * 1024

	// When true, use msg_seq based incremental pair flushing instead of
	// waiting for inactivity timer to flush all accumulated data.
	UseMsgSeqFlush = true

	// How often the flush routine checks for complete pairs
	flushTickInterval = 500 * time.Millisecond

	// Per-connection channel buffer size
	perConnChBufferSize = 10
)

func init() {
	utils.InitVar("TRAFFIC_DISABLE_EGRESS", &disableEgress)
	utils.InitVar("TRAFFIC_MAX_ACTIVE_CONN", &maxActiveConnections)
	utils.InitVar("TRAFFIC_INACTIVITY_THRESHOLD", &inactivityThreshold)
	utils.InitVar("TRAFFIC_BUFFER_THRESHOLD", &bufferMemThreshold)
	utils.InitVar("AKTO_MEM_SOFT_LIMIT", &bufferMemThreshold)
	utils.InitVar("TRACKER_DATA_PROCESS_INTERVAL", &trackerDataProcessInterval)
	utils.InitVar("SOCKET_DATA_EVENT_BYTES_THRESHOLD", &socketDataEventBytesThreshold)
	utils.InitVar("MSG_SEQ_FLUSH_ENABLED", &UseMsgSeqFlush)
	utils.InitVar("MSG_SEQ_FLUSH_TICK_INTERVAL", &flushTickInterval)
	utils.InitVar("AKTO_PER_CONN_CH_BUFFER_SIZE", &perConnChBufferSize)
}

func ProcessTrackerData(connID structs.ConnID, tracker *Tracker, isComplete bool) {
	tracker.mutex.Lock()
	defer tracker.mutex.Unlock()

	if len(tracker.sentBuf) == 0 || len(tracker.recvBuf) == 0 {
		return
	}
	receiveBuffer := convertToSingleByteArr(tracker.recvBuf)
	sentBuffer := convertToSingleByteArr(tracker.sentBuf)

	originalInt := uint32(connID.Raddr)
	// Convert integer to little-endian byte slice
	byteSlice := make([]byte, 4)
	binary.LittleEndian.PutUint32(byteSlice, originalInt)
	// Convert the byte slice to an IP address
	ip := net.IP(byteSlice)
	raddrStr := ip.String() + ":" + fmt.Sprint(connID.Rport)

	originalInt = uint32(tracker.laddr)
	byteSlice = make([]byte, 4)
	binary.LittleEndian.PutUint32(byteSlice, originalInt)
	ip = net.IP(byteSlice)
	laddrStr := ip.String() + ":" + fmt.Sprint(tracker.lport)

	hostName := ""
	if kafkaUtil.PodInformerInstance != nil {
		hostName = kafkaUtil.PodInformerInstance.GetPodNameByProcessId(int32(connID.Id >> 32))
	}

	if len(sentBuffer) >= len(httpBytes) && (bytes.Equal(sentBuffer[:len(httpBytes)], httpBytes)) {
		tryReadFromBD(raddrStr, laddrStr, receiveBuffer, sentBuffer, isComplete, 1, connID.Id, connID.Fd, uniqueDaemonsetId, hostName)
	}
	if !disableEgress {
		// attempt to parse the egress as well by switching the recv and sent buffers.
		if len(receiveBuffer) >= len(httpBytes) && (bytes.Equal(receiveBuffer[:len(httpBytes)], httpBytes)) {
			tryReadFromBD(laddrStr, raddrStr, sentBuffer, receiveBuffer, isComplete, 2, connID.Id, connID.Fd, uniqueDaemonsetId, hostName)
		}
	}
}

// ProcessSinglePair processes one request-response pair from msg_seq groups.
func ProcessSinglePair(connID structs.ConnID, tracker *Tracker, g1Blob, g2Blob []byte) {
	tracker.mutex.RLock()
	laddrVal := tracker.laddr
	lportVal := tracker.lport
	tracker.mutex.RUnlock()

	originalInt := uint32(connID.Raddr)
	byteSlice := make([]byte, 4)
	binary.LittleEndian.PutUint32(byteSlice, originalInt)
	ip := net.IP(byteSlice)
	raddrStr := ip.String() + ":" + fmt.Sprint(connID.Rport)

	originalInt = uint32(laddrVal)
	byteSlice = make([]byte, 4)
	binary.LittleEndian.PutUint32(byteSlice, originalInt)
	ip = net.IP(byteSlice)
	laddrStr := ip.String() + ":" + fmt.Sprint(lportVal)

	hostName := ""
	if kafkaUtil.PodInformerInstance != nil {
		hostName = kafkaUtil.PodInformerInstance.GetPodNameByProcessId(int32(connID.Id >> 32))
	}

	// Detect which blob is the response (starts with "HTTP")
	if len(g2Blob) >= len(httpBytes) && bytes.Equal(g2Blob[:len(httpBytes)], httpBytes) {
		// g1=request, g2=response (server ingress path)
		tryReadFromBD(raddrStr, laddrStr, g1Blob, g2Blob, true, 1, connID.Id, connID.Fd, uniqueDaemonsetId, hostName)
	} else if len(g1Blob) >= len(httpBytes) && bytes.Equal(g1Blob[:len(httpBytes)], httpBytes) {
		// g1=response, g2=request (client egress path)
		if !disableEgress {
			tryReadFromBD(laddrStr, raddrStr, g2Blob, g1Blob, true, 2, connID.Id, connID.Fd, uniqueDaemonsetId, hostName)
		}
	} else {
		slog.Warn("msg_seq: neither blob starts with HTTP",
			"fd", connID.Fd,
			"g1_preview", string(g1Blob[:min(32, len(g1Blob))]),
			"g2_preview", string(g2Blob[:min(32, len(g2Blob))]))
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
		utils.LogProcessing("Creating tracker", "fd", connectionID.Fd, "id", connectionID.Id, "timestamp", connectionID.Conn_start_ns, "ip", connectionID.Raddr, "port", connectionID.Rport)
		tracker := NewTracker(connectionID)
		now := uint64(time.Now().UnixNano())
		tracker.openTimestamp = now
		factory.connections[connectionID] = tracker
		ch := make(chan interface{}, perConnChBufferSize)
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

		utils.LogProcessing("Starting go routine", "fd", connID.Fd, "id", connID.Id, "timestamp", connID.Conn_start_ns, "ip", connID.Raddr, "port", connID.Rport)
		inactivityTimer := time.NewTimer(inactivityThreshold)
		delayedDeleteChan := make(chan struct{}, 1)

		// Spawn flush routine if msg_seq flush is enabled
		var done chan struct{}
		if UseMsgSeqFlush {
			done = make(chan struct{})
			go startFlushRoutine(connID, tracker, done)
		}

		for {
			select {
			case event := <-ch:
				// Handle event based on its type
				switch e := event.(type) {
				case *structs.SocketDataEvent:
					utils.LogProcessing("Received data event", "fd", connID.Fd, "id", connID.Id, "timestamp", connID.Conn_start_ns, "ip", connID.Raddr, "port", connID.Rport)
					tracker.AddDataEvent(*e)

					if !UseMsgSeqFlush && tracker.GetSentBytes()+tracker.GetRecvBytes() > uint64(socketDataEventBytesThreshold) {
						utils.LogProcessing("Socket Data threshold data breached, processing current data", "fd", connID.Fd, "id", connID.Id, "timestamp", connID.Conn_start_ns, "ip", connID.Raddr, "port", connID.Rport)
						factory.StopProcessing(connID)
						return
					} else {
						resetTimer(inactivityTimer, inactivityThreshold)
					}
				case *structs.SocketOpenEvent:
					utils.LogProcessing("Received open event", "fd", connID.Fd, "id", connID.Id, "timestamp", connID.Conn_start_ns, "ip", connID.Raddr, "port", connID.Rport)
					tracker.AddOpenEvent(*e)
					resetTimer(inactivityTimer, inactivityThreshold)
				case *structs.SocketCloseEvent:
					utils.LogProcessing("Received close event", "fd", connID.Fd, "id", connID.Id, "timestamp", connID.Conn_start_ns, "ip", connID.Raddr, "port", connID.Rport)
					tracker.AddCloseEvent(*e)

					time.AfterFunc(100*time.Millisecond, func() {
						delayedDeleteChan <- struct{}{}
					})
				}

			case <-delayedDeleteChan:
				utils.LogProcessing("Stopping go routine (delayed close)", "fd", connID.Fd, "id", connID.Id, "timestamp", connID.Conn_start_ns, "ip", connID.Raddr, "port", connID.Rport)
				if UseMsgSeqFlush {
					close(done) // signal flush routine to do final flush and exit
					factory.DeleteWorker(connID)
				} else {
					factory.StopProcessing(connID)
				}
				return

			case <-inactivityTimer.C:
				utils.LogProcessing("Inactivity threshold reached, marking connection as inactive and processing", "fd", connID.Fd, "id", connID.Id, "timestamp", connID.Conn_start_ns, "ip", connID.Raddr, "port", connID.Rport)
				if UseMsgSeqFlush {
					slog.Info("msg_seq: inactivity flush",
						"fd", connID.Fd,
						"remaining_groups", len(tracker.msgGroups),
						"lowest_pending", tracker.lowestPendingSeq,
						"highest", tracker.highestMsgSeq)
					close(done) // signal flush routine to do final flush and exit
					factory.DeleteWorker(connID)
				} else {
					factory.StopProcessing(connID)
				}
				utils.LogProcessing("Stopping go routine", "fd", connID.Fd, "id", connID.Id, "timestamp", connID.Conn_start_ns, "ip", connID.Raddr, "port", connID.Rport)
				return
			}
		}
	}(connectionID, tracker, ch)
}

// startFlushRoutine runs in its own goroutine, periodically flushing complete
// msg_seq pairs. Exits when done channel is closed, doing a final flush before returning.
func startFlushRoutine(connID structs.ConnID, tracker *Tracker, done <-chan struct{}) {
	ticker := time.NewTicker(flushTickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			pairs := tracker.GetFlushablePairs()
			for _, pair := range pairs {
				g1Blob := convertToSingleByteArr(pair.ReqGroup.chunks)
				g2Blob := convertToSingleByteArr(pair.RespGroup.chunks)

				slog.Info("msg_seq: processing pair (tick)",
					"fd", connID.Fd,
					"g1_msg_seq", pair.ReqGroup.msgSeq,
					"g2_msg_seq", pair.RespGroup.msgSeq,
					"g1_bytes", len(g1Blob),
					"g2_bytes", len(g2Blob))

				ProcessSinglePair(connID, tracker, g1Blob, g2Blob)
			}
			if len(pairs) > 0 {
				slog.Info("msg_seq: flushed pairs (tick)",
					"fd", connID.Fd,
					"pairs_flushed", len(pairs))
			}

		case <-done:
			// Final flush of all remaining pairs before exit
			slog.Info("msg_seq: flush routine exiting, final flush",
				"fd", connID.Fd,
				"remaining_groups", len(tracker.msgGroups))
			flushAndProcessRemainingPairs(connID, tracker)
			return
		}
	}
}

func flushAndProcessRemainingPairs(connID structs.ConnID, tracker *Tracker) {
	pairs := tracker.FlushRemainingPairs()
	for _, pair := range pairs {
		g1Blob := convertToSingleByteArr(pair.ReqGroup.chunks)
		g2Blob := convertToSingleByteArr(pair.RespGroup.chunks)

		slog.Info("msg_seq: processing remaining pair",
			"fd", connID.Fd,
			"g1_msg_seq", pair.ReqGroup.msgSeq,
			"g2_msg_seq", pair.RespGroup.msgSeq,
			"g1_bytes", len(g1Blob),
			"g2_bytes", len(g2Blob))

		ProcessSinglePair(connID, tracker, g1Blob, g2Blob)
	}
	if len(pairs) > 0 {
		slog.Info("msg_seq: flushed remaining pairs",
			"fd", connID.Fd,
			"pairs_flushed", len(pairs))
	}
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
		utils.LogProcessing("Deleted event channel", "fd", connectionID.Fd, "id", connectionID.Id, "timestamp", connectionID.Conn_start_ns, "ip", connectionID.Raddr, "port", connectionID.Rport)
	}

	if _, exists := factory.connections[connectionID]; exists {
		delete(factory.connections, connectionID)
		utils.LogProcessing("Deleted connection", "fd", connectionID.Fd, "id", connectionID.Id, "timestamp", connectionID.Conn_start_ns, "ip", connectionID.Raddr, "port", connectionID.Rport)
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
			utils.LogProcessing("Deleting all trackers at mem", "mem", mem)
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
		utils.LogProcessing("Received event", "fd", connectionID.Fd, "id", connectionID.Id, "timestamp", connectionID.Conn_start_ns, "ip", connectionID.Raddr, "port", connectionID.Rport)
		defer func() {
			if r := recover(); r != nil {
				// Recover from a panic, caused by sending to a closed channel
				utils.LogProcessing("Attempted to send on a closed channel for connectionId", "connectionId", connectionID)
			}
		}()
		select {
		case ch <- event: // Try sending the event to the worker's channel
			utils.LogProcessing("Sent event", "fd", connectionID.Fd, "id", connectionID.Id, "timestamp", connectionID.Conn_start_ns, "ip", connectionID.Raddr, "port", connectionID.Rport)
		default: // Avoid blocking if the channel is full
			slog.Warn("Dropping event Channel full", "fd", connectionID.Fd, "ch_len", len(ch), "ch_cap", cap(ch))
		}
	} else {
		utils.LogProcessing("No worker found for", "connectionId", connectionID)
	}
}
