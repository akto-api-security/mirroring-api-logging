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

func convertToSingleByteArr(bufMap map[int][]byte, skipSequenceCheck bool) []byte {

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
			if !skipSequenceCheck && !sequenceCheckSkip && k != 1 {
				utils.LogProcessing("Bad start sequence", "key", k, "value", string(bufMap[k]))
				break
			}
			kPrev = k
		} else {
			if !skipSequenceCheck && kPrev+1 != k {
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
	inactivityThreshold  = 7 * time.Second
	// Value in MB
	bufferMemThreshold = 400

	// unique id of daemonset
	uniqueDaemonsetId          = uuid.New().String()
	trackerDataProcessInterval = 100

	socketDataEventBytesThreshold = 10 * 1024 * 1024
)

func init() {
	utils.InitVar("TRAFFIC_DISABLE_EGRESS", &disableEgress)
	utils.InitVar("TRAFFIC_MAX_ACTIVE_CONN", &maxActiveConnections)
	utils.InitVar("TRAFFIC_INACTIVITY_THRESHOLD", &inactivityThreshold)
	utils.InitVar("TRAFFIC_BUFFER_THRESHOLD", &bufferMemThreshold)
	utils.InitVar("AKTO_MEM_SOFT_LIMIT", &bufferMemThreshold)
	utils.InitVar("TRACKER_DATA_PROCESS_INTERVAL", &trackerDataProcessInterval)
	utils.InitVar("SOCKET_DATA_EVENT_BYTES_THRESHOLD", &socketDataEventBytesThreshold)
}

func isKnownWebSocketConnection(connID structs.ConnID) bool {
	if kafkaUtil.WSConnectionManager == nil {
		return false
	}
	slog.Info("Skipping tracker processing, missing send or recv buffer",
		"connID.id", connID.Id,
		"connID.fd", connID.Fd)
	return kafkaUtil.WSConnectionManager.IsRegisteredByConnID(connID.Id, connID.Fd)
}

func hasCloseFrame(frames []kafkaUtil.WebSocketMessage) bool {
	for _, f := range frames {
		if f.Opcode == 0x8 {
			return true
		}
	}
	return false
}

func extractHTTPHeadersOnly(buffer []byte) []byte {
	if len(buffer) < 4 {
		return buffer
	}

	// Look for \r\n\r\n which marks the end of HTTP headers
	headerEnd := bytes.Index(buffer, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		// No header terminator found, return as-is
		return buffer
	}

	// Return headers including the \r\n\r\n terminator
	return buffer[:headerEnd+4]
}

func isTLSBuffer(buf []byte) bool {
	if len(buf) < 3 {
		return false
	}
	// TLS record types: 0x14 ChangeCipherSpec, 0x15 Alert, 0x16 Handshake, 0x17 ApplicationData
	switch buf[0] {
	case 0x14, 0x15, 0x16, 0x17:
		return buf[1] == 0x03 && (buf[2] == 0x01 || buf[2] == 0x03 || buf[2] == 0x04)
	default:
		return false
	}
}

func bufferPreview(buf []byte, maxLen int) string {
	if len(buf) == 0 {
		return "<empty>"
	}
	if isTLSBuffer(buf) {
		return fmt.Sprintf("TLS-record(type=0x%02x,len=%d)", buf[0], len(buf))
	}
	n := len(buf)
	if n > maxLen {
		n = maxLen
	}
	prefix := buf[:n]
	if bytes.HasPrefix(buf, httpBytes) ||
		bytes.HasPrefix(buf, []byte("GET ")) ||
		bytes.HasPrefix(buf, []byte("POST ")) ||
		bytes.HasPrefix(buf, []byte("PUT ")) ||
		bytes.HasPrefix(buf, []byte("DELETE ")) ||
		bytes.HasPrefix(buf, []byte("PATCH ")) ||
		bytes.HasPrefix(buf, []byte("HEAD ")) ||
		bytes.HasPrefix(buf, []byte("OPTIONS ")) {
		return string(prefix)
	}
	return fmt.Sprintf("binary(len=%d,hex=%x)", len(buf), prefix)
}

func ProcessTrackerData(connID structs.ConnID, tracker *Tracker, isComplete bool) {
	tracker.mutex.Lock()
	defer tracker.mutex.Unlock()

	if len(tracker.sentBuf) == 0 || len(tracker.recvBuf) == 0 {
		slog.Info("Skipping tracker processing, missing send or recv buffer",
			"fd", connID.Fd,
			"id", connID.Id,
			"ssl", tracker.ssl,
			"sentChunks", len(tracker.sentBuf),
			"recvChunks", len(tracker.recvBuf),
			"isComplete", isComplete,
		)
		return
	}

	// Check if this is already a known WebSocket connection - if so, skip sequence checks
	// since binary WebSocket frames won't have sequential packet numbering
	isKnownWebSocket := isKnownWebSocketConnection(connID)
	receiveBuffer := convertToSingleByteArr(tracker.recvBuf, isKnownWebSocket)
	sentBuffer := convertToSingleByteArr(tracker.sentBuf, isKnownWebSocket)

	slog.Info("Processing tracker data",
		"connID", connID,
		"isComplete", isComplete,
		"isKnownWebSocket", isKnownWebSocket,
		"ssl", tracker.ssl,
		"sentLen", len(sentBuffer),
		"recvLen", len(receiveBuffer),
		"sentPreview", bufferPreview(sentBuffer, 80),
		"recvPreview", bufferPreview(receiveBuffer, 80),
		"sentIsTLS", isTLSBuffer(sentBuffer),
		"recvIsTLS", isTLSBuffer(receiveBuffer),
	)

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

	if isKnownWebSocket {
		processWebSocketConnection(connID, receiveBuffer, sentBuffer, isComplete, hostName)
		return
	}

	isWebSocket, wsChecks := isWebSocketUpgradeData(sentBuffer, receiveBuffer)
	slog.Info("WebSocket upgrade check",
		"fd", connID.Fd,
		"id", connID.Id,
		"matched", isWebSocket,
		"has101", wsChecks.has101,
		"hasUpgradeResponseHeader", wsChecks.hasUpgradeResponseHeader,
		"hasUpgradeRequestHeader", wsChecks.hasUpgradeRequestHeader,
		"hasConnectionResponseHeader", wsChecks.hasConnectionResponseHeader,
		"hasConnectionRequestHeader", wsChecks.hasConnectionRequestHeader,
		"sentIsTLS", isTLSBuffer(sentBuffer),
		"recvIsTLS", isTLSBuffer(receiveBuffer),
	)

	if isWebSocket {
		slog.Info("Detected WebSocket upgrade, registering connection",
			"fd", connID.Fd,
			"id", connID.Id,
			"ssl", tracker.ssl,
		)

		// Extract headers from the request buffer (receiveBuffer contains the WebSocket upgrade request)
		headers := extractHeadersFromHTTPBuffer(receiveBuffer)

		// Register the connection with the WebSocket manager using ConnID as stable key
		kafkaUtil.WSConnectionManager.RegisterConnectionNumeric(connID.Id, connID.Fd, connID.Ip, connID.Port, tracker.srcIp, tracker.srcPort, headers)

		httpReceiveBuffer := extractHTTPHeadersOnly(receiveBuffer)
		httpSentBuffer := extractHTTPHeadersOnly(sentBuffer)
		tryReadFromBD(destIpStr, srcIpStr, httpReceiveBuffer, httpSentBuffer, isComplete, 1, connID.Id, connID.Fd, uniqueDaemonsetId, hostName) // call as http for first time
	} else if len(sentBuffer) >= len(httpBytes) && (bytes.Equal(sentBuffer[:len(httpBytes)], httpBytes)) {
		slog.Info("Matched inbound HTTP response, sending to parser",
			"fd", connID.Fd,
			"id", connID.Id,
			"ssl", tracker.ssl,
			"destIp", destIpStr,
			"srcIp", srcIpStr,
		)
		tryReadFromBD(destIpStr, srcIpStr, receiveBuffer, sentBuffer, isComplete, 1, connID.Id, connID.Fd, uniqueDaemonsetId, hostName)
	} else {
		slog.Info("No inbound HTTP/WebSocket match",
			"fd", connID.Fd,
			"id", connID.Id,
			"ssl", tracker.ssl,
			"sentStartsHTTP", len(sentBuffer) >= len(httpBytes) && bytes.Equal(sentBuffer[:len(httpBytes)], httpBytes),
			"sentIsTLS", isTLSBuffer(sentBuffer),
			"recvIsTLS", isTLSBuffer(receiveBuffer),
		)
	}
	if !disableEgress && !isWebSocket {
		// attempt to parse the egress as well by switching the recv and sent buffers.
		if len(receiveBuffer) >= len(httpBytes) && (bytes.Equal(receiveBuffer[:len(httpBytes)], httpBytes)) {
			slog.Info("Matched outbound HTTP request, sending to parser",
				"fd", connID.Fd,
				"id", connID.Id,
				"ssl", tracker.ssl,
				"destIp", destIpStr,
				"srcIp", srcIpStr,
			)
			tryReadFromBD(srcIpStr, destIpStr, sentBuffer, receiveBuffer, isComplete, 2, connID.Id, connID.Fd, uniqueDaemonsetId, hostName)
		}
	}
}

type webSocketUpgradeChecks struct {
	has101                      bool
	hasUpgradeResponseHeader    bool
	hasUpgradeRequestHeader     bool
	hasConnectionResponseHeader bool
	hasConnectionRequestHeader  bool
}

func isWebSocketUpgradeData(sentBuffer, receiveBuffer []byte) (bool, webSocketUpgradeChecks) {
	checks := webSocketUpgradeChecks{}
	slog.Info("Checking for WebSocket upgrade",
		"sentPreview", bufferPreview(sentBuffer, 80),
		"recvPreview", bufferPreview(receiveBuffer, 80),
		"sentIsTLS", isTLSBuffer(sentBuffer),
		"recvIsTLS", isTLSBuffer(receiveBuffer),
	)
	if len(sentBuffer) == 0 || len(receiveBuffer) == 0 {
		return false, checks
	}

	if bytes.Contains(sentBuffer, []byte(":9092")) || bytes.Contains(receiveBuffer, []byte(":9092")) {
		return false, checks
	}

	// Check for 101 Switching Protocols in sent buffer (response)
	checks.has101 = bytes.Contains(sentBuffer, []byte("101 Switching Protocols"))

	// Check for Upgrade: websocket header (case-insensitive in both buffers)
	// sentBuffer (response) should have it
	checks.hasUpgradeResponseHeader = bytes.Contains(sentBuffer, []byte("Upgrade: websocket")) ||
		bytes.Contains(sentBuffer, []byte("upgrade: websocket"))

	// receiveBuffer (request) should have it
	checks.hasUpgradeRequestHeader = bytes.Contains(receiveBuffer, []byte("Upgrade: websocket")) ||
		bytes.Contains(receiveBuffer, []byte("upgrade: websocket"))

	// Check for Connection: Upgrade/upgrade header (case-insensitive in both buffers)
	// sentBuffer (response) should have it
	checks.hasConnectionResponseHeader = bytes.Contains(sentBuffer, []byte("Connection: Upgrade")) ||
		bytes.Contains(sentBuffer, []byte("Connection: upgrade")) ||
		bytes.Contains(sentBuffer, []byte("connection: Upgrade")) ||
		bytes.Contains(sentBuffer, []byte("connection: upgrade"))

	// receiveBuffer (request) should have it
	checks.hasConnectionRequestHeader = bytes.Contains(receiveBuffer, []byte("Connection: Upgrade")) ||
		bytes.Contains(receiveBuffer, []byte("Connection: upgrade")) ||
		bytes.Contains(receiveBuffer, []byte("connection: Upgrade")) ||
		bytes.Contains(receiveBuffer, []byte("connection: upgrade"))

	// All conditions must be met: 101 status + upgrade headers in both request and response
	matched := checks.has101 && checks.hasUpgradeResponseHeader && checks.hasUpgradeRequestHeader &&
		checks.hasConnectionResponseHeader && checks.hasConnectionRequestHeader
	return matched, checks
}

// extractHeadersFromHTTPBuffer extracts HTTP headers from raw buffer (request or response line format)
func extractHeadersFromHTTPBuffer(buffer []byte) map[string]string {
	headers := make(map[string]string)
	if len(buffer) == 0 {
		return headers
	}

	// Split into lines
	lines := bytes.Split(buffer, []byte("\r\n"))

	// Skip first line (request line or status line)
	for i := 1; i < len(lines); i++ {
		line := lines[i]

		// Empty line marks end of headers
		if len(line) == 0 {
			break
		}

		// Split header into key and value
		parts := bytes.SplitN(line, []byte(":"), 2)
		if len(parts) == 2 {
			key := string(bytes.TrimSpace(parts[0]))
			value := string(bytes.TrimSpace(parts[1]))
			headers[key] = value
		}
	}

	return headers
}

func processWebSocketConnection(connID structs.ConnID, receiveBuffer, sentBuffer []byte, isComplete bool, hostName string) {
	connectionClosed := false
	if len(sentBuffer) > 0 {
		frames := kafkaUtil.ParseWebSocketFrames(sentBuffer, "outgoing")
		if len(frames) > 0 {
			if hasCloseFrame(frames) {
				connectionClosed = true
			}
			err := kafkaUtil.WSConnectionManager.AccumulateMessagesNumeric(
				connID.Id,
				connID.Fd,
				frames,
			)
			if err != nil {
				slog.Debug("Failed to accumulate WebSocket frames from sent buffer", "error", err)
			}
		}
	}

	if len(receiveBuffer) > 0 {
		frames := kafkaUtil.ParseWebSocketFrames(receiveBuffer, "incoming")
		if len(frames) > 0 {
			if hasCloseFrame(frames) {
				connectionClosed = true
			}
			err := kafkaUtil.WSConnectionManager.AccumulateMessagesNumeric(
				connID.Id,
				connID.Fd,
				frames,
			)
			if err != nil {
				slog.Debug("Failed to accumulate WebSocket frames from receive buffer", "error", err)
			}
		}
	}

	if connectionClosed {
		kafkaUtil.WSConnectionManager.RemoveConnectionByConnID(connID.Id, connID.Fd)
	}

	slog.Debug("WebSocket connection processed", "connID", connID, "isComplete", isComplete)
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
					tracker.AddDataEvent(*e)
					if tracker.GetSentBytes()+tracker.GetRecvBytes() > uint64(socketDataEventBytesThreshold) {
						utils.LogProcessing("Socket Data threshold data breached, processing current data", "fd", connID.Fd, "id", connID.Id, "timestamp", connID.Conn_start_ns, "ip", connID.Ip, "port", connID.Port)
						factory.StopProcessing(connID)
						return
					} else {
						resetTimer(inactivityTimer, inactivityThreshold)
					}
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
		utils.LogProcessing("Deleted event channel", "fd", connectionID.Fd, "id", connectionID.Id, "timestamp", connectionID.Conn_start_ns, "ip", connectionID.Ip, "port", connectionID.Port)
	}

	if _, exists := factory.connections[connectionID]; exists {

		delete(factory.connections, connectionID)
		utils.LogProcessing("Deleted connection", "fd", connectionID.Fd, "id", connectionID.Id, "timestamp", connectionID.Conn_start_ns, "ip", connectionID.Ip, "port", connectionID.Port)
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
				if kafkaUtil.WSConnectionManager != nil {
					kafkaUtil.WSConnectionManager.RemoveConnectionByConnID(key.Id, key.Fd)
				}
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
