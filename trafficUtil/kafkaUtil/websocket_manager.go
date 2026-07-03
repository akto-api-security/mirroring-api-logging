package kafkaUtil

import (
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// WebSocketConnection stores metadata about an active WebSocket connection.
type WebSocketConnection struct {
	SourceIP      string
	SourcePort    string
	DestIP        string
	DestPort      string
	Headers       map[string]string
	EstablishedAt time.Time
	LastMessageAt time.Time
	Messages      []WebSocketMessage
}

// WebSocketMessage represents a single WebSocket frame or message.
type WebSocketMessage struct {
	EventType string // Custom event type (populated during post-processing, not from eBPF)
	Payload   string // Message payload
	Direction string // "incoming" or "outgoing"
	Timestamp time.Time
	FIN       bool  // Final frame flag
	Opcode    uint8 // WebSocket opcode (1=text, 2=binary, etc.)
	Masked    bool  // Whether payload was masked
}

// WebSocketBatch represents accumulated messages ready to send to Kafka.
type WebSocketBatch struct {
	ConnectionKey string
	Connection    WebSocketConnection
	Messages      []WebSocketMessage
	BatchTime     time.Time
}

// WebSocketConnectionManager manages active WebSocket connections and message accumulation.
type WebSocketConnectionManager struct {
	connections map[string]*WebSocketConnection
	mutex       sync.RWMutex
	cleanupTTL  time.Duration
}

// NewWebSocketConnectionManager creates a new WebSocket connection manager.
func NewWebSocketConnectionManager() *WebSocketConnectionManager {
	return &WebSocketConnectionManager{
		connections: make(map[string]*WebSocketConnection),
		cleanupTTL:  5 * time.Minute,
	}
}

// buildConnectionKey creates a unique key for a connection.
func buildConnectionKey(sourceIP, sourcePort, destIP, destPort string) string {
	return fmt.Sprintf("%s:%s:%s:%s", sourceIP, sourcePort, destIP, destPort)
}

func buildConnIDKey(connIDId uint64, connIDFd uint32) string {
	return fmt.Sprintf("%d:%d", connIDId, connIDFd)
}

// IsRegisteredByConnID reports whether an eBPF ConnID is tracked as WebSocket.
func (wcm *WebSocketConnectionManager) IsRegisteredByConnID(connIDId uint64, connIDFd uint32) bool {
	wcm.mutex.RLock()
	defer wcm.mutex.RUnlock()
	_, exists := wcm.connections[buildConnIDKey(connIDId, connIDFd)]
	slog.Info("Skipping tracker processing, missing send or recv buffer",
		"connID.id", connIDId,
		"connID.fd", connIDId,
		"exists", exists)
	return exists
}

// RegisterConnection registers a new WebSocket connection with initial HTTP handshake headers.
func (wcm *WebSocketConnectionManager) RegisterConnection(sourceIP, sourcePort, destIP, destPort string, req *http.Request) error {
	wcm.mutex.Lock()
	defer wcm.mutex.Unlock()

	key := buildConnectionKey(sourceIP, sourcePort, destIP, destPort)

	if _, exists := wcm.connections[key]; exists {
		slog.Warn("WebSocket connection already registered", "key", key)
		return nil
	}

	headers := make(map[string]string)
	for name, values := range req.Header {
		if len(values) > 0 {
			headers[name] = values[0]
		}
	}

	wcm.connections[key] = &WebSocketConnection{
		SourceIP:      sourceIP,
		SourcePort:    sourcePort,
		DestIP:        destIP,
		DestPort:      destPort,
		Headers:       headers,
		EstablishedAt: time.Now(),
		LastMessageAt: time.Now(),
		Messages:      []WebSocketMessage{},
	}

	slog.Debug("WebSocket connection registered", "key", key)
	return nil
}

func (wcm *WebSocketConnectionManager) RegisterConnectionNumeric(connIDId uint64, connIDFd uint32, destIPNumeric uint32, destPort uint16, srcIPNumeric uint32, srcPort uint16, headers map[string]string) error {
	wcm.mutex.Lock()
	defer wcm.mutex.Unlock()

	key := buildConnIDKey(connIDId, connIDFd)

	if _, exists := wcm.connections[key]; exists {
		slog.Debug("WebSocket connection already registered", "key", key)
		return nil
	}

	if headers == nil {
		headers = make(map[string]string)
	}

	wcm.connections[key] = &WebSocketConnection{
		SourceIP:      fmt.Sprintf("%d", srcIPNumeric),
		SourcePort:    fmt.Sprintf("%d", srcPort),
		DestIP:        fmt.Sprintf("%d", destIPNumeric),
		DestPort:      fmt.Sprintf("%d", destPort),
		Headers:       headers,
		EstablishedAt: time.Now(),
		LastMessageAt: time.Now(),
		Messages:      []WebSocketMessage{},
	}

	slog.Info("WebSocket connection registered (numeric)", "key", key)
	return nil
}

// AccumulateMessages adds WebSocket messages to the connection's batch.
func (wcm *WebSocketConnectionManager) AccumulateMessages(sourceIP, sourcePort, destIP, destPort string, messages []WebSocketMessage) error {
	wcm.mutex.Lock()
	defer wcm.mutex.Unlock()

	key := buildConnectionKey(sourceIP, sourcePort, destIP, destPort)

	conn, exists := wcm.connections[key]
	if !exists {
		slog.Warn("WebSocket connection not found for accumulation", "key", key)
		return fmt.Errorf("connection not found: %s", key)
	}

	conn.Messages = append(conn.Messages, messages...)
	conn.LastMessageAt = time.Now()

	return nil
}

func (wcm *WebSocketConnectionManager) AccumulateMessagesNumeric(connIDId uint64, connIDFd uint32, messages []WebSocketMessage) error {
	wcm.mutex.Lock()
	defer wcm.mutex.Unlock()

	key := buildConnIDKey(connIDId, connIDFd)

	conn, exists := wcm.connections[key]
	if !exists {
		slog.Warn("WebSocket connection not found for accumulation", "key", key)
		return fmt.Errorf("connection not found: %s", key)
	}

	conn.Messages = append(conn.Messages, messages...)
	conn.LastMessageAt = time.Now()

	return nil
}

// GetAndClearBatch retrieves accumulated messages and resets the batch.
func (wcm *WebSocketConnectionManager) GetAndClearBatch(sourceIP, sourcePort, destIP, destPort string) (*WebSocketBatch, error) {
	wcm.mutex.Lock()
	defer wcm.mutex.Unlock()

	key := buildConnectionKey(sourceIP, sourcePort, destIP, destPort)

	conn, exists := wcm.connections[key]
	if !exists {
		return nil, fmt.Errorf("connection not found: %s", key)
	}

	batch := &WebSocketBatch{
		ConnectionKey: key,
		Connection:    *conn,
		Messages:      conn.Messages,
		BatchTime:     time.Now(),
	}

	conn.Messages = []WebSocketMessage{}

	return batch, nil
}

func (wcm *WebSocketConnectionManager) GetAndClearBatchByConnID(connIDId uint64, connIDFd uint32) (*WebSocketBatch, error) {
	wcm.mutex.Lock()
	defer wcm.mutex.Unlock()

	key := buildConnIDKey(connIDId, connIDFd)

	conn, exists := wcm.connections[key]
	if !exists {
		return nil, fmt.Errorf("connection not found: %s", key)
	}

	batch := &WebSocketBatch{
		ConnectionKey: key,
		Connection:    *conn,
		Messages:      conn.Messages,
		BatchTime:     time.Now(),
	}

	conn.Messages = []WebSocketMessage{}

	return batch, nil
}

// GetAllConnections returns all active WebSocket connections.
func (wcm *WebSocketConnectionManager) GetAllConnections() []string {
	wcm.mutex.RLock()
	defer wcm.mutex.RUnlock()

	keys := make([]string, 0, len(wcm.connections))
	for k := range wcm.connections {
		keys = append(keys, k)
	}
	return keys
}

// RemoveConnection removes a connection from tracking.
func (wcm *WebSocketConnectionManager) RemoveConnection(sourceIP, sourcePort, destIP, destPort string) {
	wcm.mutex.Lock()
	defer wcm.mutex.Unlock()

	key := buildConnectionKey(sourceIP, sourcePort, destIP, destPort)
	delete(wcm.connections, key)
	slog.Debug("WebSocket connection removed", "key", key)
}

func (wcm *WebSocketConnectionManager) RemoveConnectionByConnID(connIDId uint64, connIDFd uint32) {
	wcm.mutex.Lock()
	defer wcm.mutex.Unlock()

	key := buildConnIDKey(connIDId, connIDFd)
	if _, exists := wcm.connections[key]; !exists {
		return
	}
	delete(wcm.connections, key)
	slog.Info("WebSocket connection removed (closed)", "key", key)
}

// CleanupStaleConnections removes connections that haven't been active within the TTL.
func (wcm *WebSocketConnectionManager) CleanupStaleConnections() {
	wcm.mutex.Lock()
	defer wcm.mutex.Unlock()

	cutoff := time.Now().Add(-wcm.cleanupTTL)
	for key, conn := range wcm.connections {
		if conn.LastMessageAt.Before(cutoff) {
			delete(wcm.connections, key)
			slog.Debug("WebSocket connection cleaned up (stale)", "key", key)
		}
	}
}

// Global WebSocket connection manager instance
var WSConnectionManager *WebSocketConnectionManager

func init() {
	WSConnectionManager = NewWebSocketConnectionManager()

	// Start cleanup routine - runs every 5 minutes
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			WSConnectionManager.CleanupStaleConnections()
		}
	}()
}
