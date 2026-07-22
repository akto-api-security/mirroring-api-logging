package structs

import "sync"

var socketDataEventPool = sync.Pool{New: func() any { return new(SocketDataEvent) }}

// GetSocketDataEvent returns a SocketDataEvent from the pool.
// Caller must call ReleaseSocketDataEvent when done.
func GetSocketDataEvent() *SocketDataEvent {
	return socketDataEventPool.Get().(*SocketDataEvent)
}

// ReleaseSocketDataEvent returns a SocketDataEvent to the pool.
// Must be called after all fields of the event have been read.
func ReleaseSocketDataEvent(e *SocketDataEvent) {
	socketDataEventPool.Put(e)
}
