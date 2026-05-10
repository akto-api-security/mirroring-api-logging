package connections

import (
	"sync"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/structs"
)

var socketDataEventPool = sync.Pool{
	New: func() any { return new(structs.SocketDataEvent) },
}

func AcquireSocketDataEvent() *structs.SocketDataEvent {
	return socketDataEventPool.Get().(*structs.SocketDataEvent)
}

func ReleaseSocketDataEvent(ev *structs.SocketDataEvent) {
	if ev != nil {
		socketDataEventPool.Put(ev)
	}
}
