package connections

// Global, process-wide bandwidth sampling gate: caps how many MB/minute of
// buffer this process will sample, independent of any Factory/Tracker/
// connection state. Previously called from SocketDataEventCallback
// (eventCallbacks.go), specifically in the data-event path, as a pre-check
// before processing/forwarding a payload — currently unwired, kept for reuse.
//
// BufferCheck()      — call before sampling a buffer; returns false if this
//                       minute's budget (TRAFFIC_SAMPLE_BUFFER_PER_MINUTE MB)
//                       is already spent.
// UpdateBufferSize() — call after sampling, with the bytes actually sampled,
//                       to charge them against the budget.

import (
	"log/slog"
	"sync"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

var (
	sampleBufferPerMin        = -1
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
