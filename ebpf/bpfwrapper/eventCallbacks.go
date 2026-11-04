package bpfwrapper

import (
	"encoding/binary"
	"log/slog"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/connections"
	"github.com/akto-api-security/mirroring-api-logging/ebpf/structs"
	metaUtils "github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

func init() {
	if metaUtils.TrafficLogBpfSocketDataSubmits {
		startSocketDataInboundMetricsFlushLoop()
	}
}

const socketDataInboundLogInterval = 10 * time.Second

var socketDataInboundEvents atomic.Uint64

func startSocketDataInboundMetricsFlushLoop() {
	go func() {
		ticker := time.NewTicker(socketDataInboundLogInterval)
		defer ticker.Stop()
		for range ticker.C {
			n := socketDataInboundEvents.Swap(0)
			if n == 0 {
				continue
			}
			slog.Warn("socket_data events reaching eventCallback",
				"countInWindow", n,
				"window", socketDataInboundLogInterval.String())
		}
	}()
}

// handleShardRecord applies the userspace ingest filters, then hands the
// record to its shard. Dropping a data record here is safe: the next record's
// counters show the gap and the affected messages are not emitted.
func handleShardRecord(shard *connections.Shard, data []byte, now time.Time) {
	if len(data) < 16 {
		return
	}
	switch binary.LittleEndian.Uint32(data[12:16]) {
	case structs.EventOpen:
		if !connections.CanBeFilled() {
			metaUtils.LogIngest("Connections filled")
			return
		}
	case structs.EventData:
		if len(data) < structs.MsgPayloadOffset {
			slog.Error("socket data event too short", "len", len(data))
			return
		}
		id := (*structs.ConnID)(unsafe.Pointer(&data[0]))
		if metaUtils.SystemCPUIngestPaused() || !connections.BufferCheck() {
			shard.DropData(data)
			return
		}
		n := len(data) - structs.MsgPayloadOffset
		if metaUtils.TrafficLogBpfSocketDataSubmits {
			socketDataInboundEvents.Add(1)
		}
		if metaUtils.IngestLogsEnabled() {
			attr := (*[structs.MsgPayloadOffset]byte)(data[:structs.MsgPayloadOffset])
			metaUtils.LogIngest("Got data",
				"fd", id.Fd,
				"id", id.Id,
				"ip", id.Ip,
				"port", id.Port,
				"data", string(data[structs.MsgPayloadOffset:structs.MsgPayloadOffset+min(32, n)]),
				"rc", binary.LittleEndian.Uint32(attr[36:40]),
				"wc", binary.LittleEndian.Uint32(attr[40:44]),
				"ssl", attr[44] != 0,
				"bytesSent", int32(binary.LittleEndian.Uint32(attr[32:36])),
				"lost", binary.LittleEndian.Uint32(attr[48:52]))
		}
		connections.UpdateBufferSize(uint64(n))
	}
	shard.HandleRecord(data, now)
}
