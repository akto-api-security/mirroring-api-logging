package bpfwrapper

import (
	"errors"
	"fmt"
	"log"
	"log/slog"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/connections"
	metaUtils "github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

var (
	logRingbufStats      bool
	ringbufStatsInterval = 10 * time.Second
)

func init() {
	metaUtils.InitVar("TRAFFIC_LOG_RINGBUF_STATS", &logRingbufStats)
	metaUtils.InitVar("TRAFFIC_RINGBUF_STATS_INTERVAL", &ringbufStatsInterval)
}

// ProbeEventHandler processes a single ring buffer record inline in the reader goroutine.
// data is backed by the reader's internal buffer and is only valid until the handler returns;
// the handler must copy out any bytes it needs to keep.
type ProbeEventHandler func(data []byte, connectionFactory *connections.Factory)

// ProbeChannel links a named BPF ring buffer to an event handler.
type ProbeChannel struct {
	name    string
	handler ProbeEventHandler
	reader  *ringbuf.Reader
}

// NewProbeChannel creates a new probe channel for the given BPF ring buffer name.
func NewProbeChannel(name string, handler ProbeEventHandler) *ProbeChannel {
	return &ProbeChannel{
		name:    name,
		handler: handler,
	}
}

// Start opens the ring buffer reader and processes events inline with no intermediate Go channel.
// The kernel ring buffer (mmap'd) acts as the sole buffer. Backpressure propagates directly:
// if the handler is slow, ReadInto blocks, the kernel ring fills, and BPF drops at the source.
func (pc *ProbeChannel) Start(coll *ebpf.Collection, connectionFactory *connections.Factory) error {
	m, ok := coll.Maps[pc.name]
	if !ok {
		return fmt.Errorf("BPF map %q not found in collection", pc.name)
	}

	var err error
	pc.reader, err = ringbuf.NewReader(m)
	if err != nil {
		return fmt.Errorf("failed to open ring buffer reader for %q: %v", pc.name, err)
	}

	go func() {
		log.Printf("ring buffer reader started for %s", pc.name)
		var rec ringbuf.Record
		var eventsInWindow uint64
		var lastStatsLog time.Time
		minRemaining := -1
		for {
			if err := pc.reader.ReadInto(&rec); err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Printf("error reading ring buffer event on %s: %v", pc.name, err)
				continue
			}
			if logRingbufStats {
				eventsInWindow++
				if minRemaining < 0 || rec.Remaining < minRemaining {
					minRemaining = rec.Remaining
				}
				now := time.Now()
				if lastStatsLog.IsZero() {
					lastStatsLog = now
				} else if now.Sub(lastStatsLog) >= ringbufStatsInterval {
					bufferSize := pc.reader.BufferSize()
					availableBytes := pc.reader.AvailableBytes()
					slog.Warn("ring buffer stats",
						"map", pc.name,
						"eventsInWindow", eventsInWindow,
						"window", now.Sub(lastStatsLog).String(),
						"bufferSizeBytes", bufferSize,
						"availableBytes", availableBytes,
						"availablePct", pct(availableBytes, bufferSize),
						"lastRecordRemainingBytes", rec.Remaining,
						"minRecordRemainingBytes", minRemaining,
					)
					eventsInWindow = 0
					minRemaining = -1
					lastStatsLog = now
				}
			}
			pc.handler(rec.RawSample, connectionFactory)
		}
	}()

	return nil
}

func pct(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return float64(n) * 100 / float64(d)
}

// Stop closes the underlying ring buffer reader, which will unblock the reader goroutine.
func (pc *ProbeChannel) Stop() {
	if pc.reader != nil {
		pc.reader.Close()
	}
}

// LaunchPerfBufferConsumers starts all probe channels.
func LaunchPerfBufferConsumers(coll *ebpf.Collection, connectionFactory *connections.Factory, probeList []*ProbeChannel) error {
	for _, pc := range probeList {
		if err := pc.Start(coll, connectionFactory); err != nil {
			return err
		}
	}
	return nil
}
