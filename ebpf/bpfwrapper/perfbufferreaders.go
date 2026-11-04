package bpfwrapper

import (
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
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

// ShardReader drains one socket_data_events_N ring into the Shard that owns
// the connections hashed to it. The kernel puts every record of a connection
// on the same ring, so this goroutine sees them in order and is the only one
// touching that shard.
type ShardReader struct {
	name   string
	shard  *connections.Shard
	reader *ringbuf.Reader
}

func NewShardReader(name string, shard *connections.Shard) *ShardReader {
	return &ShardReader{name: name, shard: shard}
}

func (sr *ShardReader) Start(coll *ebpf.Collection) error {
	m, ok := coll.Maps[sr.name]
	if !ok {
		return fmt.Errorf("BPF map %q not found in collection", sr.name)
	}
	var err error
	sr.reader, err = ringbuf.NewReader(m)
	if err != nil {
		return fmt.Errorf("failed to open ring buffer reader for %q: %v", sr.name, err)
	}

	go func() {
		log.Printf("ring buffer reader started for %s", sr.name)
		var rec ringbuf.Record
		var eventsInWindow uint64
		lastStatsLog := time.Now()
		minRemaining := -1
		sweep := connections.SweepInterval()
		sr.reader.SetDeadline(time.Now().Add(sweep))
		for {
			err := sr.reader.ReadInto(&rec)
			now := time.Now()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				if errors.Is(err, os.ErrDeadlineExceeded) {
					sr.shard.Sweep(now)
					sr.reader.SetDeadline(now.Add(sweep))
					continue
				}
				log.Printf("error reading ring buffer event on %s: %v", sr.name, err)
				continue
			}
			handleShardRecord(sr.shard, rec.RawSample, now)

			if logRingbufStats {
				eventsInWindow++
				if minRemaining < 0 || rec.Remaining < minRemaining {
					minRemaining = rec.Remaining
				}
				if now.Sub(lastStatsLog) >= ringbufStatsInterval {
					bufferSize := sr.reader.BufferSize()
					availableBytes := sr.reader.AvailableBytes()
					slog.Warn("ring buffer stats",
						"map", sr.name,
						"eventsInWindow", eventsInWindow,
						"window", now.Sub(lastStatsLog).String(),
						"bufferSizeBytes", bufferSize,
						"availableBytes", availableBytes,
						"availablePct", pct(availableBytes, bufferSize),
						"minRecordRemainingBytes", minRemaining,
					)
					eventsInWindow = 0
					minRemaining = -1
					lastStatsLog = now
				}
			}
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

func (sr *ShardReader) Stop() {
	if sr.reader != nil {
		sr.reader.Close()
	}
}
