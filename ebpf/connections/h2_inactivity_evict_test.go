package connections

import (
	"testing"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/structs"
	kafka "github.com/akto-api-security/mirroring-api-logging/trafficUtil/kafkaUtil"
	metaUtils "github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

// The inactivity timer must not evict HTTP/2 connections. Their parser state
// (HPACK's dynamic table) is cumulative from the connection's first byte, so
// dropping the tracker while the socket is still open leaves the next request
// to rebuild the parser mid-stream, where it can never resynchronise — every
// later stream on that connection is then lost silently. HTTP/1.1 is stateless
// per message and keeps the old eviction behaviour.
func TestInactivityEvictionSkipsHTTP2(t *testing.T) {
	origThreshold := inactivityThreshold
	origFast := metaUtils.FastIngestion
	origKafka := kafka.KafkaDisabled
	inactivityThreshold = 200 * time.Millisecond
	metaUtils.FastIngestion = true
	kafka.KafkaDisabled = true
	t.Cleanup(func() {
		inactivityThreshold = origThreshold
		metaUtils.FastIngestion = origFast
		kafka.KafkaDisabled = origKafka
	})

	cases := []struct {
		name      string
		protocol  uint32
		wantAlive bool
	}{
		{"http1 is evicted on inactivity", structs.ProtoHTTP1, false},
		{"http2 survives inactivity", structs.ProtoHTTP2, true},
	}

	for i, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			factory := NewFactory()
			connID := structs.ConnID{Fd: uint32(100 + i), Id: uint64(100 + i), Conn_start_ns: uint64(time.Now().UnixNano())}

			factory.CreateIfNotExists(connID)
			tracker, ok := factory.getTracker(connID)
			if !ok {
				t.Fatalf("tracker was not created")
			}
			tracker.protocol = tc.protocol

			// Well past the threshold, with no events in between.
			time.Sleep(5 * inactivityThreshold)

			_, alive := factory.getTracker(connID)
			if alive != tc.wantAlive {
				t.Fatalf("after %v idle: tracker alive = %v, want %v", 5*inactivityThreshold, alive, tc.wantAlive)
			}
		})
	}
}

// An HTTP/2 connection exempt from inactivity eviction must still be torn down
// when the socket closes, otherwise the exemption leaks trackers.
func TestHTTP2StillTerminatedOnSocketClose(t *testing.T) {
	origThreshold := inactivityThreshold
	origFast := metaUtils.FastIngestion
	origKafka := kafka.KafkaDisabled
	inactivityThreshold = 200 * time.Millisecond
	metaUtils.FastIngestion = true
	kafka.KafkaDisabled = true
	t.Cleanup(func() {
		inactivityThreshold = origThreshold
		metaUtils.FastIngestion = origFast
		kafka.KafkaDisabled = origKafka
	})

	factory := NewFactory()
	connID := structs.ConnID{Fd: 200, Id: 200, Conn_start_ns: uint64(time.Now().UnixNano())}
	factory.CreateIfNotExists(connID)
	tracker, ok := factory.getTracker(connID)
	if !ok {
		t.Fatalf("tracker was not created")
	}
	tracker.protocol = structs.ProtoHTTP2

	time.Sleep(3 * inactivityThreshold)
	if _, alive := factory.getTracker(connID); !alive {
		t.Fatalf("http2 tracker was evicted on inactivity")
	}

	factory.mutex.RLock()
	ch := factory.processor[connID]
	factory.mutex.RUnlock()
	ch <- &structs.SocketCloseEvent{}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, alive := factory.getTracker(connID); !alive {
			return // torn down as expected
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("http2 tracker was not torn down after socket close")
}
