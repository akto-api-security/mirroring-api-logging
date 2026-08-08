package bpfwrapper

import (
	"fmt"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/kafkaUtil"
	"log"

	"github.com/iovisor/gobpf/bcc"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/connections"
)

// ProbeEventLoop is the signature for the callback functions to extract the events from the input channel.
type ProbeEventLoop func(inputChan chan []byte, connectionFactory *connections.Factory)

// ProbeChannel represents a single handler to a channel of events in the BPF.
type ProbeChannel struct {
	// Name of the BPF channel.
	name string
	// Event loop handler, a method which receive a channel for the input events from the implementation, and parse them.
	eventLoop ProbeEventLoop
	// A go channel which holds the messages from the BPF module.
	eventChannel chan []byte
	// A go channel for lost events.
	lostEventsChannel chan uint64
	// The bpf perf map that links our user mode channel to the BPF module.
	perfMap *bcc.PerfMap
	// Number of parallel goroutines processing events from eventChannel
	numWorkers int
}

// NewProbeChannel creates a new probe channel with the given handle for the given bpf channel name.
// numWorkers is optional (variadic) to maintain backward compatibility; default is 1.
func NewProbeChannel(name string, handler ProbeEventLoop, numWorkers ...int) *ProbeChannel {
	workers := 1
	if len(numWorkers) > 0 && numWorkers[0] > 1 {
		workers = numWorkers[0]
	}
	return &ProbeChannel{
		name:       name,
		eventLoop:  handler,
		numWorkers: workers,
	}
}

// Start initiate a goroutine for the event loop handler, for a lost events messages and the perf map.
func (probeChannel *ProbeChannel) Start(module *bcc.Module, connectionFactory *connections.Factory) error {
	probeChannel.eventChannel = make(chan []byte, kafkaUtil.EventChanBuffSize)
	probeChannel.lostEventsChannel = make(chan uint64)

	table := bcc.NewTable(module.TableId(probeChannel.name), module)

	var err error
	probeChannel.perfMap, err = bcc.InitPerfMapWithPageCnt(table, probeChannel.eventChannel, probeChannel.lostEventsChannel, 65536)
	if err != nil {
		return fmt.Errorf("failed to init perf mapping for %q due to: %v", probeChannel.name, err)
	}

	// Launch N parallel goroutines to process events from the channel
	for i := 0; i < probeChannel.numWorkers; i++ {
		go probeChannel.eventLoop(probeChannel.eventChannel, connectionFactory)
	}
	go func() {
		log.Printf("⚠️ Lost events on channel, starting to listen for lost events on channel %s", probeChannel.name)
		for lost := range probeChannel.lostEventsChannel {
			log.Printf("⚠️ Lost %d events on channel %s", lost, probeChannel.name)
		}
	}()

	probeChannel.perfMap.Start()
	return nil
}

// LaunchPerfBufferConsumers launches all probe channels.
func LaunchPerfBufferConsumers(module *bcc.Module, connectionFactory *connections.Factory, probeList []*ProbeChannel) error {
	for _, probeChannel := range probeList {
		if err := probeChannel.Start(module, connectionFactory); err != nil {
			return err
		}
	}

	return nil
}
