package bpfwrapper

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/connections"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/kafkaUtil"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

// ProbeEventLoop is the signature for callbacks that drain perf event channels.
type ProbeEventLoop func(inputChan chan []byte, connectionFactory *connections.Factory)

// ProbeChannel links a named BPF perf-event array to a Go channel and event loop.
type ProbeChannel struct {
	name         string
	eventLoop    ProbeEventLoop
	eventChannel chan []byte
	reader       *perf.Reader
}

// NewProbeChannel creates a new probe channel for the given BPF perf-event array name.
func NewProbeChannel(name string, handler ProbeEventLoop) *ProbeChannel {
	return &ProbeChannel{
		name:      name,
		eventLoop: handler,
	}
}

// Start opens the perf reader, launches the event loop goroutine and starts draining.
func (pc *ProbeChannel) Start(coll *ebpf.Collection, connectionFactory *connections.Factory) error {
	m, ok := coll.Maps[pc.name]
	if !ok {
		return fmt.Errorf("BPF map %q not found in collection", pc.name)
	}

	pc.eventChannel = make(chan []byte, kafkaUtil.EventChanBuffSize)

	var err error
	pc.reader, err = perf.NewReader(m, os.Getpagesize()*8192)
	if err != nil {
		return fmt.Errorf("failed to open perf reader for %q: %v", pc.name, err)
	}

	go pc.eventLoop(pc.eventChannel, connectionFactory)

	go func() {
		log.Printf("perf reader started for channel %s", pc.name)
		for {
			record, err := pc.reader.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					close(pc.eventChannel)
					return
				}
				log.Printf("error reading perf event on %s: %v", pc.name, err)
				continue
			}
			if record.LostSamples > 0 {
				log.Printf("⚠️ Lost %d events on channel %s", record.LostSamples, pc.name)
				continue
			}
			pc.eventChannel <- record.RawSample
		}
	}()

	return nil
}

// Stop closes the underlying perf reader, which will unblock the drain goroutine.
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
