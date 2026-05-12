package bpfwrapper

import (
	"errors"
	"fmt"
	"log"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/connections"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

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

// Start opens the ring buffer reader and processes events inline — no intermediate Go channel.
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
		for {
			if err := pc.reader.ReadInto(&rec); err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Printf("error reading ring buffer event on %s: %v", pc.name, err)
				continue
			}
			pc.handler(rec.RawSample, connectionFactory)
		}
	}()

	return nil
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
