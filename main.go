// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// This binary provides an example of connecting up bidirectional streams from
// the unidirectional streams provided by gopacket/tcpassembly.
package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"log"
	"time"
)

var iface = flag.String("i", "eth0", "Interface to get packets from")
var snaplen = flag.Int("s", 16<<10, "SnapLen for pcap packet capture")
var filter = flag.String("f", "tcp", "BPF filter for pcap")
var logAllPackets = flag.Bool("v", false, "Logs every packet in great detail")
var (
    handle   *pcap.Handle
    err      error	
)

// key is used to map bidirectional streams to each other.
type key struct {
	net, transport gopacket.Flow
}

// String prints out the key in a human-readable fashion.
func (k key) String() string {
	return fmt.Sprintf("%v:%v", k.net, k.transport)
}

// timeout is the length of time to wait befor flushing connections and
// bidirectional stream pairs.
const timeout time.Duration = time.Minute * 5

// myStream implements tcpassembly.Stream
type myStream struct {
	bytes []byte // total bytes seen on this stream.
	bidi  *bidi // maps to my bidirectional twin.
	done  bool  // if true, we've seen the last packet we're going to for this stream.
}

// bidi stores each unidirectional side of a bidirectional stream.
//
// When a new stream comes in, if we don't have an opposite stream, a bidi is
// created with 'a' set to the new stream.  If we DO have an opposite stream,
// 'b' is set to the new stream.
type bidi struct {
	key            key       // Key of the first stream, mostly for logging.
	a, b           *myStream // the two bidirectional streams.
	lastPacketSeen time.Time // last time we saw a packet from either stream.
}

// myFactory implements tcpassmebly.StreamFactory
type myFactory struct {
	// bidiMap maps keys to bidirectional stream pairs.
	bidiMap map[key]*bidi
}

// New handles creating a new tcpassembly.Stream.
func (f *myFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	// Create a new stream.
	s := &myStream{}

	// Find the bidi bidirectional struct for this stream, creating a new one if
	// one doesn't already exist in the map.
	k := key{netFlow, tcpFlow}
	bd := f.bidiMap[k]
	if bd == nil {
		bd = &bidi{a: s, key: k}
		log.Printf("[%v] created first side of bidirectional stream", bd.key)
		// Register bidirectional with the reverse key, so the matching stream going
		// the other direction will find it.
		f.bidiMap[key{netFlow.Reverse(), tcpFlow.Reverse()}] = bd
	} else {
		log.Printf("[%v] found second side of bidirectional stream", bd.key)
		bd.b = s
		// Clear out the bidi we're using from the map, just in case.
		delete(f.bidiMap, k)
	}
	s.bidi = bd
	return s
}

// emptyStream is used to finish bidi that only have one stream, in
// collectOldStreams.
var emptyStream = &myStream{done: true}

// collectOldStreams finds any streams that haven't received a packet within
// 'timeout', and sets/finishes the 'b' stream inside them.  The 'a' stream may
// still receive packets after this.
func (f *myFactory) collectOldStreams() {
	cutoff := time.Now().Add(-timeout)
	for k, bd := range f.bidiMap {
		if bd.lastPacketSeen.Before(cutoff) {
			log.Printf("[%v] timing out old stream", bd.key)
			bd.b = emptyStream   // stub out b with an empty stream.
			delete(f.bidiMap, k) // remove it from our map.
			bd.maybeFinish()     // if b was the last stream we were waiting for, finish up.
		}
	}
}

// Reassembled handles reassembled TCP stream data.
func (s *myStream) Reassembled(rs []tcpassembly.Reassembly) {
	for _, r := range rs {
		// For now, we'll simply count the bytes on each side of the TCP stream.
		s.bytes = append(s.bytes, r.Bytes...)
		log.Println("new packet %v %v %v =================================================================================", r.Start, r.End, string(r.Bytes))
		// Mark that we've received new packet data.
		// We could just use time.Now, but by using r.Seen we handle the case
		// where packets are being read from a file and could be very old.
		if s.bidi.lastPacketSeen.Before(r.Seen) {
			s.bidi.lastPacketSeen = r.Seen
		}
	}
}

// ReassemblyComplete marks this stream as finished.
func (s *myStream) ReassemblyComplete() {
	s.done = true
	s.bidi.maybeFinish()
}

// maybeFinish will wait until both directions are complete, then print out
// stats.
func (bd *bidi) maybeFinish() {
	switch {
	case bd.a == nil:
		log.Fatalf("[%v] a should always be non-nil, since it's set when bidis are created", bd.key)
	case !bd.a.done:
		log.Printf("[%v] still waiting on first stream", bd.key)
	case bd.b == nil:
		log.Printf("[%v] no second stream yet", bd.key)
	case !bd.b.done:
		log.Printf("[%v] still waiting on second stream", bd.key)
	default:
		log.Println("[%v] FINISHED, bytes: %v tx, %v rx", bd.key, string(bd.a.bytes), string(bd.b.bytes))
	}
}

func main() {
	defer util.Run()()
	log.Printf("starting capture on interface %q", *iface)
	// Set up pcap packet capture
    handle, err = pcap.OpenOffline("/Users/ankushjain/Downloads/dump2.pcap")
    if err != nil { log.Fatal(err) }
    defer handle.Close()


	// Set up assembly
	streamFactory := &myFactory{bidiMap: make(map[key]*bidi)}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	// Limit memory usage by auto-flushing connection state if we get over 100K
	// packets in memory, or over 1000 for a single stream.
	assembler.MaxBufferedPagesTotal = 100000
	assembler.MaxBufferedPagesPerConnection = 1000

	log.Println("reading in packets")
	// Read in packets, pass to assembler.
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Loop through packets in file
	for packet := range packetSource.Packets() {
		// log.Println("some packet")

		udpContent := packet.TransportLayer().(*layers.UDP)
		// log.Println("%v", udpContent.Payload)

		innerPacket := gopacket.NewPacket(udpContent.Payload[8:], layers.LayerTypeEthernet, gopacket.Default)

		// log.Println("%v", innerPacket)

		if innerPacket.NetworkLayer() == nil || innerPacket.TransportLayer() == nil || innerPacket.TransportLayer().LayerType() != layers.LayerTypeTCP {
			// log.Println("not a tcp payload")
			continue
		} else {
			tcp := innerPacket.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(innerPacket.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
		}
	}
}

