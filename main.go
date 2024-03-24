// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// This binary provides an example of connecting up bidirectional streams from
// the unidirectional streams provided by gopacket/tcpassembly.
package main

import "C"

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/db"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/kafkaUtil"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/trafficMetrics"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"

	"net"
)

var bytesInSleepDuration = time.Second * 120
var assemblerMap = make(map[int]*tcpassembly.Assembler)
var maintainTrafficIpMap = false

var (
	handle *pcap.Handle
	err    error
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
const timeout time.Duration = time.Minute * 1

// myStream implements tcpassembly.Stream
type myStream struct {
	bytes []byte // total bytes seen on this stream.
	bidi  *bidi  // maps to my bidirectional twin.
	done  bool   // if true, we've seen the last packet we're going to for this stream.
}

// bidi stores each unidirectional side of a bidirectional stream.
//
// When a new stream comes in, if we don't have an opposite stream, a bidi is
// created with 'a' set to the new stream.  If we DO have an opposite stream,
// 'b' is set to the new stream.
type bidi struct {
	key               key       // Key of the first stream, mostly for logging.
	a, b              *myStream // the two bidirectional streams.
	lastPacketSeen    time.Time // last time we saw a packet from either stream.
	lastProcessedTime time.Time
	vxlanID           int
	source            string
}

// myFactory implements tcpassmebly.StreamFactory
type myFactory struct {
	// bidiMap maps keys to bidirectional stream pairs.
	bidiMap map[key]*bidi
	vxlanID int
	source  string
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
		bd = &bidi{a: s, key: k, vxlanID: f.vxlanID, source: f.source}
		//log.Printf("[%v] created first side of bidirectional stream", bd.key)
		// Register bidirectional with the reverse key, so the matching stream going
		// the other direction will find it.
		f.bidiMap[key{netFlow.Reverse(), tcpFlow.Reverse()}] = bd
	} else {
		//log.Printf("[%v] found second side of bidirectional stream", bd.key)
		bd.b = s
		// Clear out the bidi we're using from the map, just in case.
		delete(f.bidiMap, k)
	}
	s.bidi = bd
	bd.lastProcessedTime = time.Now()
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
	if s.done {
		return
	}
	for _, r := range rs {
		// For now, we'll simply count the bytes on each side of the TCP stream.
		if r.Skip > 0 {
			s.done = true
			return
		}
		s.bytes = append(s.bytes, r.Bytes...)
		// Mark that we've received new packet data.
		// We could just use time.Now, but by using r.Seen we handle the case
		// where packets are being read from a file and could be very old.
		if s.bidi.lastPacketSeen.Before(r.Seen) {
			s.bidi.lastPacketSeen = r.Seen
		}
	}

	//s.bidi.maybeFinish()
}

// ReassemblyComplete marks this stream as finished.
func (s *myStream) ReassemblyComplete() {
	s.done = true
	s.bidi.maybeFinish()
}

func tryReadFromBD(bd *bidi, isPending bool) {

	kafkaUtil.ParseAndProduce(bd.a.bytes, bd.b.bytes,
		bd.key.net.Src().String(), bd.vxlanID, isPending, bd.source)

}

// maybeFinish will wait until both directions are complete, then print out
// stats.
func (bd *bidi) maybeFinish() {
	timeNow := time.Now()
	switch {
	case bd.a == nil:
		//log.Fatalf("[%v] a should always be non-nil, since it's set when bidis are created", bd.key)
	case bd.b == nil:
		//log.Printf("[%v] no second stream yet", bd.key)
	default:
		if bd.a.done && bd.b.done {
			tryReadFromBD(bd, false)
			bd.a.bytes = make([]byte, 0)
			bd.b.bytes = make([]byte, 0)
		} else if timeNow.Sub(bd.lastProcessedTime).Seconds() >= 60 {
			tryReadFromBD(bd, true)
			bd.lastProcessedTime = timeNow
		}
	}
}

func wipeOut() {
	for _, v := range assemblerMap {
		v.FlushAll()
	}
}

var factoryMap = make(map[int]*myFactory)

func createAndGetAssembler(vxlanID int, source string) *tcpassembly.Assembler {

	_assembler := assemblerMap[vxlanID]
	if _assembler == nil {
		log.Println("creating assembler for vxlanID=", vxlanID)
		// Set up assembly
		streamFactory := &myFactory{bidiMap: make(map[key]*bidi), vxlanID: vxlanID, source: source}
		streamPool := tcpassembly.NewStreamPool(streamFactory)
		_assembler = tcpassembly.NewAssembler(streamPool)
		// Limit memory usage by auto-flushing connection state if we get over 100K
		// packets in memory, or over 1000 for a single stream.
		_assembler.MaxBufferedPagesTotal = 100000
		_assembler.MaxBufferedPagesPerConnection = 1000

		factoryMap[vxlanID] = streamFactory
		assemblerMap[vxlanID] = _assembler
		log.Println("created assembler for vxlanID=", vxlanID)

	}
	return _assembler

}

func flushAll() {
	for _, v := range assemblerMap {
		v.FlushOlderThan(time.Now().Add(time.Second * -5))
		//log.Println("num flushed/closed:", r, k)
		//log.Println("streams before closing: ", len(factoryMap[k].bidiMap))
		//factoryMap[k].collectOldStreams()
		//log.Println("streams after closing: ", len(factoryMap[k].bidiMap))
	}
}

func run(handle *pcap.Handle, apiCollectionId int, source string) {

	if err := handle.SetBPFFilter("tcp && not (port 9092 or port 22)"); err != nil { // optional
		log.Fatal(err)
		return
	}

	utils.PrintLog("reading in packets")

	interfaceMap := make(map[string]bool)
	incomingReqSrcIpCountMap := make(map[string]int)
	incomingReqDstIpCountMap := make(map[string]int)

	maintainTrafficIpMapInput := os.Getenv("MAINTAIN_TRAFFIC_IP_MAP")
	if len(maintainTrafficIpMapInput) > 0 {
		val, err := strconv.ParseBool(maintainTrafficIpMapInput)
		if err != nil {
			fmt.Println("invalid value set for flag MAINTAIN_TRAFFIC_IP_MAP")
		}
		fmt.Println("setting MAINTAIN_TRAFFIC_IP_MAP = ", val)
		maintainTrafficIpMap = val
	}

	utils.InitMemThresh()

	if maintainTrafficIpMap {
		ifaces, err := net.Interfaces()
		if err == nil && ifaces != nil {
			for _, i := range ifaces {
				addrs, err := i.Addrs()
				if err != nil {
					fmt.Print(fmt.Errorf("localAddresses: %+v", err.Error()))
					continue
				}
				for _, a := range addrs {

					if ipnet, ok := a.(*net.IPNet); ok {
						// Check if it's an IPv4 address
						if ipnet.IP.To4() != nil {
							// Compare the address with the target address
							fmt.Printf("Interface addr %s\n", ipnet.IP.To4().String())
							interfaceMap[ipnet.IP.To4().String()] = true
						}
					}
				}
			}
		}

	}

	// Read in packets, pass to assembler.
	var bytesIn = 0
	var bytesInEpoch = time.Now()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {

		innerPacket := packet
		vxlanID := apiCollectionId
		if innerPacket.NetworkLayer() == nil || innerPacket.TransportLayer() == nil || innerPacket.TransportLayer().LayerType() != layers.LayerTypeTCP {
			utils.PrintLog("not a tcp payload")
			continue
		} else {
			tcp := innerPacket.TransportLayer().(*layers.TCP)

			payloadLength := len(tcp.Payload)
			ip := innerPacket.NetworkLayer().NetworkFlow().Src().String()
			ic := utils.GenerateIncomingCounter(vxlanID, ip)

			if maintainTrafficIpMap {
				src, dst := innerPacket.NetworkLayer().NetworkFlow().Endpoints()

				dstEndpoint := dst.Raw()
				//fmt.Println("dstEndpoint ", len(dstEndpoint))

				srcEndpoint := src.Raw()
				//fmt.Println("srcEndpoint ", len(srcEndpoint))

				srcIp := getIpString(srcEndpoint)

				dstIp := getIpString(dstEndpoint)

				_, ok2 := incomingReqSrcIpCountMap[srcIp]
				if !ok2 {
					incomingReqSrcIpCountMap[srcIp] = 0
				}
				incomingReqSrcIpCountMap[srcIp] += len(tcp.Payload)

				_, ok2 = incomingReqDstIpCountMap[dstIp]
				if !ok2 {
					incomingReqDstIpCountMap[dstIp] = 0
				}
				incomingReqDstIpCountMap[dstIp] += len(tcp.Payload)
			}

			trafficMetrics.SubmitIncomingTrafficMetrics(ic, payloadLength)

			assembler := createAndGetAssembler(vxlanID, source)
			assembler.AssembleWithTimestamp(innerPacket.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

			bytesIn += len(tcp.Payload)

			if bytesIn > kafkaUtil.BytesInThreshold {
				log.Println("exceeded bytesInThreshold: ", kafkaUtil.BytesInThreshold, " with curr: ", bytesIn)
				log.Println("limit reached, sleeping", time.Now())

				log.Println("logging memory stats before wipeout", time.Now())
				utils.LogMemoryStats()
				wipeOut()
				log.Println("wipeout done", time.Now())
				log.Println("logging memory stats post wipeout", time.Now())
				utils.LogMemoryStats()

				for k, v := range incomingReqSrcIpCountMap {
					log.Printf("srcIp %s, total req %d", k, v)
				}

				for k, v := range incomingReqDstIpCountMap {
					log.Printf("dstIp %s, total req %d", k, v)
				}

				bytesIn = 0
				bytesInEpoch = time.Now()
				time.Sleep(10 * time.Second)
				kafkaUtil.Close()
				break
			}

			if time.Since(bytesInEpoch).Seconds() > 3 {
				bytesInEpoch = time.Now()
				flushAll()
				utils.LogMemoryStats()
				kafkaUtil.LogKafkaStats()
			}

			kafkaUtil.LogKafkaError()

		}
	}
}

func getIpString(endpoint []byte) string {
	ip := ""
	if endpoint == nil {
		return ""
	}
	for i := 0; i < len(endpoint); i++ {
		r := strconv.Itoa(int(endpoint[i]))
		if len(ip) > 0 {
			ip = ip + "." + r
		} else {
			ip = ip + r
		}
	}
	return ip
}

//export readTcpDumpFile
func readTcpDumpFile(filepath string, kafkaURL string, apiCollectionId int) {
	os.Setenv("AKTO_KAFKA_BROKER_URL", kafkaURL)
	os.Setenv("AKTO_TRAFFIC_BATCH_SIZE", "1")
	os.Setenv("AKTO_TRAFFIC_BATCH_TIME_SECS", "1")

	kafkaUtil.InitKafka()

	if handle, err := pcap.OpenOffline(filepath); err != nil {
		log.Fatal(err)
	} else {
		run(handle, apiCollectionId, "PCAP")
	}
}

func main() {
	db.InitMongoClient()
	defer db.CloseMongoClient()

	utils.InitIgnoreVars()

	trafficMetrics.StartMetricsTicker()

	interfaceName := "any"
	kafkaUtil.InitKafka()
	for {
		if handle, err := pcap.OpenLive(interfaceName, 128*1024, true, pcap.BlockForever); err != nil {
			log.Fatal(err)
		} else {
			run(handle, -1, "MIRRORING")
			log.Println("closing pcap connection....")
			handle.Close()
			log.Println("sleeping....")
			assemblerMap = make(map[int]*tcpassembly.Assembler)
			trafficMetrics.InitTrafficMaps()
			time.Sleep(10 * time.Second)
			log.Println("SLEPT")
			kafkaUtil.InitKafka()
		}
	}

}

func mapToString(m map[string]string) string {
	jsonBytes, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return string(jsonBytes)
}
