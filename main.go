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
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"github.com/akto-api-security/mirroring-api-logging/utils"
	"io"
	"io/fs"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
)

var isGcp = false
var printCounter = 500
var bytesInThreshold = 200 * 1024 * 1024
var bytesInSleepDuration = time.Second * 120
var assemblerMap = make(map[int]*tcpassembly.Assembler)
var incomingCountMap = make(map[string]utils.IncomingCounter)
var outgoingCountMap = make(map[string]utils.OutgoingCounter)

var readFiles = make(map[string]bool)

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

func shouldPrintDebugURL(url string) bool {
	debugUrls := os.Getenv("DEBUG_URLS")

	if len(debugUrls) == 0 {
		return false
	}

	for _, item := range strings.Split(debugUrls, ",") {
		item = strings.TrimSpace(item) // Trim any spaces from each item
		if strings.Contains(strings.TrimSpace(url), item) {
			return true
		}
	}

	return false
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

	s.bidi.maybeFinish()
}

// ReassemblyComplete marks this stream as finished.
func (s *myStream) ReassemblyComplete() {
	s.done = true
	s.bidi.maybeFinish()
}

func tryReadFromBD(bd *bidi, isPending bool) {
	reader := bufio.NewReader(bytes.NewReader(bd.a.bytes))
	i := 0
	requests := []http.Request{}
	requestsContent := []string{}

	for {
		req, err := http.ReadRequest(reader)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		} else if err != nil {
			log.Println("HTTP-request", "HTTP Request error: %s\n", err)
			return
		}

		if shouldPrintDebugURL(req.URL.String()) {
			fmt.Printf("Found debug url %s while reading from BD", req.URL.String())
		}

		body, err := ioutil.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			if shouldPrintDebugURL(req.URL.String()) {
				fmt.Printf("Got body err for debug url %s", req.URL.String())
			}
		}

		requests = append(requests, *req)
		requestsContent = append(requestsContent, string(body))
		// log.Println("req.URL.String()", i, req.URL.String(), string(body), len(bd.a.bytes))
		i++
	}

	reader = bufio.NewReader(bytes.NewReader(bd.b.bytes))
	i = 0
	//log.Println("len(req)", len(requests))
	for {
		if len(requests) < i+1 {
			break
		}
		req := &requests[i]
		resp, err := http.ReadResponse(reader, req)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		} else if err != nil {
			log.Println("HTTP-request", "HTTP Request error: %s\n", err)
			return
		}
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Println("HTTP-request-body", "Got body err: %s\n", err)
			return
		}
		encoding := resp.Header["Content-Encoding"]
		var r io.Reader
		r = bytes.NewBuffer(body)
		if len(encoding) > 0 && (encoding[0] == "gzip" || encoding[0] == "deflate") {
			r, err = gzip.NewReader(r)
			if err != nil {
				log.Println("HTTP-gunzip", "Failed to gzip decode: %s", err)
				return
			}
		}
		if err == nil {
			body, err = ioutil.ReadAll(r)
			if _, ok := r.(*gzip.Reader); ok {
				r.(*gzip.Reader).Close()
			}

		}

		reqHeader := make(map[string]string)
		for name, values := range req.Header {
			// Loop over all values for the name.
			for _, value := range values {
				reqHeader[name] = value
			}
		}

		reqHeader["host"] = req.Host

		respHeader := make(map[string]string)
		for name, values := range resp.Header {
			// Loop over all values for the name.
			for _, value := range values {
				respHeader[name] = value
			}
		}

		reqHeaderString, _ := json.Marshal(reqHeader)
		respHeaderString, _ := json.Marshal(respHeader)

		if shouldPrintDebugURL(req.URL.String()) {
			fmt.Printf("Found debug url %s while creating final value", req.URL.String())
		}

		value := map[string]string{
			"path":            req.URL.String(),
			"requestHeaders":  string(reqHeaderString),
			"responseHeaders": string(respHeaderString),
			"method":          req.Method,
			"requestPayload":  requestsContent[i],
			"responsePayload": string(body),
			"ip":              bd.key.net.Src().String(),
			"time":            fmt.Sprint(time.Now().Unix()),
			"statusCode":      fmt.Sprint(resp.StatusCode),
			"type":            string(req.Proto),
			"status":          resp.Status,
			"akto_account_id": fmt.Sprint(1000000),
			"akto_vxlan_id":   fmt.Sprint(bd.vxlanID),
			"is_pending":      fmt.Sprint(isPending),
			"source":          bd.source,
		}

		out, _ := json.Marshal(value)
		if 1 > 2 {
			println(out)
		}
		totalCounter += 1

		// calculating the size of outgoing bytes and requests (1) and saving it in outgoingCounterMap
		outgoingBytes := len(bd.a.bytes) + len(bd.b.bytes)
		if totalCounter%100 == 0 {
			println("outgoingBytes: ", outgoingBytes)
		}
		i++
	}
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
		} else if timeNow.Sub(bd.lastProcessedTime).Seconds() >= 60 {
			tryReadFromBD(bd, true)
			bd.lastProcessedTime = timeNow
		}
	}
}

func flushAll() {
	for _, v := range assemblerMap {
		v.FlushAll()
	}
}

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

		assemblerMap[vxlanID] = _assembler
		log.Println("created assembler for vxlanID=", vxlanID)

	}
	return _assembler

}

func run(handle *pcap.Handle, apiCollectionId int, source string) {
	kafka_url := os.Getenv("AKTO_KAFKA_BROKER_MAL")
	log.Println("kafka_url", kafka_url)

	if len(kafka_url) == 0 {
		kafka_url = os.Getenv("AKTO_KAFKA_BROKER_URL")
	}
	log.Println("kafka_url", kafka_url)

	bytesInThresholdInput := os.Getenv("AKTO_BYTES_IN_THRESHOLD")
	if len(bytesInThresholdInput) > 0 {
		bytesInThreshold, err = strconv.Atoi(bytesInThresholdInput)
		if err != nil {
			log.Println("AKTO_BYTES_IN_THRESHOLD should be valid integer. Found ", bytesInThresholdInput)
			return
		} else {
			log.Println("Setting bytes in threshold at ", bytesInThreshold)
		}

	}

	// Set up pcap packet capture
	// handle, err = pcap.OpenOffline("/Users/ankushjain/Downloads/dump2.pcap")
	// if err != nil {  }

	if !isGcp {
		if err := handle.SetBPFFilter("udp and port 4789"); err != nil { // optional
			log.Printf("SetBPFFilter error: %v", err)
			return
		}
	}

	log.Println("reading in packets")
	// Read in packets, pass to assembler.
	var bytesIn = 0
	var bytesInEpoch = time.Now()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		innerPacket := packet
		vxlanID := apiCollectionId
		if apiCollectionId <= 0 && !isGcp {

			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeUDP {
				continue
			}

			udpContent := packet.TransportLayer().(*layers.UDP)

			vxlanIDbyteArr := udpContent.Payload[4:7]
			vxlanID = int(vxlanIDbyteArr[2]) + (int(vxlanIDbyteArr[1]) * 256) + (int(vxlanIDbyteArr[0]) * 256 * 256)
			innerPacket = gopacket.NewPacket(udpContent.Payload[8:], layers.LayerTypeEthernet, gopacket.Default)
			// log.Println("%v", innerPacket)
		}
		if innerPacket.NetworkLayer() == nil || innerPacket.TransportLayer() == nil || innerPacket.TransportLayer().LayerType() != layers.LayerTypeTCP {
			// log.Println("not a tcp payload")
			continue
		} else {
			if isGcp {
				vxlanID = 0
			}
			tcp := innerPacket.TransportLayer().(*layers.TCP)

			payloadLength := len(tcp.Payload)
			ip := innerPacket.NetworkLayer().NetworkFlow().Src().String()
			ic := utils.GenerateIncomingCounter(vxlanID, ip)
			existingIC, ok := incomingCountMap[ic.IncomingCounterKey()]
			if ok {
				existingIC.Inc(payloadLength)
			} else {
				ic.Inc(payloadLength)
				incomingCountMap[ic.IncomingCounterKey()] = ic
			}

			assembler := createAndGetAssembler(vxlanID, source)
			assembler.AssembleWithTimestamp(innerPacket.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

			bytesIn += len(tcp.Payload)

			if bytesIn%1_000_000 == 0 {
				log.Println("Bytes in: ", bytesIn)
			}

			if bytesIn > bytesInThreshold {
				if time.Now().Sub(bytesInEpoch).Seconds() < 60 {
					log.Println("exceeded bytesInThreshold: ", bytesInThreshold, " with curr: ", bytesIn)
					log.Println("sleeping for: ", bytesInSleepDuration)
					flushAll()
					time.Sleep(bytesInSleepDuration)
				}

				bytesIn = 0
				bytesInEpoch = time.Now()
			}

		}
	}
}

//export readTcpDumpFile
func readTcpDumpFile(filepath string, kafkaURL string, apiCollectionId int) {
	os.Setenv("AKTO_KAFKA_BROKER_URL", kafkaURL)
	os.Setenv("AKTO_TRAFFIC_BATCH_SIZE", "1")
	os.Setenv("AKTO_TRAFFIC_BATCH_TIME_SECS", "1")

	if handle, err := pcap.OpenOffline(filepath); err != nil {
		log.Fatal(err)
	} else {
		run(handle, apiCollectionId, "PCAP")
	}
}

var totalCounter = 0

func getDirectoryName() string {
	aktoClientId := os.Getenv("AKTO_CLIENT_ID")
	return "/app/files_" + aktoClientId + "/"
}

func main() {
	isGcp = true

	for {
		files, err := ioutil.ReadDir(getDirectoryName())
		log.Println("reading files...")
		if err != nil {
			log.Printf("Error reading files from directory : %v", err)
			continue
		}

		for _, file := range files {
			readTCPFileAndProcess(file)
		}

		time.Sleep(time.Second * 2)
	}

}

func cleanupReadFilesMap() {
	timeNow := time.Now().Unix()
	for k, _ := range readFiles {
		fileCreationTs, _ := strconv.Atoi(k)
		if timeNow-int64(fileCreationTs) > 600 {
			delete(readFiles, k)
		}
	}
}

func readTCPFileAndProcess(file fs.FileInfo) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Recovering from panic : %v \n", r)
			return
		}
	}()

	if file.IsDir() {
		return
	}

	fileName := file.Name()
	fileNameSplit := strings.Split(fileName, ".")
	fileCreationTs, _ := strconv.Atoi(fileNameSplit[0])

	filePath := getDirectoryName() + file.Name()
	timeNow := time.Now().Unix()
	if timeNow-int64(fileCreationTs) < 35 {
		return
	}

	_, ok := readFiles[file.Name()]
	if ok {
		return
	} else {
		readFiles[file.Name()] = true
	}

	log.Println("file: " + file.Name() + " size (" + strconv.FormatInt(file.Size(), 10) + ")")

	assemblerMap = make(map[int]*tcpassembly.Assembler)

	if handle, err := pcap.OpenOffline(filePath); err != nil {
		log.Printf("Error while creating pcap handle %v", err)
	} else {
		run(handle, -1, "MIRRORING")
		flushAll()
		handle.Close()
	}
}
