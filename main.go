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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/db"
	"github.com/akto-api-security/mirroring-api-logging/utils"
	"go.mongodb.org/mongo-driver/mongo/readpref"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"

	"net"

	"github.com/akto-api-security/gomiddleware"
	"github.com/segmentio/kafka-go"
)

var printCounter = 500
var bytesInThreshold = 10 * 1024 * 1024
var bytesInSleepDuration = time.Second * 120
var assemblerMap = make(map[int]*tcpassembly.Assembler)
var incomingCountMap = make(map[string]utils.IncomingCounter)
var outgoingCountMap = make(map[string]utils.OutgoingCounter)

var filterHeaderValueMap = make(map[string]string)

var ignoreCloudMetadataCalls = false
var ignoreIpTraffic = false
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

func checkIfIp(host string) bool {
	if len(host) == 0 {
		return true
	}
	chunks := strings.Split(host, ":")
	return net.ParseIP(chunks[0]) != nil
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
			printLog(fmt.Sprintf("HTTP-request error: %s \n", err))
			return
		}
		body, err := ioutil.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			printLog(fmt.Sprintf("Got body err: %s\n", err))
			return
		}

		requests = append(requests, *req)
		requestsContent = append(requestsContent, string(body))
		i++
	}

	if len(requests) == 0 {
		return
	}

	reader = bufio.NewReader(bytes.NewReader(bd.b.bytes))
	i = 0

	responses := []http.Response{}
	responsesContent := []string{}

	for {

		resp, err := http.ReadResponse(reader, nil)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		} else if err != nil {
			printLog(fmt.Sprintf("HTTP Request error: %s\n", err))
			return
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			printLog(fmt.Sprintf("Got body err: %s\n", err))
			return
		}
		encoding := resp.Header["Content-Encoding"]
		var r io.Reader
		r = bytes.NewBuffer(body)
		if len(encoding) > 0 && (encoding[0] == "gzip" || encoding[0] == "deflate") {
			r, err = gzip.NewReader(r)
			if err != nil {
				printLog(fmt.Sprintf("HTTP-gunzip "+"Failed to gzip decode: %s", err))
				return
			}
		}
		if err == nil {
			body, err = ioutil.ReadAll(r)
			if _, ok := r.(*gzip.Reader); ok {
				r.(*gzip.Reader).Close()
			}

		}

		responses = append(responses, *resp)
		responsesContent = append(responsesContent, string(body))

		i++
	}

	if len(requests) != len(responses) {
		return
	}

	i = 0
	for {
		if len(requests) < i+1 {
			break
		}

		req := &requests[i]
		resp := &responses[i]

		reqHeader := make(map[string]string)
		for name, values := range req.Header {
			// Loop over all values for the name.
			for _, value := range values {
				reqHeader[name] = value
			}
		}

		reqHeader["host"] = req.Host

		passes := utils.PassesFilter(filterHeaderValueMap, reqHeader)
		//printLog("Req header: " + mapToString(reqHeader))
		//printLog(fmt.Sprintf("passes %t", passes))

		if !passes {
			i++
			continue
		}

		if ignoreIpTraffic && checkIfIp(req.Host) {
			i++
			continue
		}

		if ignoreCloudMetadataCalls && req.Host == "169.254.169.254" {
			i++
			continue
		}

		respHeader := make(map[string]string)
		for name, values := range resp.Header {
			// Loop over all values for the name.
			for _, value := range values {
				respHeader[name] = value
			}
		}

		reqHeaderString, _ := json.Marshal(reqHeader)
		respHeaderString, _ := json.Marshal(respHeader)

		value := map[string]string{
			"path":            req.URL.String(),
			"requestHeaders":  string(reqHeaderString),
			"responseHeaders": string(respHeaderString),
			"method":          req.Method,
			"requestPayload":  requestsContent[i],
			"responsePayload": responsesContent[i],
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
		ctx := context.Background()

		// calculating the size of outgoing bytes and requests (1) and saving it in outgoingCounterMap
		outgoingBytes := len(bd.a.bytes) + len(bd.b.bytes)
		hostString := reqHeader["host"]
		if utils.CheckIfIpHost(hostString) {
			hostString = "ip-host"
		}
		oc := utils.GenerateOutgoingCounter(bd.vxlanID, bd.key.net.Src().String(), hostString)
		existingOc, ok := outgoingCountMap[oc.OutgoingCounterKey()]
		if ok {
			existingOc.Inc(outgoingBytes, 1)
		} else {
			oc.Inc(outgoingBytes, 1)
			outgoingCountMap[oc.OutgoingCounterKey()] = oc
		}

		//printLog("req-resp.String() " + string(out))
		go gomiddleware.Produce(kafkaWriter, ctx, string(out))
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

var kafkaWriter *kafka.Writer

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
	kafka_url := os.Getenv("AKTO_KAFKA_BROKER_MAL")

	if len(kafka_url) == 0 {
		kafka_url = os.Getenv("AKTO_KAFKA_BROKER_URL")
	}
	printLog("kafka_url: " + kafka_url)

	bytesInThresholdInput := os.Getenv("AKTO_BYTES_IN_THRESHOLD")
	if len(bytesInThresholdInput) > 0 {
		bytesInThreshold, err = strconv.Atoi(bytesInThresholdInput)
		if err != nil {
			printLog("AKTO_BYTES_IN_THRESHOLD should be valid integer. Found " + bytesInThresholdInput)
			return
		} else {
			printLog("Setting bytes in threshold at " + strconv.Itoa(bytesInThreshold))
		}

	}

	kafka_batch_size, e := strconv.Atoi(os.Getenv("AKTO_TRAFFIC_BATCH_SIZE"))
	if e != nil {
		printLog("AKTO_TRAFFIC_BATCH_SIZE should be valid integer")
		return
	}

	kafka_batch_time_secs, e := strconv.Atoi(os.Getenv("AKTO_TRAFFIC_BATCH_TIME_SECS"))
	if e != nil {
		printLog("AKTO_TRAFFIC_BATCH_TIME_SECS should be valid integer")
		return
	}
	kafka_batch_time_secs_duration := time.Duration(kafka_batch_time_secs)

	kafkaWriter = gomiddleware.GetKafkaWriter(kafka_url, "akto.api.logs", kafka_batch_size, kafka_batch_time_secs_duration*time.Second)
	// Set up pcap packet capture
	// handle, err = pcap.OpenOffline("/Users/ankushjain/Downloads/dump2.pcap")
	// if err != nil {  }

	if err := handle.SetBPFFilter("not (port 9092 or port 22)"); err != nil { // optional
		log.Fatal(err)
		return
	}

	printLog("reading in packets")
	// Read in packets, pass to assembler.
	var bytesIn = 0
	var bytesInEpoch = time.Now()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {

		innerPacket := packet
		vxlanID := apiCollectionId
		if innerPacket.NetworkLayer() == nil || innerPacket.TransportLayer() == nil || innerPacket.TransportLayer().LayerType() != layers.LayerTypeTCP {
			printLog("not a tcp payload")
			continue
		} else {
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

			if bytesIn > bytesInThreshold {
				log.Println("exceeded bytesInThreshold: ", bytesInThreshold, " with curr: ", bytesIn)
				log.Println("limit reached, sleeping", time.Now())
				wipeOut()
				bytesIn = 0
				bytesInEpoch = time.Now()
				time.Sleep(10 * time.Second)
				kafkaWriter.Close()
				break
			}

			if time.Now().Sub(bytesInEpoch).Seconds() > 3 {
				bytesInEpoch = time.Now()
				flushAll()
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

func main() {
	disableOnDb := os.Getenv("AKTO_DISABLE_ON_DB")
	disableOnDbFlag := disableOnDb == "true"

	log.Printf("Disable flag : %t", disableOnDbFlag)

	client, err := db.GetMongoClient()
	mongoPingErr := client.Ping(context.Background(), readpref.Primary())
	if err != nil || mongoPingErr != nil {
		log.Printf("Failed connecting to mongo %s", err)
		if disableOnDbFlag {
			log.Println("Exiting....")
			time.Sleep(time.Second * 60)
			panic("Failed connecting to mongo") // this will get restarted by docker
		}
	}

	defer func() {
		if err := client.Disconnect(context.Background()); err != nil {
			// Handle error
		}
	}()
	ignoreIpTrafficVar := os.Getenv("AKTO_IGNORE_IP_TRAFFIC")
	if len(ignoreIpTrafficVar) > 0 {
		ignoreIpTraffic = strings.ToLower(ignoreIpTrafficVar) == "true"
		log.Println("ignoreIpTraffic: ", ignoreIpTraffic)
	} else {
		log.Println("ignoreIpTraffic: missing. defaulting to false")
	}

	ignoreCloudMetadataCallsVar := os.Getenv("AKTO_IGNORE_CLOUD_METADATA_CALLS")
	if len(ignoreCloudMetadataCallsVar) > 0 {
		ignoreCloudMetadataCalls = strings.ToLower(ignoreCloudMetadataCallsVar) == "true"
		log.Println("ignoreCloudMetadataCalls: ", ignoreCloudMetadataCalls)
	} else {
		log.Println("ignoreCloudMetadataCalls: missing. defaulting to false")
	}

	// Set up a ticker to run every 2 minutes
	ticker := time.NewTicker(2 * time.Minute)

	tickerCode() // to run this immediately
	go func() {
		for range ticker.C {
			tickerCode()
		}
	}()

	interfaceName := "any"
	for {
		if handle, err := pcap.OpenLive(interfaceName, 128*1024, true, pcap.BlockForever); err != nil {
			log.Fatal(err)
		} else {
			run(handle, -1, "MIRRORING")
			log.Println("closing pcap connection....")
			handle.Close()
			log.Println("sleeping....")
			assemblerMap = make(map[int]*tcpassembly.Assembler)
			incomingCountMap = make(map[string]utils.IncomingCounter)
			outgoingCountMap = make(map[string]utils.OutgoingCounter)
			time.Sleep(10 * time.Second)
			log.Println("SLEPT")
		}
	}

}

func tickerCode() {
	log.Println("Running ticker")
	db.TrafficMetricsDbUpdates(incomingCountMap, outgoingCountMap)
	incomingCountMap = make(map[string]utils.IncomingCounter)
	outgoingCountMap = make(map[string]utils.OutgoingCounter)
	filterHeaderValueMap = db.FetchFilterHeaderMap()
}

func printLog(val string) {
	if printCounter > 0 {
		log.Println(val)
		printCounter--
	}
}

func mapToString(m map[string]string) string {
	jsonBytes, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return string(jsonBytes)
}
