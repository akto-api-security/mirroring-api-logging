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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

	"github.com/akto-api-security/gomiddleware"
	"github.com/segmentio/kafka-go"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

var printCounter = 500
var assemblerMap = make(map[int]*tcpassembly.Assembler)
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
const timeout time.Duration = time.Minute * 5

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
}

// myFactory implements tcpassmebly.StreamFactory
type myFactory struct {
	// bidiMap maps keys to bidirectional stream pairs.
	bidiMap map[key]*bidi
	vxlanID int
}

type http2ReqResp struct {
	headersMap map[string]string
	payload    string
	isInvalid  bool
}

func (k http2ReqResp) String() string {
	return fmt.Sprintf("%v:%v", k.headersMap, k.payload)
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
		bd = &bidi{a: s, key: k, vxlanID: f.vxlanID}
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
	for _, r := range rs {
		// For now, we'll simply count the bytes on each side of the TCP stream.
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

func tryParseAsHttp2Request(bd *bidi, isPending bool) (bool, error) {

	isHttp2Req := false
	if len(bd.a.bytes) > 24 && string(bd.a.bytes[0:24]) == "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
		bd.a.bytes = bd.a.bytes[24:]
	}
	streamRequestMap := make(map[string][]http2ReqResp)
	framer := http2.NewFramer(nil, bytes.NewReader(bd.a.bytes))

	headersMap := make(map[string]string)
	payload := ""

	gotHeaders := make(map[string]bool)
	gotPayload := make(map[string]bool)
	decoder := hpack.NewDecoder(4096, func(hf hpack.HeaderField) {

		// fmt.Printf("REQ Header: %s: %s\n", hf.Name, hf.Value)
		if len(hf.Name) > 0 {
			headersMap[hf.Name] = hf.Value
		}
	})

	for {

		frame, err := framer.ReadFrame()
		// fmt.Printf("Frame: %v\n", frame)

		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		// Print frame details
		// fmt.Printf("Frame reached here: %v\n", frame)
		// fmt.Printf("Stream Id: %v\n", frame.Header().StreamID)
		streamId := fmt.Sprint(frame.Header().StreamID)
		if len(streamId) == 0 {
			continue
		}

		if !gotHeaders[streamId] {
			headersMap = make(map[string]string)
		}

		// fmt.Printf("Frame reached here: %v\n", frame.Header().StreamID)
		// fmt.Printf("streamId working on %v\n", streamId)
		switch f := frame.(type) {
		case *http2.HeadersFrame:
			_, err := decoder.Write(f.HeaderBlockFragment())
			gotHeaders[streamId] = true
			if err != nil {
				// log.Printf("Error request decoding headers: %v", err)
			}

		case *http2.DataFrame:
			// log.Println("Data: ", len(f.Data()), string(f.Data()))
			if len(string(f.Data())) > 0 {
				payload = base64.StdEncoding.EncodeToString(f.Data())
				gotPayload[streamId] = true
				// fmt.Println("payload", payload)
			}
		}

		if gotHeaders[streamId] && gotPayload[streamId] {
			if _, exists := streamRequestMap[streamId]; !exists {
				streamRequestMap[streamId] = []http2ReqResp{}
			}
			streamRequestMap[streamId] = append(streamRequestMap[streamId], http2ReqResp{
				headersMap: headersMap,
				payload:    payload,
			})
			gotHeaders[streamId] = false
			gotPayload[streamId] = false
		}
	}

	// log.Println("Reached here for resp")
	// log.Println("bd.b.bytes: ", len(bd.b.bytes), string(bd.b.bytes))

	gotHeaders = make(map[string]bool)
	gotPayload = make(map[string]bool)
	gotGrpcHeaders := make(map[string]bool)
	headersCount := make(map[string]int)
	headersMap = make(map[string]string)
	payload = ""

	streamResponseMap := make(map[string][]http2ReqResp)
	framerResp := http2.NewFramer(nil, bytes.NewReader(bd.b.bytes))
	headersMap = make(map[string]string)
	decoder = hpack.NewDecoder(4096, func(hf hpack.HeaderField) {
		// fmt.Printf("RES Header: %s: %s\n", hf.Name, hf.Value)
		if len(hf.Name) > 0 {
			headersMap[hf.Name] = hf.Value
		}
	})

	for {
		frame, err := framerResp.ReadFrame()
		// fmt.Printf("Frame: %v\n", frame)
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		// Print frame details
		streamId := fmt.Sprint(frame.Header().StreamID)

		if len(streamId) == 0 {
			continue
		}
		if !(gotHeaders[streamId]) {
			headersMap = make(map[string]string)
		}

		switch f := frame.(type) {
		case *http2.HeadersFrame:
			// fmt.Println("headers map", headersMap)
			_, err := decoder.Write(f.HeaderBlockFragment())
			if err != nil {
				log.Printf("Error response decoding headers: %v", err)
			}
			if headersCount[streamId] == 0 {
				if strings.Contains(headersMap["content-type"], "application/grpc") {
					gotGrpcHeaders[streamId] = true
				}
				gotHeaders[streamId] = true
			}
			headersCount[streamId]++
		case *http2.DataFrame:
			// log.Println("Data: ", len(f.Data()), string(f.Data()))
			if len(string(f.Data())) > 0 {
				payload = base64.StdEncoding.EncodeToString(f.Data())
				gotPayload[streamId] = true
				// fmt.Println("payload", payload)
			}
		}
		if gotHeaders[streamId] && gotPayload[streamId] {

			if gotGrpcHeaders[streamId] && headersCount[streamId] == 1 {
				continue
			}

			if _, exists := streamResponseMap[streamId]; !exists {
				streamResponseMap[streamId] = []http2ReqResp{}
			}
			streamResponseMap[streamId] = append(streamResponseMap[streamId], http2ReqResp{
				headersMap: headersMap,
				payload:    payload,
			})
			gotPayload[streamId] = false
			gotHeaders[streamId] = false
			gotGrpcHeaders[streamId] = false
			headersCount[streamId] = 0
		}
	}

	for streamId, http2Req := range streamRequestMap {
		http2Resp := streamResponseMap[streamId]
		if len(http2Resp) != len(http2Req) {
			continue
		}
		for req := range http2Req {

			http2Request := http2Req[req]
			http2Response := http2Resp[req]

			value := make(map[string]string)

			if path, exists := http2Request.headersMap[":path"]; exists {
				value["path"] = path
				delete(http2Request.headersMap, ":path")
			}
			if method, exists := http2Request.headersMap[":method"]; exists {
				value["method"] = method
				delete(http2Request.headersMap, ":method")
			}
			if scheme, exists := http2Request.headersMap[":scheme"]; exists {
				value["scheme"] = scheme
				delete(http2Request.headersMap, ":scheme")
			}
			if status, exists := http2Response.headersMap[":status"]; exists {
				value["statusCode"] = status
				delete(http2Response.headersMap, ":status")
			}
			value["requestPayload"] = http2Request.payload
			value["responsePayload"] = http2Request.payload

			if len(http2Request.headersMap) > 0 {
				requestHeaders, _ := json.Marshal(http2Request.headersMap)
				value["requestHeaders"] = string(requestHeaders)
			}
			if len(http2Response.headersMap) > 0 {
				responseHeader, _ := json.Marshal(http2Response.headersMap)
				value["responseHeader"] = string(responseHeader)
			}

			value["ip"] = bd.key.net.Src().String()
			value["akto_account_id"] = fmt.Sprint(1000000)
			value["akto_vxlan_id"] = fmt.Sprint(bd.vxlanID)
			value["time"] = fmt.Sprint(time.Now().Unix())
			value["is_pending"] = fmt.Sprint(isPending)
			out, _ := json.Marshal(value)
			isHttp2Req = true

			if printCounter > 0 {
				printCounter--
				log.Println("req-resp.String()", string(out))
			}
			// go gomiddleware.Produce(kafkaWriter, ctx, string(out))
		}

	}

	if isHttp2Req {
		return true, nil
	}
	return false, errors.New("not an http2 request")
}

func tryParseAsNormalHttpRequest(bd *bidi, isPending bool) {

	reader := bufio.NewReader(bytes.NewReader(bd.b.bytes))
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
		body, err := ioutil.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			log.Println("HTTP-request-body", "Got body err: %s\n", err)
			return
		}

		requests = append(requests, *req)
		requestsContent = append(requestsContent, string(body))
		// log.Println("req.URL.String()", i, req.URL.String(), string(body), len(bd.a.bytes))
		i++
	}

	reader = bufio.NewReader(bytes.NewReader(bd.b.bytes))
	i = 0
	log.Println("len(req)", len(requests))
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
			"responsePayload": string(body),
			"ip":              bd.key.net.Src().String(),
			"time":            fmt.Sprint(time.Now().Unix()),
			"statusCode":      fmt.Sprint(resp.StatusCode),
			"type":            string(req.Proto),
			"status":          resp.Status,
			"akto_account_id": fmt.Sprint(1000000),
			"akto_vxlan_id":   fmt.Sprint(bd.vxlanID),
			"is_pending":      fmt.Sprint(isPending),
		}

		out, _ := json.Marshal(value)
		ctx := context.Background()

		if printCounter > 0 {
			printCounter--
			log.Println("req-resp.String()", string(out))
		}
		go gomiddleware.Produce(kafkaWriter, ctx, string(out))
		i++
	}
}

func tryReadFromBD(bd *bidi, isPending bool) {
	_, err := tryParseAsHttp2Request(bd, isPending)
	if err != nil {
		tryParseAsNormalHttpRequest(bd, isPending)
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

// func flushAll() {
// 	for _, v := range assemblerMap {
// 		log.Println("TIME.SECOND:", time.Second)
// 		v.FlushOlderThan(time.Now().Add(time.Second * -500))
// 		//log.Println("num flushed/closed:", r, k)
// 		//log.Println("streams before closing: ", len(factoryMap[k].bidiMap))
// 		//factoryMap[k].collectOldStreams()
// 		//log.Println("streams after closing: ", len(factoryMap[k].bidiMap))
// 	}
// }

func createAndGetAssembler(vxlanID int) *tcpassembly.Assembler {

	_assembler := assemblerMap[vxlanID]
	if _assembler == nil {
		log.Println("creating assembler for vxlanID=", vxlanID)
		// Set up assembly
		streamFactory := &myFactory{bidiMap: make(map[key]*bidi), vxlanID: vxlanID}
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

var kafkaWriter *kafka.Writer

func run(handle *pcap.Handle, apiCollectionId int) {
	kafka_url := os.Getenv("AKTO_KAFKA_BROKER_URL")
	kafka_batch_size, e := strconv.Atoi(os.Getenv("AKTO_TRAFFIC_BATCH_SIZE"))
	if e != nil {
		log.Printf("AKTO_TRAFFIC_BATCH_SIZE should be valid integer")
		return
	}

	kafka_batch_time_secs, e := strconv.Atoi(os.Getenv("AKTO_TRAFFIC_BATCH_TIME_SECS"))
	if e != nil {
		log.Printf("AKTO_TRAFFIC_BATCH_TIME_SECS should be valid integer")
		return
	}
	kafka_batch_time_secs_duration := time.Duration(kafka_batch_time_secs)

	kafkaWriter = gomiddleware.GetKafkaWriter(kafka_url, "akto.api.logs", kafka_batch_size, kafka_batch_time_secs_duration*time.Second)
	// Set up pcap packet capture
	// handle, err = pcap.OpenOffline("/Users/ankushjain/Downloads/dump2.pcap")
	// if err != nil {  }

	if err := handle.SetBPFFilter("udp and port 4789"); err != nil { // optional
		log.Fatal(err)
	} else {
		log.Println("reading in packets")
		// Read in packets, pass to assembler.
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			// pb, ok := packet.(gopacket.PacketBuilder)
			// if !ok {
			// 	panic("Not a PacketBuilder")
			// }
			// ipv4 := &layers.IPv4{}
			// ipv4.DecodeFromBytes(packet.Data()[20:], pb)
			// pb.AddLayer(ipv4)
			// pb.SetNetworkLayer(ipv4)
			// pb.NextDecoder(ipv4.NextLayerType())

			// 			arr := packet1.Data()
			// 			if len(arr) <= 20 {
			// 				continue
			// 			}
			//
			// 			packet := gopacket.NewPacket(arr[20:], layers.LayerTypeIPv4, gopacket.Default)
			//
			innerPacket := packet
			vxlanID := apiCollectionId
			if apiCollectionId <= 0 {

				// log.Println("packet.NetworkLayer().NetworkFlow().Des()", packet.NetworkLayer().NetworkFlow().Dst())
				// log.Println("packet.TransportLayer().LayerType()", packet.TransportLayer().LayerType())
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
				tcp := innerPacket.TransportLayer().(*layers.TCP)
				assembler := createAndGetAssembler(vxlanID)
				assembler.AssembleWithTimestamp(innerPacket.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
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
		run(handle, apiCollectionId)
	}
}

func main() {
	if handle, err := pcap.OpenLive("eth0", 33554392, true, pcap.BlockForever); err != nil {
		log.Fatal(err)
	} else {
		run(handle, -1)
	}
}
