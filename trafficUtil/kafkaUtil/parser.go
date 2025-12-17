package kafkaUtil

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/apiProcessor"
	trafficpb "github.com/akto-api-security/mirroring-api-logging/trafficUtil/protobuf/traffic_payload"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/trafficMetrics"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

var (
	goodRequests               = 0
	badRequests                = 0
	debugMode                  = false
	outputBandwidthLimitPerMin = -1
	currentBandwidthProcessed  = 0
	lastSampleUpdate           = time.Now().Unix()
	sampleMutex                = sync.RWMutex{}
	methodsMap                 = map[string]bool{
		"GET":     true,
		"HEAD":    true,
		"POST":    true,
		"PUT":     true,
		"DELETE":  true,
		"CONNECT": true,
		"OPTIONS": true,
		"TRACE":   true,
		"TRACK":   true,
		"PATCH":   true}
	DebugStrings = []string{}

	EventChanBuffSize = 100000
)

const ONE_MINUTE = 60

const (
	protocolhttp2 = "http2"
)

func init() {
	utils.InitVar("DEBUG_MODE", &debugMode)
	utils.InitVar("OUTPUT_BANDWIDTH_LIMIT", &outputBandwidthLimitPerMin)
	utils.InitVar("EVENT_CHAN_BUFF_SIZE", &EventChanBuffSize)
	// convert MB to B
	if outputBandwidthLimitPerMin != -1 {
		outputBandwidthLimitPerMin = outputBandwidthLimitPerMin * 1024 * 1024
	}
	debugStringsEnv := ""
	utils.InitVar("DEBUG_URLS", &debugStringsEnv)
	if len(debugStringsEnv) > 0 {
		DebugStrings = strings.Split(debugStringsEnv, ",")
	}
	slog.Info("debugStrings", "DebugStrings", DebugStrings)

	// Start ticker to read debug URLs from file every 30 seconds
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			UpdateDebugStringsFromFile()
			<-ticker.C
		}
	}()
}

// Reads /ebpf/debug-urls.txt and updates DebugStrings with any new URLs found in the file (one per line)
func UpdateDebugStringsFromFile() {
	filePath := "/ebpf/debug-urls.txt"
	f, err := os.Open(filePath)
	if err != nil {
		// File may not exist, that's fine
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	fileUrls := []string{}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			fileUrls = append(fileUrls, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return
	}

	if len(fileUrls) > 0 {
		// Merge with env DebugStrings, avoid duplicates
		urlSet := make(map[string]struct{})
		for _, u := range DebugStrings {
			urlSet[u] = struct{}{}
		}
		newUrls := []string{}
		for _, u := range fileUrls {
			if _, exists := urlSet[u]; !exists {
				newUrls = append(newUrls, u)
			}
			urlSet[u] = struct{}{}
		}
		if len(newUrls) > 0 {
			merged := make([]string, 0, len(urlSet))
			for u := range urlSet {
				merged = append(merged, u)
			}
			DebugStrings = merged
			utils.PrintLogDebug("New debugStrings found in file", "newUrls", newUrls, "DebugStrings", DebugStrings)
		}
	}
}

func checkDebugUrlAndPrint(url string, host string, message string) {
	// url or host. [array string]
	if len(DebugStrings) > 0 {
		for _, debugString := range DebugStrings {
			if strings.Contains(url, debugString) {
				ctx := context.Background()
				logMsg := fmt.Sprintf("%s : %s", message, url)
				utils.PrintLogDebug(logMsg)
				go ProduceLogs(ctx, logMsg, LogTypeInfo)
				break
			} else if strings.Contains(host, debugString) {
				ctx := context.Background()
				logMsg := fmt.Sprintf("%s : %s", message, host)
				utils.PrintLogDebug(logMsg)
				go ProduceLogs(ctx, logMsg, LogTypeInfo)
				break
			}
		}
	}
}

func checkAndUpdateBandwidthProcessed(sampleSize int) bool {

	if outputBandwidthLimitPerMin == -1 {
		return false
	}
	sampleMutex.Lock()
	defer sampleMutex.Unlock()
	now := time.Now().Unix()
	if int(now-lastSampleUpdate) > ONE_MINUTE {
		lastSampleUpdate = now
		currentBandwidthProcessed = 0
		slog.Debug("reset limit", "now", now, "lastSampleUpdate", lastSampleUpdate, "currentBandwidthProcessed", currentBandwidthProcessed)
	}
	skip := currentBandwidthProcessed > outputBandwidthLimitPerMin
	if !skip {
		currentBandwidthProcessed += sampleSize
		skip = currentBandwidthProcessed > outputBandwidthLimitPerMin
		if skip {
			slog.Debug("Skipping sending to akto", "now", now, "lastSampleUpdate", lastSampleUpdate, "currentBandwidthProcessed", currentBandwidthProcessed)
		}
	}
	return skip
}

func IsValidMethod(method string) bool {
	_, ok := methodsMap[strings.ToUpper(method)]
	return ok
}

func ParseAndProduce(receiveBuffer []byte, sentBuffer []byte, sourceIp string, destIp string, vxlanID int, isPending bool,
	trafficSource string, isComplete bool, direction int, idfd uint64, fd uint32, daemonsetIdentifier string, hostName string, protocol string) {

	if checkAndUpdateBandwidthProcessed(0) {
		return
	}
	// Route to HTTP/2 parser if protocol is detected as HTTP/2
	if protocol == protocolhttp2 {
		slog.Debug("Routing to HTTP/2 parser", "sourceIp", sourceIp, "destIp", destIp, "protocol", protocol)
		ParseHTTP2AndProduce(receiveBuffer, sentBuffer, sourceIp, destIp, vxlanID, isPending, trafficSource, isComplete, direction, idfd, fd, daemonsetIdentifier, hostName)
		return
	}

	shouldPrint := debugMode && strings.Contains(string(receiveBuffer), "x-debug-token")
	if shouldPrint {
		slog.Debug("ParseAndProduce", "receiveBuffer", string(receiveBuffer), "sentBuffer", string(sentBuffer), "protocol", protocol)
	}

	reader := bufio.NewReader(bytes.NewReader(receiveBuffer))
	i := 0
	requests := []http.Request{}
	requestsContent := []string{}

	for {
		req, err := http.ReadRequest(reader)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		} else if err != nil {
			utils.PrintLog(fmt.Sprintf("HTTP-request error: %s \n", err))
			return
		}
		body, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			utils.PrintLog(fmt.Sprintf("Got body err: %s\n", err))
			return
		}

		requests = append(requests, *req)
		requestsContent = append(requestsContent, string(body))
		i++
	}

	if shouldPrint {
		slog.Debug("ParseAndProduce", "count", i)
	}
	if len(requests) == 0 {
		return
	}

	reader = bufio.NewReader(bytes.NewReader(sentBuffer))
	i = 0

	responses := []http.Response{}
	responsesContent := []string{}

	for {

		resp, err := http.ReadResponse(reader, nil)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		} else if err != nil {
			utils.PrintLog(fmt.Sprintf("HTTP-Response error: %s\n", err))
			return
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			utils.PrintLog(fmt.Sprintf("Got err reading resp body: %s\n", err))
			return
		}
		encoding := resp.Header["Content-Encoding"]
		var r io.Reader
		r = bytes.NewBuffer(body)
		if len(encoding) > 0 && (encoding[0] == "gzip" || encoding[0] == "deflate") {
			r, err = gzip.NewReader(r)
			if err != nil {
				utils.PrintLog(fmt.Sprintf("HTTP-gunzip "+"Failed to gzip decode: %s", err))
				return
			}
		}
		if err == nil {
			body, err = io.ReadAll(r)
			if err != nil {
				utils.PrintLog(fmt.Sprintf("Failed to read decompressed body: %s\n", err))
				return
			}
			if _, ok := r.(*gzip.Reader); ok {
				r.(*gzip.Reader).Close()
			}
		}

		responses = append(responses, *resp)
		responsesContent = append(responsesContent, string(body))

		i++
	}

	if shouldPrint {

		slog.Debug("ParseAndProduce", "count", i)
	}
	if len(requests) != len(responses) {
		if shouldPrint {
			slog.Debug("Len req-res mismatch", "lenRequests", len(requests), "lenResponses", len(responses), "lenReceiveBuffer", len(receiveBuffer), "lenSentBuffer", len(sentBuffer), "isComplete", isComplete)
		}
		if isComplete {
			return
		}
		correctLen := len(requests)
		if len(responses) < len(requests) {
			correctLen = len(responses)
		}

		responses = responses[:correctLen]
		requests = requests[:correctLen]
	}

	i = 0
	for {
		if len(requests) < i+1 {
			break
		}

		req := &requests[i]
		resp := &responses[i]

		if !IsValidMethod(req.Method) {
			continue
		}

		id := ""

		// build req headers for threat client
		reqHeader := make(map[string]*trafficpb.StringList)
		for name, values := range req.Header {
			// Loop over all values for the name.
			for _, value := range values {
				reqHeader[strings.ToLower(name)] = &trafficpb.StringList{
					Values: []string{value},
				}
			}
		}
		ip := GetSourceIp(reqHeader, sourceIp)

		reqHeader["host"] = &trafficpb.StringList{
			Values: []string{req.Host},
		}

		reqHeaderStr := make(map[string]string)
		for name, values := range req.Header {
			// Loop over all values for the name.
			for _, value := range values {
				if shouldPrint &&
					strings.EqualFold(name, "x-debug-token") {
					id = value
				}
				reqHeaderStr[name] = value
			}
		}

		reqHeaderStr["host"] = req.Host

		passes := utils.PassesFilter(trafficMetrics.FilterHeaderValueMap, reqHeaderStr)
		//printLog("Req header: " + mapToString(reqHeaderStr))
		//printLog(fmt.Sprintf("passes %t", passes))

		if !passes {
			i++
			continue
		}

		if utils.IgnoreIpTraffic && utils.CheckIfIp(req.Host) {
			i++
			continue
		}

		if utils.IgnoreCloudMetadataCalls && req.Host == "169.254.169.254" {
			i++
			continue
		}

		if utils.IgnoreEnvoyProxycalls && sourceIp == utils.EnvoyProxyIp && direction == utils.DirectionOutbound {
			slog.Debug("Ignoring outbound envoy proxy call", "sourceIp", sourceIp, "url", req.URL.String(), "host", req.Host)
			i++
			continue
		}

		var skipPacket = utils.FilterPacket(reqHeaderStr)

		if skipPacket {
			i++
			continue
		}

		// build resp headers for threat client
		respHeader := make(map[string]*trafficpb.StringList)
		for name, values := range resp.Header {
			// Loop over all values for the name.
			for _, value := range values {
				respHeader[strings.ToLower(name)] = &trafficpb.StringList{
					Values: []string{value},
				}
			}
		}

		// TODO: remove and use protobuf instead
		respHeaderStr := make(map[string]string)
		for name, values := range resp.Header {
			// Loop over all values for the name.
			for _, value := range values {
				respHeaderStr[name] = value
			}
		}

		url := req.URL.String()
		checkDebugUrlAndPrint(url, req.Host, "URL,host found in ParseAndProduce")

		// build kafka payload for threat client
		payload := &trafficpb.HttpResponseParam{
			Method:          req.Method,
			Path:            req.URL.String(),
			RequestHeaders:  reqHeader,
			ResponseHeaders: respHeader,
			RequestPayload:  requestsContent[i],
			ResponsePayload: responsesContent[i],
			Ip:              ip,
			Time:            int32(time.Now().Unix()),
			StatusCode:      int32(resp.StatusCode),
			Type:            string(req.Proto),
			Status:          resp.Status,
			AktoAccountId:   fmt.Sprint(1000000),
			AktoVxlanId:     fmt.Sprint(vxlanID),
			IsPending:       isPending,
			Source:          trafficSource,
		}

		reqHeaderString, _ := json.Marshal(reqHeaderStr)
		respHeaderString, _ := json.Marshal(respHeaderStr)

		// TODO: remove and use protobuf instead
		value := map[string]string{
			"path":            req.URL.String(),
			"requestHeaders":  string(reqHeaderString),
			"responseHeaders": string(respHeaderString),
			"method":          req.Method,
			"requestPayload":  requestsContent[i],
			"responsePayload": responsesContent[i],
			"ip":              sourceIp,
			"destIp":          destIp,
			"time":            fmt.Sprint(time.Now().Unix()),
			"statusCode":      fmt.Sprint(resp.StatusCode),
			"type":            string(req.Proto),
			"status":          resp.Status,
			"akto_account_id": fmt.Sprint(1000000),
			"akto_vxlan_id":   fmt.Sprint(vxlanID),
			"is_pending":      fmt.Sprint(isPending),
			"source":          trafficSource,
			"direction":       fmt.Sprint(direction),
			"process_id":      fmt.Sprint(idfd >> 32),
			"socket_id":       fmt.Sprint(fd),
			"daemonset_id":    fmt.Sprint(daemonsetIdentifier),
			"enable_graph":    fmt.Sprint(utils.EnableGraph),
		}

		// Process id was captured from the eBPF program using bpf_get_current_pid_tgid()
		// Shifting by 32 gives us the process id on host machine.
		var pid = idfd >> 32
		log := fmt.Sprintf("pod direction log: direction=%v, host=%v, path=%v, sourceIp=%v, destIp=%v, socketId=%v, processId=%v, hostName=%v",
			direction,
			reqHeaderStr["host"],
			value["path"],
			sourceIp,
			destIp,
			value["socket_id"],
			pid,
			hostName,
		)
		checkDebugUrlAndPrint(url, req.Host, log)

		if PodInformerInstance != nil && direction == utils.DirectionInbound {

			if hostName == "" {
				checkDebugUrlAndPrint(url, req.Host, "Failed to resolve pod name, hostName is empty for processId "+fmt.Sprint(pid))
				slog.Error("Failed to resolve pod name, hostName is empty for ", "processId", pid, "hostName", hostName)
			} else {
				podLabels, err := PodInformerInstance.ResolvePodLabels(hostName, url, req.Host)
				if err != nil {
					slog.Error("Failed to resolve pod labels", "hostName", hostName, "error", err)
					checkDebugUrlAndPrint(url, req.Host, "Error resolving pod labels "+hostName)
				} else {
					value["tag"] = podLabels
					checkDebugUrlAndPrint(url, req.Host, "Pod labels found in ParseAndProduce, podLabels found "+fmt.Sprint(podLabels)+" for hostName "+hostName)
					slog.Debug("Pod labels", "podName", hostName, "labels", podLabels)
				}
			}
		} else {
			checkDebugUrlAndPrint(url, req.Host, "Pod labels not resolved, PodInformerInstance is nil or direction is not inbound, direction: "+fmt.Sprint(direction))
		}

		out, _ := json.Marshal(value)
		ctx := context.Background()

		// calculating the size of outgoing bytes and requests (1) and saving it in outgoingCounterMap
		// this number is the closest (slightly higher) to the actual connection transfer bytes.
		outgoingBytes := len(out)

		if checkAndUpdateBandwidthProcessed(outgoingBytes) {
			return
		}

		hostString := reqHeaderStr["host"]
		if utils.CheckIfIpHost(hostString) {
			hostString = "ip-host"
		}
		oc := utils.GenerateOutgoingCounter(vxlanID, sourceIp, hostString)
		trafficMetrics.SubmitOutgoingTrafficMetrics(oc, outgoingBytes)

		if shouldPrint {
			if strings.Contains(responsesContent[i], id) {
				goodRequests++
			} else {
				slog.Debug("req-resp.String()", "out", string(out))
				badRequests++
			}

			if goodRequests%100 == 0 || badRequests%100 == 0 {
				slog.Debug("Good requests", "count", goodRequests, "badRequests", badRequests)
			}
		}

		if apiProcessor.CloudProcessorInstance != nil {
			apiProcessor.CloudProcessorInstance.Produce(value)

		} else {
			// Produce to kafka
			// TODO : remove and use protobuf instead
			go ProduceStr(ctx, string(out), url, req.Host)
			go Produce(ctx, payload)
		}

		i++
	}
}

type http2Stream struct {
	streamID         uint32
	requestHeaders   map[string]string
	requestBody      []byte
	responseHeaders  map[string]string
	responseBody     []byte
	method           string
	path             string
	statusCode       int
	status           string
	requestComplete  bool
	responseComplete bool
}

func ParseHTTP2AndProduce(receiveBuffer []byte, sentBuffer []byte, sourceIp string, destIp string, vxlanID int, isPending bool,
	trafficSource string, isComplete bool, direction int, idfd uint64, fd uint32, daemonsetIdentifier string, hostName string) {

	if checkAndUpdateBandwidthProcessed(0) {
		return
	}

	shouldPrint := debugMode && strings.Contains(string(receiveBuffer), "x-debug-token")
	if shouldPrint {
		slog.Debug("ParseHTTP2AndProduce", "receiveBufferLen", len(receiveBuffer), "sentBufferLen", len(sentBuffer))
	}

	http2Preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	if len(receiveBuffer) >= len(http2Preface) && bytes.Equal(receiveBuffer[:len(http2Preface)], http2Preface) {
		receiveBuffer = receiveBuffer[len(http2Preface):]
		slog.Debug("Skipped HTTP/2 connection preface")
	}
	if len(sentBuffer) >= len(http2Preface) && bytes.Equal(sentBuffer[:len(http2Preface)], sentBuffer) {
		sentBuffer = sentBuffer[len(http2Preface):]
	}

	streams := make(map[uint32]*http2Stream)

	parseHTTP2Frames(receiveBuffer, streams, true, shouldPrint)
	parseHTTP2Frames(sentBuffer, streams, false, shouldPrint)

	// Process complete request/response pairs
	for streamID, stream := range streams {
		if !stream.requestComplete || !stream.responseComplete {
			if shouldPrint {
				slog.Debug("Incomplete stream", "streamID", streamID, "requestComplete", stream.requestComplete, "responseComplete", stream.responseComplete)
			}
			// Skip incomplete streams unless connection is complete
			if !isComplete {
				continue
			}
		}

		reqHeader := make(map[string]*trafficpb.StringList)
		for name, value := range stream.requestHeaders {
			reqHeader[strings.ToLower(name)] = &trafficpb.StringList{
				Values: []string{value},
			}
		}

		ip := GetSourceIp(reqHeader, sourceIp)

		if stream.method != "" {
			reqHeader[":method"] = &trafficpb.StringList{Values: []string{stream.method}}
		}
		if stream.path != "" {
			reqHeader[":path"] = &trafficpb.StringList{Values: []string{stream.path}}
		}

		host := stream.requestHeaders[":authority"]
		if host == "" {
			host = stream.requestHeaders["host"]
		}
		if host != "" {
			reqHeader["host"] = &trafficpb.StringList{Values: []string{host}}
		}

		respHeader := make(map[string]*trafficpb.StringList)
		for name, value := range stream.responseHeaders {
			respHeader[strings.ToLower(name)] = &trafficpb.StringList{
				Values: []string{value},
			}
		}

		reqHeaderStr := make(map[string]string)
		for name, value := range stream.requestHeaders {
			reqHeaderStr[name] = value
		}
		if host != "" {
			reqHeaderStr["host"] = host
		}

		passes := utils.PassesFilter(trafficMetrics.FilterHeaderValueMap, reqHeaderStr)
		if !passes {
			continue
		}

		if utils.IgnoreIpTraffic && utils.CheckIfIp(host) {
			continue
		}

		if utils.IgnoreCloudMetadataCalls && host == "169.254.169.254" {
			continue
		}

		if utils.IgnoreEnvoyProxycalls && sourceIp == utils.EnvoyProxyIp && direction == utils.DirectionOutbound {
			slog.Debug("Ignoring outbound envoy proxy call", "sourceIp", sourceIp, "path", stream.path, "host", host)
			continue
		}

		var skipPacket = utils.FilterPacket(reqHeaderStr)
		if skipPacket {
			continue
		}

		url := stream.path
		checkDebugUrlAndPrint(url, host, "HTTP/2 URL,host found in ParseHTTP2AndProduce")

		payload := &trafficpb.HttpResponseParam{
			Method:          stream.method,
			Path:            stream.path,
			RequestHeaders:  reqHeader,
			ResponseHeaders: respHeader,
			RequestPayload:  string(stream.requestBody),
			ResponsePayload: string(stream.responseBody),
			Ip:              ip,
			Time:            int32(time.Now().Unix()),
			StatusCode:      int32(stream.statusCode),
			Type:            "HTTP/2.0",
			Status:          stream.status,
			AktoAccountId:   fmt.Sprint(1000000),
			AktoVxlanId:     fmt.Sprint(vxlanID),
			IsPending:       isPending,
			Source:          trafficSource,
		}

		respHeaderStr := make(map[string]string)
		for name, value := range stream.responseHeaders {
			respHeaderStr[name] = value
		}

		reqHeaderString, _ := json.Marshal(reqHeaderStr)
		respHeaderString, _ := json.Marshal(respHeaderStr)

		value := map[string]string{
			"path":            stream.path,
			"requestHeaders":  string(reqHeaderString),
			"responseHeaders": string(respHeaderString),
			"method":          stream.method,
			"requestPayload":  string(stream.requestBody),
			"responsePayload": string(stream.responseBody),
			"ip":              sourceIp,
			"destIp":          destIp,
			"time":            fmt.Sprint(time.Now().Unix()),
			"statusCode":      fmt.Sprint(stream.statusCode),
			"type":            "HTTP/2.0",
			"status":          stream.status,
			"akto_account_id": fmt.Sprint(1000000),
			"akto_vxlan_id":   fmt.Sprint(vxlanID),
			"is_pending":      fmt.Sprint(isPending),
			"source":          trafficSource,
			"direction":       fmt.Sprint(direction),
			"process_id":      fmt.Sprint(idfd >> 32),
			"socket_id":       fmt.Sprint(fd),
			"daemonset_id":    fmt.Sprint(daemonsetIdentifier),
			"enable_graph":    fmt.Sprint(utils.EnableGraph),
		}

		var pid = idfd >> 32
		log := fmt.Sprintf("HTTP/2 pod direction log: direction=%v, host=%v, path=%v, sourceIp=%v, destIp=%v, socketId=%v, processId=%v, hostName=%v, streamId=%v",
			direction, host, stream.path, sourceIp, destIp, fd, pid, hostName, streamID)
		checkDebugUrlAndPrint(url, host, log)

		if PodInformerInstance != nil && direction == utils.DirectionInbound {
			if hostName == "" {
				checkDebugUrlAndPrint(url, host, "Failed to resolve pod name, hostName is empty for processId "+fmt.Sprint(pid))
				slog.Error("Failed to resolve pod name, hostName is empty for ", "processId", pid, "hostName", hostName)
			} else {
				podLabels, err := PodInformerInstance.ResolvePodLabels(hostName, url, host)
				if err != nil {
					slog.Error("Failed to resolve pod labels", "hostName", hostName, "error", err)
					checkDebugUrlAndPrint(url, host, "Error resolving pod labels "+hostName)
				} else {
					value["tag"] = podLabels
					checkDebugUrlAndPrint(url, host, "Pod labels found in ParseHTTP2AndProduce, podLabels found "+fmt.Sprint(podLabels)+" for hostName "+hostName)
					slog.Debug("Pod labels", "podName", hostName, "labels", podLabels)
				}
			}
		} else {
			checkDebugUrlAndPrint(url, host, "Pod labels not resolved, PodInformerInstance is nil or direction is not inbound, direction: "+fmt.Sprint(direction))
		}

		out, _ := json.Marshal(value)
		ctx := context.Background()

		outgoingBytes := len(out)
		if checkAndUpdateBandwidthProcessed(outgoingBytes) {
			return
		}

		hostString := host
		if utils.CheckIfIpHost(hostString) {
			hostString = "ip-host"
		}
		oc := utils.GenerateOutgoingCounter(vxlanID, sourceIp, hostString)
		trafficMetrics.SubmitOutgoingTrafficMetrics(oc, outgoingBytes)

		if apiProcessor.CloudProcessorInstance != nil {
			apiProcessor.CloudProcessorInstance.Produce(value)
		} else {
			go ProduceStr(ctx, string(out), url, host)
			go Produce(ctx, payload)
		}
	}
}

func parseHTTP2Frames(buffer []byte, streams map[uint32]*http2Stream, isRequest bool, shouldPrint bool) {
	framer := http2.NewFramer(nil, bytes.NewReader(buffer))
	framer.SetMaxReadFrameSize(1 << 20) // 1MB max frame size

	decoder := hpack.NewDecoder(4096, nil)

	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			if err != io.EOF {
				if shouldPrint {
					slog.Debug("Error reading HTTP/2 frame", "error", err, "isRequest", isRequest)
				}
			}
			break
		}

		streamID := frame.Header().StreamID

		// Skip stream 0 (connection-level frames like SETTINGS, WINDOW_UPDATE, PING)
		if streamID == 0 {
			continue
		}

		// Get or create stream
		stream, exists := streams[streamID]
		if !exists {
			stream = &http2Stream{
				streamID:        streamID,
				requestHeaders:  make(map[string]string),
				responseHeaders: make(map[string]string),
			}
			streams[streamID] = stream
		}

		switch f := frame.(type) {
		case *http2.HeadersFrame:
			headerBlock := f.HeaderBlockFragment()
			headers, err := decoder.DecodeFull(headerBlock)
			if err != nil {
				slog.Error("Failed to decode HPACK headers", "error", err, "streamID", streamID)
				continue
			}

			if isRequest {
				for _, hf := range headers {
					stream.requestHeaders[hf.Name] = hf.Value
					// Extract pseudo-headers
					if hf.Name == ":method" {
						stream.method = hf.Value
					} else if hf.Name == ":path" {
						stream.path = hf.Value
					}
				}
				if f.StreamEnded() {
					stream.requestComplete = true
				}
			} else {
				for _, hf := range headers {
					stream.responseHeaders[hf.Name] = hf.Value
					// Extract status code
					if hf.Name == ":status" {
						stream.status = hf.Value
						fmt.Sscanf(hf.Value, "%d", &stream.statusCode)
					}
				}
				if f.StreamEnded() {
					stream.responseComplete = true
				}
			}

		case *http2.DataFrame:
			data := f.Data()
			if isRequest {
				stream.requestBody = append(stream.requestBody, data...)
				if f.StreamEnded() {
					stream.requestComplete = true
				}
			} else {
				stream.responseBody = append(stream.responseBody, data...)
				if f.StreamEnded() {
					stream.responseComplete = true
				}
			}

		case *http2.RSTStreamFrame:
			// Stream was reset
			if shouldPrint {
				slog.Debug("Stream reset", "streamID", streamID, "errorCode", f.ErrCode)
			}
		}
	}
}
