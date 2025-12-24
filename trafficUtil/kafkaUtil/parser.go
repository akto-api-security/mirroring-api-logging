package kafkaUtil

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
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
	protocolhttp2 = "HTTP2"
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

		// build req headers for threat client (no longer needed, keeping for x-debug-token detection)
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

		// Apply common filters
		if !applyFiltersAndChecks(reqHeaderStr, req.Host, sourceIp, direction) {
			i++
			continue
		}

		// Build response headers map
		respHeaderStr := make(map[string]string)
		for name, values := range resp.Header {
			for _, value := range values {
				respHeaderStr[name] = value
			}
		}

		// Use common production logic
		params := trafficParams{
			method:          req.Method,
			path:            req.URL.String(),
			requestHeaders:  reqHeaderStr,
			responseHeaders: respHeaderStr,
			requestPayload:  requestsContent[i],
			responsePayload: responsesContent[i],
			statusCode:      resp.StatusCode,
			status:          resp.Status,
			protocolType:    string(req.Proto),
			sourceIp:        sourceIp,
			destIp:          destIp,
			vxlanID:         vxlanID,
			isPending:       isPending,
			trafficSource:   trafficSource,
			direction:       direction,
			idfd:            idfd,
			fd:              fd,
			daemonsetID:     daemonsetIdentifier,
			hostName:        hostName,
		}

		if shouldPrint {
			if strings.Contains(responsesContent[i], id) {
				goodRequests++
			} else {
				slog.Debug("req-resp mismatch", "path", req.URL.String())
				badRequests++
			}

			if goodRequests%100 == 0 || badRequests%100 == 0 {
				slog.Debug("Good requests", "count", goodRequests, "badRequests", badRequests)
			}
		}

		produceTrafficData(params)

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
	isGRPC           bool
	grpcStatus       string
	grpcMessage      string
}

type trafficParams struct {
	method          string
	path            string
	requestHeaders  map[string]string
	responseHeaders map[string]string
	requestPayload  string
	responsePayload string
	statusCode      int
	status          string
	protocolType    string
	sourceIp        string
	destIp          string
	vxlanID         int
	isPending       bool
	trafficSource   string
	direction       int
	idfd            uint64
	fd              uint32
	daemonsetID     string
	hostName        string
}

// applyFiltersAndChecks performs common filtering logic for both HTTP/1 and HTTP/2
func applyFiltersAndChecks(reqHeaderStr map[string]string, host string, sourceIp string, direction int) bool {
	passes := utils.PassesFilter(trafficMetrics.FilterHeaderValueMap, reqHeaderStr)
	if !passes {
		return false
	}

	if utils.IgnoreIpTraffic && utils.CheckIfIp(host) {
		return false
	}

	if utils.IgnoreCloudMetadataCalls && host == "169.254.169.254" {
		return false
	}

	if utils.IgnoreEnvoyProxycalls && sourceIp == utils.EnvoyProxyIp && direction == utils.DirectionOutbound {
		slog.Debug("Ignoring outbound envoy proxy call", "sourceIp", sourceIp, "host", host)
		return false
	}

	return !utils.FilterPacket(reqHeaderStr)
}

func produceTrafficData(params trafficParams) {

	reqHeader := make(map[string]*trafficpb.StringList)
	for name, value := range params.requestHeaders {
		reqHeader[strings.ToLower(name)] = &trafficpb.StringList{
			Values: []string{value},
		}
	}

	// Add HTTP/2 pseudo-headers if present
	if params.method != "" {
		reqHeader[":method"] = &trafficpb.StringList{Values: []string{params.method}}
	}
	if params.path != "" {
		reqHeader[":path"] = &trafficpb.StringList{Values: []string{params.path}}
	}

	ip := GetSourceIp(reqHeader, params.sourceIp)

	respHeader := make(map[string]*trafficpb.StringList)
	for name, value := range params.responseHeaders {
		respHeader[strings.ToLower(name)] = &trafficpb.StringList{
			Values: []string{value},
		}
	}

	host := params.requestHeaders["host"]
	url := params.path
	checkDebugUrlAndPrint(url, host, fmt.Sprintf("%s URL,host found", params.protocolType))

	payload := &trafficpb.HttpResponseParam{
		Method:          params.method,
		Path:            params.path,
		RequestHeaders:  reqHeader,
		ResponseHeaders: respHeader,
		RequestPayload:  params.requestPayload,
		ResponsePayload: params.responsePayload,
		Ip:              ip,
		Time:            int32(time.Now().Unix()),
		StatusCode:      int32(params.statusCode),
		Type:            params.protocolType,
		Status:          params.status,
		AktoAccountId:   fmt.Sprint(1000000),
		AktoVxlanId:     fmt.Sprint(params.vxlanID),
		IsPending:       params.isPending,
		Source:          params.trafficSource,
	}

	// Build JSON value map
	reqHeaderString, _ := json.Marshal(params.requestHeaders)
	respHeaderString, _ := json.Marshal(params.responseHeaders)

	// TODO: remove and use protobuf instead
	value := map[string]string{
		"path":            params.path,
		"requestHeaders":  string(reqHeaderString),
		"responseHeaders": string(respHeaderString),
		"method":          params.method,
		"requestPayload":  params.requestPayload,
		"responsePayload": params.responsePayload,
		"ip":              params.sourceIp,
		"destIp":          params.destIp,
		"time":            fmt.Sprint(time.Now().Unix()),
		"statusCode":      fmt.Sprint(params.statusCode),
		"type":            params.protocolType,
		"status":          params.status,
		"akto_account_id": fmt.Sprint(1000000),
		"akto_vxlan_id":   fmt.Sprint(params.vxlanID),
		"is_pending":      fmt.Sprint(params.isPending),
		"source":          params.trafficSource,
		"direction":       fmt.Sprint(params.direction),
		"process_id":      fmt.Sprint(params.idfd >> 32),
		"socket_id":       fmt.Sprint(params.fd),
		"daemonset_id":    params.daemonsetID,
		"enable_graph":    fmt.Sprint(utils.EnableGraph),
	}

	var pid = params.idfd >> 32
	log := fmt.Sprintf("%s pod direction log: direction=%v, host=%v, path=%v, sourceIp=%v, destIp=%v, socketId=%v, processId=%v, hostName=%v",
		params.protocolType, params.direction, host, params.path, params.sourceIp, params.destIp, params.fd, pid, params.hostName)
	checkDebugUrlAndPrint(url, host, log)

	// Resolve pod labels if applicable
	if PodInformerInstance != nil && params.direction == utils.DirectionInbound {
		if params.hostName == "" {
			checkDebugUrlAndPrint(url, host, "Failed to resolve pod name, hostName is empty for processId "+fmt.Sprint(pid))
			slog.Error("Failed to resolve pod name, hostName is empty for ", "processId", pid, "hostName", params.hostName)
		} else {
			podLabels, err := PodInformerInstance.ResolvePodLabels(params.hostName, url, host)
			if err != nil {
				slog.Error("Failed to resolve pod labels", "hostName", params.hostName, "error", err)
				checkDebugUrlAndPrint(url, host, "Error resolving pod labels "+params.hostName)
			} else {
				value["tag"] = podLabels
				checkDebugUrlAndPrint(url, host, fmt.Sprintf("Pod labels found in %s, podLabels found %v for hostName %s", params.protocolType, podLabels, params.hostName))
				slog.Debug("Pod labels", "podName", params.hostName, "labels", podLabels)
			}
		}
	} else {
		checkDebugUrlAndPrint(url, host, fmt.Sprintf("Pod labels not resolved, PodInformerInstance is nil or direction is not inbound, direction: %d", params.direction))
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
	oc := utils.GenerateOutgoingCounter(params.vxlanID, params.sourceIp, hostString)
	trafficMetrics.SubmitOutgoingTrafficMetrics(oc, outgoingBytes)

	if apiProcessor.CloudProcessorInstance != nil {
		apiProcessor.CloudProcessorInstance.Produce(value)
	} else {
		go ProduceStr(ctx, string(out), url, host)
		go Produce(ctx, payload)
	}
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
			// Skip incomplete streams
			continue
		}

		// Extract host for filtering
		host := stream.requestHeaders[":authority"]
		if host == "" {
			host = stream.requestHeaders["host"]
		}

		reqHeaderStr := make(map[string]string)
		for name, value := range stream.requestHeaders {
			reqHeaderStr[name] = value
		}
		if host != "" {
			reqHeaderStr["host"] = host
		}

		// Apply common filters
		if !applyFiltersAndChecks(reqHeaderStr, host, sourceIp, direction) {
			continue
		}

		respHeaderStr := make(map[string]string)
		for name, value := range stream.responseHeaders {
			respHeaderStr[name] = value
		}

		protocolType := "HTTP/2.0"
		if stream.isGRPC {
			protocolType = "gRPC"
		}

		// Use common production logic
		params := trafficParams{
			method:          stream.method,
			path:            stream.path,
			requestHeaders:  reqHeaderStr,
			responseHeaders: respHeaderStr,
			requestPayload:  string(stream.requestBody),
			responsePayload: string(stream.responseBody),
			statusCode:      stream.statusCode,
			status:          stream.status,
			protocolType:    protocolType,
			sourceIp:        sourceIp,
			destIp:          destIp,
			vxlanID:         vxlanID,
			isPending:       isPending,
			trafficSource:   trafficSource,
			direction:       direction,
			idfd:            idfd,
			fd:              fd,
			daemonsetID:     daemonsetIdentifier,
			hostName:        hostName,
		}

		produceTrafficData(params)
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
					if hf.Name == "content-type" && strings.HasPrefix(hf.Value, "application/grpc") {
						stream.isGRPC = true
					}
					// Extract pseudo-headers
					switch hf.Name {
					case ":method":
						stream.method = hf.Value
					case ":path":
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
					switch hf.Name {
					case ":status":
						stream.status = hf.Value
						fmt.Sscanf(hf.Value, "%d", &stream.statusCode)
					case "grpc-status":
						stream.grpcStatus = hf.Value
					case "grpc-message":
						stream.grpcMessage = hf.Value
					}
				}
				if f.StreamEnded() {
					stream.responseComplete = true
				}
			}

		case *http2.DataFrame:
			data := f.Data()
			if isRequest {
				if stream.isGRPC {
					parsedData := parseGRPCFrames(data)
					stream.requestBody = append(stream.requestBody, parsedData...)
				} else {
					stream.requestBody = append(stream.requestBody, data...)
				}
				if f.StreamEnded() {
					stream.requestComplete = true
				}
			} else {
				if stream.isGRPC {
					parsedData := parseGRPCFrames(data)
					stream.responseBody = append(stream.responseBody, parsedData...)
				} else {
					stream.responseBody = append(stream.responseBody, data...)
				}
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

func parseGRPCFrames(data []byte) []byte {
	var finalData []byte
	offset := 0

	for offset < len(data) {
		// Need atleast 5 bytes for gRPC
		if offset+5 > len(data) {
			break
		}
		compressed := data[offset]
		messageLength := binary.BigEndian.Uint32(data[offset+1 : offset+5])

		if offset+5+int(messageLength) > len(data) {
			break
		}

		message := data[offset+5 : offset+5+int(messageLength)]

		if compressed == 1 {
			// Message is compressed
			// TODO, if required we can get the compression algo and uncompress it.
			slog.Debug("gRPC message is compressed", "length", messageLength)
		}

		finalData = append(finalData, message...)

		offset += (5 + int(messageLength))
	}

	return finalData
}
