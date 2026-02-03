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
)

// TrafficContext holds metadata about the captured traffic.
// This consolidates the many parameters previously passed to ParseAndProduce.
type TrafficContext struct {
	SourceIP            string
	DestIP              string
	VxlanID             int
	IsPending           bool
	TrafficSource       string
	IsComplete          bool
	Direction           int
	ProcessID           uint32 // Extracted from idfd >> 32
	SocketFD            uint32
	DaemonsetIdentifier string
	HostName            string
}

// ParsedTraffic holds the parsed HTTP requests and responses with their bodies.
type ParsedTraffic struct {
	Requests       []http.Request
	RequestBodies  []string
	Responses      []http.Response
	ResponseBodies []string
}

// HeaderSet holds HTTP headers in both protobuf and string map formats.
type HeaderSet struct {
	Protobuf  map[string]*trafficpb.StringList
	StringMap map[string]string
}

// ConvertedHeaders holds converted headers for both request and response.
type ConvertedHeaders struct {
	Request  HeaderSet
	Response HeaderSet
	DebugID  string // x-debug-token value if present
}

// PayloadInput contains the data needed to build traffic payloads.
type PayloadInput struct {
	Request      *http.Request
	Response     *http.Response
	Headers      ConvertedHeaders
	RequestBody  string
	ResponseBody string
	SourceIP     string // IP after GetSourceIp processing
	Context      TrafficContext
}

// buildProtobufPayload creates the protobuf payload for the threat client.
func buildProtobufPayload(input PayloadInput) *trafficpb.HttpResponseParam {
	return &trafficpb.HttpResponseParam{
		Method:          input.Request.Method,
		Path:            input.Request.URL.String(),
		RequestHeaders:  input.Headers.Request.Protobuf,
		ResponseHeaders: input.Headers.Response.Protobuf,
		RequestPayload:  input.RequestBody,
		ResponsePayload: input.ResponseBody,
		Ip:              input.SourceIP,
		DestIp:          input.Context.DestIP,
		Time:            int32(time.Now().Unix()),
		StatusCode:      int32(input.Response.StatusCode),
		Type:            string(input.Request.Proto),
		Status:          input.Response.Status,
		AktoAccountId:   fmt.Sprint(1000000),
		AktoVxlanId:     fmt.Sprint(input.Context.VxlanID),
		IsPending:       input.Context.IsPending,
		Source:          input.Context.TrafficSource,
	}
}

// buildJSONPayload creates the JSON map payload (legacy format, TODO: remove).
func buildJSONPayload(input PayloadInput) map[string]string {
	reqHeaderString, _ := json.Marshal(input.Headers.Request.StringMap)
	respHeaderString, _ := json.Marshal(input.Headers.Response.StringMap)

	return map[string]string{
		"path":            input.Request.URL.String(),
		"requestHeaders":  string(reqHeaderString),
		"responseHeaders": string(respHeaderString),
		"method":          input.Request.Method,
		"requestPayload":  input.RequestBody,
		"responsePayload": input.ResponseBody,
		"ip":              input.Context.SourceIP,
		"destIp":          input.Context.DestIP,
		"time":            fmt.Sprint(time.Now().Unix()),
		"statusCode":      fmt.Sprint(input.Response.StatusCode),
		"type":            string(input.Request.Proto),
		"status":          input.Response.Status,
		"akto_account_id": fmt.Sprint(1000000),
		"akto_vxlan_id":   fmt.Sprint(input.Context.VxlanID),
		"is_pending":      fmt.Sprint(input.Context.IsPending),
		"source":          input.Context.TrafficSource,
		"direction":       fmt.Sprint(input.Context.Direction),
		"process_id":      fmt.Sprint(input.Context.ProcessID),
		"socket_id":       fmt.Sprint(input.Context.SocketFD),
		"daemonset_id":    fmt.Sprint(input.Context.DaemonsetIdentifier),
		"enable_graph":    fmt.Sprint(utils.EnableGraph),
	}
}

// resolvePodLabels resolves pod labels for inbound traffic and adds them to the value map.
func resolvePodLabels(value map[string]string, ctx TrafficContext, url, host string) {
		
	if PodInformerInstance == nil {
		checkDebugUrlAndPrint(url, host, "Pod labels not resolved, PodInformerInstance is nil")
		return
	}

	if ctx.Direction == utils.DirectionOutbound {
		checkDebugUrlAndPrint(url, host, fmt.Sprintf("Pod labels not resolved for outbound request, podName: %s, direction: %v", ctx.HostName, ctx.Direction))
		return
	}

	processName := PodInformerInstance.GetProcessNameByProcessId(int32(ctx.ProcessID))
	if strings.Contains(processName, "envoy") {
		checkDebugUrlAndPrint(url, host, fmt.Sprintf("Pod labels not resolved for envoy request, podName: %s, direction: %v", ctx.HostName, ctx.Direction))
		return
	}

	if ctx.HostName == "" {
		checkDebugUrlAndPrint(url, host, "Failed to resolve pod name, hostName is empty for processId "+fmt.Sprint(ctx.ProcessID))
		slog.Debug("Failed to resolve pod name, hostName is empty for ", "processId", ctx.ProcessID, "hostName", ctx.HostName)
		return
	}

	podLabels, err := PodInformerInstance.ResolvePodLabels(ctx.HostName, url, host)
	if err != nil {
		slog.Error("Failed to resolve pod labels", "hostName", ctx.HostName, "error", err)
		checkDebugUrlAndPrint(url, host, "Error resolving pod labels "+ctx.HostName)
		return
	}

	value["tag"] = podLabels
	checkDebugUrlAndPrint(url, host, "Pod labels found in ParseAndProduce, podLabels found "+fmt.Sprint(podLabels)+" for hostName "+ctx.HostName)
	slog.Debug("Pod labels", "podName", ctx.HostName, "labels", podLabels)
}

// convertHeaders converts HTTP headers to both protobuf and string map formats in a single pass.
func convertHeaders(req *http.Request, resp *http.Response, shouldPrint bool) ConvertedHeaders {
	result := ConvertedHeaders{
		Request: HeaderSet{
			Protobuf:  make(map[string]*trafficpb.StringList),
			StringMap: make(map[string]string),
		},
		Response: HeaderSet{
			Protobuf:  make(map[string]*trafficpb.StringList),
			StringMap: make(map[string]string),
		},
	}

	// Convert request headers
	for name, values := range req.Header {
		for _, value := range values {
			result.Request.Protobuf[strings.ToLower(name)] = &trafficpb.StringList{
				Values: []string{value},
			}
			if shouldPrint && strings.EqualFold(name, "x-debug-token") {
				result.DebugID = value
			}
			result.Request.StringMap[name] = value
		}
	}
	result.Request.Protobuf["host"] = &trafficpb.StringList{Values: []string{req.Host}}
	result.Request.StringMap["host"] = req.Host

	// Convert response headers
	for name, values := range resp.Header {
		for _, value := range values {
			result.Response.Protobuf[strings.ToLower(name)] = &trafficpb.StringList{
				Values: []string{value},
			}
			result.Response.StringMap[name] = value
		}
	}

	return result
}

// shouldProcessRequest checks all filter conditions and returns true if the request should be processed.
func shouldProcessRequest(req *http.Request, reqHeaders map[string]string, ctx TrafficContext) bool {
	if !IsValidMethod(req.Method) {
		return false
	}

	if !utils.PassesFilter(trafficMetrics.FilterHeaderValueMap, reqHeaders) {
		return false
	}

	if utils.IgnoreIpTraffic && utils.CheckIfIp(req.Host) {
		return false
	}

	if utils.IgnoreCloudMetadataCalls && req.Host == "169.254.169.254" {
		return false
	}

	if utils.IgnoreEnvoyProxycalls && ctx.SourceIP == utils.EnvoyProxyIp && ctx.Direction == utils.DirectionOutbound {
		slog.Debug("Ignoring outbound envoy proxy call", "sourceIp", ctx.SourceIP, "url", req.URL.String(), "host", req.Host)
		return false
	}

	if utils.FilterPacket(reqHeaders) {
		return false
	}

	return true
}

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
				logMsg := fmt.Sprintf("url: %s, host: %s, message: %s", url, host, message)
				utils.PrintLogDebug(logMsg)
				go ProduceLogs(ctx, logMsg, LogTypeInfo)
				break
			} else if strings.Contains(host, debugString) {
				ctx := context.Background()
				logMsg := fmt.Sprintf("url: %s, host: %s, message: %s", url, host, message)
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

// parseHTTPTraffic parses HTTP requests and responses from raw byte buffers.
// Returns nil if parsing fails (errors are logged).
func parseHTTPTraffic(reqBuffer, respBuffer []byte, shouldPrint bool) *ParsedTraffic {
	// Parse requests
	reader := bufio.NewReader(bytes.NewReader(reqBuffer))
	requests := []http.Request{}
	requestBodies := []string{}

	for {
		req, err := http.ReadRequest(reader)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		} else if err != nil {
			utils.PrintLog(fmt.Sprintf("HTTP-request error: %s \n", err))
			return nil
		}
		body, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			utils.PrintLog(fmt.Sprintf("Got body err: %s\n", err))
			body = []byte{}
		}

		requests = append(requests, *req)
		requestBodies = append(requestBodies, string(body))
	}

	if shouldPrint {
		slog.Debug("parseHTTPTraffic", "requestCount", len(requests))
	}

	if len(requests) == 0 {
		return nil
	}

	// Parse responses
	reader = bufio.NewReader(bytes.NewReader(respBuffer))
	responses := []http.Response{}
	responseBodies := []string{}

	for {
		resp, err := http.ReadResponse(reader, nil)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		} else if err != nil {
			utils.PrintLog(fmt.Sprintf("HTTP-Response error: %s\n", err))
			return nil
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			utils.PrintLog(fmt.Sprintf("Got err reading resp body: %s\n", err))
			body = []byte{}
		}

		// Handle gzip/deflate decompression
		encoding := resp.Header["Content-Encoding"]
		var r io.Reader
		r = bytes.NewBuffer(body)
		if len(encoding) > 0 && (encoding[0] == "gzip" || encoding[0] == "deflate") {
			r, err = gzip.NewReader(r)
			if err != nil {
				utils.PrintLog(fmt.Sprintf("HTTP-gunzip "+"Failed to gzip decode: %s", err))
				body = []byte{}
			}
		}
		if err == nil {
			body, err = io.ReadAll(r)
			if err != nil {
				utils.PrintLog(fmt.Sprintf("Failed to read decompressed body: %s\n", err))
				body = []byte{}
			}
			if _, ok := r.(*gzip.Reader); ok {
				r.(*gzip.Reader).Close()
			}
		}

		responses = append(responses, *resp)
		responseBodies = append(responseBodies, string(body))
	}

	if shouldPrint {
		slog.Debug("parseHTTPTraffic", "responseCount", len(responses))
	}

	return &ParsedTraffic{
		Requests:       requests,
		RequestBodies:  requestBodies,
		Responses:      responses,
		ResponseBodies: responseBodies,
	}
}

func ParseAndProduce(receiveBuffer []byte, sentBuffer []byte, ctx TrafficContext) {

	if checkAndUpdateBandwidthProcessed(0) {
		return
	}

	shouldPrint := debugMode && strings.Contains(string(receiveBuffer), "x-debug-token")
	if shouldPrint {
		slog.Debug("ParseAndProduce", "receiveBuffer", string(receiveBuffer), "sentBuffer", string(sentBuffer))
	}

	parsed := parseHTTPTraffic(receiveBuffer, sentBuffer, shouldPrint)
	if parsed == nil {
		return
	}

	requests := parsed.Requests
	requestsContent := parsed.RequestBodies
	responses := parsed.Responses
	responsesContent := parsed.ResponseBodies

	if len(requests) != len(responses) {
		if shouldPrint {
			slog.Debug("Len req-res mismatch", "lenRequests", len(requests), "lenResponses", len(responses), "lenReceiveBuffer", len(receiveBuffer), "lenSentBuffer", len(sentBuffer), "isComplete", ctx.IsComplete)
		}
		if ctx.IsComplete {
			return
		}
		correctLen := len(requests)
		if len(responses) < len(requests) {
			correctLen = len(responses)
		}

		responses = responses[:correctLen]
		requests = requests[:correctLen]
		responsesContent = responsesContent[:correctLen]
		requestsContent = requestsContent[:correctLen]
	}

	bgCtx := context.Background()

	for i := 0; i < len(requests); i++ {
		req := &requests[i]
		resp := &responses[i]
		
		url := req.URL.String()
		checkDebugUrlAndPrint(url, req.Host, "URL,host found in ParseAndProduce")
		
		// Convert headers in a single pass (both protobuf and string map formats)
		headers := convertHeaders(req, resp, shouldPrint)

		// Check all filter conditions
		if !shouldProcessRequest(req, headers.Request.StringMap, ctx) {
			continue
		}

		// Get source IP from headers
		ip := GetSourceIp(headers.Request.Protobuf, ctx.SourceIP)

		// Build payloads
		input := PayloadInput{
			Request:      req,
			Response:     resp,
			Headers:      headers,
			RequestBody:  requestsContent[i],
			ResponseBody: responsesContent[i],
			SourceIP:     ip,
			Context:      ctx,
		}
		payload := buildProtobufPayload(input)
		value := buildJSONPayload(input)

		// Debug logging
		log := fmt.Sprintf("before resolving pod labels direction log: direction=%v, host=%v, path=%v, sourceIp=%v, destIp=%v, socketId=%v, processId=%v, hostName=%v",
			ctx.Direction,
			headers.Request.StringMap["host"],
			value["path"],
			ctx.SourceIP,
			ctx.DestIP,
			value["socket_id"],
			ctx.ProcessID,
			ctx.HostName,
		)
		checkDebugUrlAndPrint(url, req.Host, log)

		// Resolve pod labels for inbound traffic
		resolvePodLabels(value, ctx, url, req.Host)

		out, _ := json.Marshal(value)

		// calculating the size of outgoing bytes and requests (1) and saving it in outgoingCounterMap
		// this number is the closest (slightly higher) to the actual connection transfer bytes.
		outgoingBytes := len(out)

		if checkAndUpdateBandwidthProcessed(outgoingBytes) {
			return
		}

		sendMetrics(headers, ctx, outgoingBytes, shouldPrint, responsesContent, i, out)

		if apiProcessor.CloudProcessorInstance != nil {
			apiProcessor.CloudProcessorInstance.Produce(value)

		} else {
			// Produce to kafka with collection_details header
			go ProduceStr(bgCtx, string(out), url, req.Host, req.Method)
			go Produce(bgCtx, payload)
		}
	}
}

func sendMetrics(headers ConvertedHeaders, ctx TrafficContext, outgoingBytes int, shouldPrint bool, responsesContent []string, i int, out []byte) {
	hostString := headers.Request.StringMap["host"]
	if utils.CheckIfIpHost(hostString) {
		hostString = "ip-host"
	}
	oc := utils.GenerateOutgoingCounter(ctx.VxlanID, ctx.SourceIP, hostString)
	trafficMetrics.SubmitOutgoingTrafficMetrics(oc, outgoingBytes)

	if shouldPrint {
		if strings.Contains(responsesContent[i], headers.DebugID) {
			goodRequests++
		} else {
			slog.Debug("req-resp.String()", "out", string(out))
			badRequests++
		}

		if goodRequests%100 == 0 || badRequests%100 == 0 {
			slog.Debug("Good requests", "count", goodRequests, "badRequests", badRequests)
		}
	}
}
