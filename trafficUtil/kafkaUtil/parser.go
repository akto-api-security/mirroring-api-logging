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
	bloomfilter "github.com/bits-and-blooms/bloom/v3"
)

// TrafficConnID mirrors ebpf/structs.ConnID fields used for log correlation (eBPF mirroring path).
type TrafficConnID struct {
	ID        uint64
	Fd        uint32
	Timestamp uint64 // connection start, nanoseconds (Conn_start_ns)
	Ip        uint32
	Port      uint16
}

// TrafficConnIDLogArgs returns the same alternating key/value pairs as structs.ConnIDLogArgs for slog.
func TrafficConnIDLogArgs(c *TrafficConnID) []any {
	if c == nil {
		return nil
	}
	return []any{"fd", c.Fd, "id", c.ID, "timestamp", c.Timestamp, "ip", c.Ip, "port", c.Port}
}

// TrafficContext holds metadata about the captured traffic.
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
	// ConnID is set on the eBPF mirroring path for structured logs (nil elsewhere).
	ConnID *TrafficConnID
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
		slog.Debug("Failed to resolve pod name, hostName is empty for ", append(TrafficConnIDLogArgs(ctx.ConnID), "processId", ctx.ProcessID, "hostName", ctx.HostName)...)
		return
	}

	podLabels, err := PodInformerInstance.ResolvePodLabels(ctx.HostName, url, host)
	if err != nil {
		slog.Error("Failed to resolve pod labels", append(TrafficConnIDLogArgs(ctx.ConnID), "hostName", ctx.HostName, "error", err)...)
		checkDebugUrlAndPrint(url, host, "Error resolving pod labels "+ctx.HostName)
		return
	}

	value["tag"] = podLabels
	checkDebugUrlAndPrint(url, host, "Pod labels found in ParseAndProduce, podLabels found "+fmt.Sprint(podLabels)+" for hostName "+ctx.HostName)
	slog.Debug("Pod labels", append(TrafficConnIDLogArgs(ctx.ConnID), "podName", ctx.HostName, "labels", podLabels)...)
}

func mergeInjectTags(value map[string]string) {
	if len(injectTagsMap) == 0 {
		return
	}

	merged := map[string]string{}
	for k, v := range injectTagsMap {
		merged[k] = v
	}

	if existing, ok := value["tag"]; ok && existing != "" {
		podLabelMap := map[string]string{}
		if err := json.Unmarshal([]byte(existing), &podLabelMap); err == nil {
			for k, v := range podLabelMap {
				merged[k] = v
			}
		}
	}

	if b, err := json.Marshal(merged); err == nil {
		value["tag"] = string(b)
	}
}

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
		slog.Debug("Ignoring outbound envoy proxy call", append(TrafficConnIDLogArgs(ctx.ConnID), "sourceIp", ctx.SourceIP, "url", req.URL.String(), "host", req.Host)...)
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
	dataPrintMode              = false
	outputBandwidthLimitPerMin = -1
	currentBandwidthProcessed  = 0
	lastSampleUpdate           = time.Now().Unix()
	sampleMutex                = sync.RWMutex{}
	injectTagsMap              = map[string]string{}
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

	lruCache            *LRUCache
	lruCacheCapacity    = 100000
	bloomFilterCapacity = 1000000
	bloomFilterFPRate   = 0.01
	timeBucketDuration  = 10 * time.Minute
	memSamplingEnabled  = false
)

var bloomFilter *bloomfilter.BloomFilter

const ONE_MINUTE = 60

func init() {
	utils.InitVar("DEBUG_MODE", &debugMode)
	utils.InitVar("OUTPUT_BANDWIDTH_LIMIT", &outputBandwidthLimitPerMin)
	utils.InitVar("EVENT_CHAN_BUFF_SIZE", &EventChanBuffSize)
	utils.InitVar("AKTO_MEM_SAMPLING_ENABLED", &memSamplingEnabled)
	utils.InitVar("LRU_CACHE_CAPACITY", &lruCacheCapacity)
	utils.InitVar("BLOOM_FILTER_CAPACITY", &bloomFilterCapacity)
	utils.InitVar("BLOOM_FILTER_FP_RATE", &bloomFilterFPRate)
	utils.InitVar("TIME_BUCKET_DURATION_MINUTES", &timeBucketDuration)
	utils.InitVar("DATA_PRINT_MODE", &dataPrintMode)

	if outputBandwidthLimitPerMin != -1 {
		outputBandwidthLimitPerMin = outputBandwidthLimitPerMin * 1024 * 1024
	}
	debugStringsEnv := ""
	utils.InitVar("DEBUG_URLS", &debugStringsEnv)
	if len(debugStringsEnv) > 0 {
		DebugStrings = strings.Split(debugStringsEnv, ",")
	}
	slog.Info("debugStrings", "DebugStrings", DebugStrings)

	if memSamplingEnabled {
		bloomFilter = bloomfilter.NewWithEstimates(uint(bloomFilterCapacity), bloomFilterFPRate)

		lruCache = NewLRUCache(lruCacheCapacity)

		go func() {
			ticker := time.NewTicker(24 * time.Hour)
			defer ticker.Stop()
			for range ticker.C {
				bloomFilter.ClearAll()
			}
		}()
	}

	injectTagsEnv := ""
	utils.InitVar("AKTO_INJECT_TAGS", &injectTagsEnv)
	if injectTagsEnv != "" {
		for _, pair := range strings.Split(injectTagsEnv, ";") {
			pair = strings.TrimSpace(pair)
			if idx := strings.IndexByte(pair, '='); idx > 0 {
				k := strings.TrimSpace(pair[:idx])
				v := strings.TrimSpace(pair[idx+1:])
				if k != "" {
					injectTagsMap[k] = v
				}
			}
		}
		slog.Info("AKTO_INJECT_TAGS loaded", "tags", injectTagsMap)
	}

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			UpdateDebugStringsFromFile()
			<-ticker.C
		}
	}()
}

func UpdateDebugStringsFromFile() {
	filePath := "/ebpf/debug-urls.txt"
	f, err := os.Open(filePath)
	if err != nil {
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

// shouldParseBody uses Bloom Filter + LRU Cache to decide if body should be parsed.
// Only applies optimization if memSamplingEnabled is true.
func shouldParseBody(method, host, path string) bool {
	if !memSamplingEnabled {
		return true
	}

	key := buildSignatureKey(method, host, path)

	if !bloomFilter.TestString(key) {
		bloomFilter.AddString(key)
		lruCache.Put(key, getTimeBucket())
		return true
	}

	if timeBucket, found := lruCache.Get(key); found {
		if isTimeBucketExpired(timeBucket) {
			lruCache.Put(key, getTimeBucket())
			return true
		}
		return false
	}

	lruCache.Put(key, getTimeBucket())
	return true
}

// parseHTTPTraffic parses HTTP requests and responses from raw byte buffers sequentially.
func parseHTTPTraffic(reqBuffer, respBuffer []byte, shouldPrint bool, ctx TrafficContext) *ParsedTraffic {
	reader := bufio.NewReader(bytes.NewReader(reqBuffer))
	requests := []http.Request{}
	requestBodies := []string{}
	parseBodyFlags := []bool{}

	for {
		req, err := http.ReadRequest(reader)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		} else if err != nil {
			utils.PrintLog(fmt.Sprintf("HTTP-request error: %s \n", err))
			return nil
		}

		parseBody := shouldParseBody(req.Method, req.Host, req.URL.Path)

		var body []byte
		if parseBody {
			body, err = io.ReadAll(req.Body)
			if err != nil {
				utils.PrintLog(fmt.Sprintf("Got body err: %s\n", err))
				body = []byte{}
			}
		} else {
			io.Copy(io.Discard, req.Body)
			body = []byte{}
			req.Header.Set("x-akto-skip-sample-update", "true")
		}
		req.Body.Close()

		requests = append(requests, *req)
		requestBodies = append(requestBodies, string(body))
		parseBodyFlags = append(parseBodyFlags, parseBody)
	}

	if shouldPrint {
		slog.Debug("parseHTTPTraffic", append(TrafficConnIDLogArgs(ctx.ConnID), "requestCount", len(requests))...)
	}

	if len(requests) == 0 {
		return nil
	}

	reader = bufio.NewReader(bytes.NewReader(respBuffer))
	responses := []http.Response{}
	responseBodies := []string{}

	for i := 0; ; i++ {
		resp, err := http.ReadResponse(reader, nil)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		} else if err != nil {
			utils.PrintLog(fmt.Sprintf("HTTP-Response error: %s\n", err))
			return nil
		}

		var body []byte
		shouldParseRespBody := i < len(parseBodyFlags) && parseBodyFlags[i]

		if shouldParseRespBody {
			body, err = io.ReadAll(resp.Body)
			if err != nil {
				utils.PrintLog(fmt.Sprintf("Got err reading resp body: %s\n", err))
				body = []byte{}
			}

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
		} else {
			io.Copy(io.Discard, resp.Body)
			body = []byte{}
		}
		resp.Body.Close()

		responses = append(responses, *resp)
		responseBodies = append(responseBodies, string(body))
	}

	if shouldPrint {
		slog.Debug("parseHTTPTraffic", append(TrafficConnIDLogArgs(ctx.ConnID), "responseCount", len(responses))...)
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

	shouldPrint := (debugMode && strings.Contains(string(receiveBuffer), "x-debug-token")) || dataPrintMode
	if shouldPrint {
		slog.Warn("ParseAndProduce", append(TrafficConnIDLogArgs(ctx.ConnID), "receiveBuffer", string(receiveBuffer), "sentBuffer", string(sentBuffer))...)
	}

	if KafkaDisabled() {
		return
	}

	parsed := parseHTTPTraffic(receiveBuffer, sentBuffer, shouldPrint, ctx)
	if parsed == nil {
		return
	}

	requests := parsed.Requests
	requestsContent := parsed.RequestBodies
	responses := parsed.Responses
	responsesContent := parsed.ResponseBodies

	if len(requests) != len(responses) {
		if shouldPrint {
			slog.Debug("Len req-res mismatch", append(TrafficConnIDLogArgs(ctx.ConnID),
				"lenRequests", len(requests), "lenResponses", len(responses),
				"lenReceiveBuffer", len(receiveBuffer), "lenSentBuffer", len(sentBuffer), "isComplete", ctx.IsComplete)...)
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

		headers := convertHeaders(req, resp, shouldPrint)

		if !shouldProcessRequest(req, headers.Request.StringMap, ctx) {
			continue
		}

		ip := GetSourceIp(headers.Request.Protobuf, ctx.SourceIP)

		input := PayloadInput{
			Request:      req,
			Response:     resp,
			Headers:      headers,
			RequestBody:  requestsContent[i],
			ResponseBody: responsesContent[i],
			SourceIP:     ip,
			Context:      ctx,
		}

		value := buildJSONPayload(input)

		if len(DebugStrings) > 0 {
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
		}

		resolvePodLabels(value, ctx, url, req.Host)

		mergeInjectTags(value)

		checkDebugUrlAndPrint(url, req.Host, "After pod labels URL,host marshalling to JSON")
		out, err := json.Marshal(value)
		if err != nil {
			slog.Error("Failed to json marshal the payload", append(TrafficConnIDLogArgs(ctx.ConnID), "error", err)...)
			checkDebugUrlAndPrint(url, req.Host, fmt.Sprintf("json marshal payload failed %v", err))
			return
		}

		outgoingBytes := len(out)

		if checkAndUpdateBandwidthProcessed(outgoingBytes) {
			return
		}

		if apiProcessor.CloudProcessorInstance != nil {
			apiProcessor.CloudProcessorInstance.Produce(value)
		} else if KafkaWriteAvailable() {
			go ProduceStr(bgCtx, string(out), url, req.Host, req.Method)

			if utils.ThreatEnabled {
				payload := buildProtobufPayload(input)
				go Produce(bgCtx, payload)
			}
		}

		sendMetrics(headers, ctx, outgoingBytes, shouldPrint, responsesContent, i, out)
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
			slog.Debug("req-resp.String()", append(TrafficConnIDLogArgs(ctx.ConnID), "out", string(out))...)
			badRequests++
		}

		if goodRequests%10 == 0 || badRequests%10 == 0 {
			slog.Debug("Good requests", append(TrafficConnIDLogArgs(ctx.ConnID), "count", goodRequests, "badRequests", badRequests)...)
		}
	}
}
