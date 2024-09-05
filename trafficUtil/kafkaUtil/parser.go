package kafkaUtil

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
	"strings"
	"sync"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/trafficMetrics"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
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
)

const ONE_MINUTE = 60

func init() {
	utils.InitVar("DEBUG_MODE", &debugMode)
	utils.InitVar("OUTPUT_BANDWIDTH_LIMIT", &outputBandwidthLimitPerMin)
	// convert MB to B
	if outputBandwidthLimitPerMin != -1 {
		outputBandwidthLimitPerMin = outputBandwidthLimitPerMin * 1024 * 1024
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
		log.Printf("reset limit: %v %v, processed: %v", now, lastSampleUpdate, currentBandwidthProcessed)
	}
	skip := currentBandwidthProcessed > outputBandwidthLimitPerMin
	if !skip {
		currentBandwidthProcessed += sampleSize
		skip = currentBandwidthProcessed > outputBandwidthLimitPerMin
		if skip {
			log.Printf("Skipping sending to akto at: %v %v, processed: %v", now, lastSampleUpdate, currentBandwidthProcessed)
		}
	}
	return skip
}

func IsValidMethod(method string) bool {
	_, ok := methodsMap[strings.ToUpper(method)]
	return ok
}

func ParseAndProduceAllRequests(allRequests []http.Request, allRequestsContent []string, sourceIp string, destIp string, vxlanID int, isPending bool, trafficSource string, isComplete bool, direction int){
	if len(allRequests) == 0 {
		return
	}

	i := 0

	for {
		if len(allRequests) < (i + 1) {
			break
		}

		req := &allRequests[i]

		if !IsValidMethod(req.Method) {
			continue
		}

		currentReq := &allRequests[i]
		currentReqHeader := make(map[string]string)

		for name, values := range currentReq.Header {
				// Loop over all values for the name.
			for _, value := range values {
				currentReqHeader[name] = value
			}
		}

		currentReqHeader["host"] = currentReq.Host
		if utils.IgnoreIpTraffic && utils.CheckIfIp(req.Host) {
			i++
			continue
		}

		if utils.IgnoreCloudMetadataCalls && req.Host == "169.254.169.254" {
			i++
			continue
		}

		reqHeaderString, _ := json.Marshal(currentReqHeader)

		value := map[string]string{
			"path":            req.URL.String(),
			"requestHeaders":  string(reqHeaderString),
			"responseHeaders": "",
			"method":          req.Method,
			"requestPayload":  allRequestsContent[i],
			"responsePayload": "",
			"ip":              sourceIp,
			"destIp":          destIp,
			"time":            fmt.Sprint(time.Now().Unix()),
			"statusCode":      fmt.Sprint(-1),
			"type":            string(req.Proto),
			"status":          "",
			"akto_account_id": fmt.Sprint(1000000),
			"akto_vxlan_id":   fmt.Sprint(vxlanID),
			"is_pending":      fmt.Sprint(isPending),
			"source":          trafficSource,
			"direction":       fmt.Sprint(direction),
		}

		out, _ := json.Marshal(value)
		ctx := context.Background()
		go Produce(ctx, string(out), true)
	}
}

func ParseAndProduce(receiveBuffer []byte, sentBuffer []byte,
	sourceIp string, destIp string, vxlanID int, isPending bool, trafficSource string, isComplete bool, direction int) {

	if checkAndUpdateBandwidthProcessed(0) {
		return
	}

	shouldPrint := debugMode && strings.Contains(string(receiveBuffer), "x-debug-token")
	if shouldPrint {
		fmt.Printf("ParseAndProduce: receiveBuffer: %v , sentBuffer: %v\n", string(receiveBuffer), string(sentBuffer))
	}

	reader := bufio.NewReader(bytes.NewReader(receiveBuffer))
	i := 0
	requests := []http.Request{}
	allRequests := []http.Request{}
	requestsContent := []string{}
	allRequestsContent := []string{}
	var invalidRequestsFound bool

	for {
		req, err := http.ReadRequest(reader)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		} else if err != nil {
			utils.PrintLog(fmt.Sprintf("HTTP-request error: %s \n", err))
			invalidRequestsFound = true
			continue
		}
		body, err := ioutil.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			utils.PrintLog(fmt.Sprintf("Got body err: %s\n", err))
			invalidRequestsFound = true
			continue
		}

		if !invalidRequestsFound{
			requests = append(requests, *req)
			requestsContent = append(requestsContent, string(body))
		}

		allRequests = append(allRequests, *req)
		allRequestsContent = append(allRequestsContent, string(body))
		
		i++
	}

	if shouldPrint {
		fmt.Printf("ParseAndProduce: Found count of requests: %v\n", i)
	}

	requestProtectionEnabled := os.Getenv("REQUEST_PROTECTION_ENABLED")
	var shouldSendAllRequests = len(requestProtectionEnabled) > 0


	if invalidRequestsFound ||  len(requests) == 0 {
		if(shouldSendAllRequests){
			ParseAndProduceAllRequests(allRequests, allRequestsContent, sourceIp, destIp, vxlanID, isPending, trafficSource, isComplete, direction)
		}
		return
	}

	reader = bufio.NewReader(bytes.NewReader(sentBuffer))
	i = 0

	responses := []http.Response{}
	responsesContent := []string{}

	var invalidResponsesFound bool

	for {

		resp, err := http.ReadResponse(reader, nil)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		} else if err != nil {
			utils.PrintLog(fmt.Sprintf("HTTP Request error: %s\n", err))
			invalidResponsesFound = true
			break
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			utils.PrintLog(fmt.Sprintf("Got body err: %s\n", err))
			invalidResponsesFound = true
			break
		}
		encoding := resp.Header["Content-Encoding"]
		var r io.Reader
		r = bytes.NewBuffer(body)
		if len(encoding) > 0 && (encoding[0] == "gzip" || encoding[0] == "deflate") {
			r, err = gzip.NewReader(r)
			if err != nil {
				utils.PrintLog(fmt.Sprintf("HTTP-gunzip "+"Failed to gzip decode: %s", err))
				invalidResponsesFound = true
				break
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

	if shouldPrint {

		fmt.Printf("ParseAndProduce: Found count of responses: %v\n", i)
	}
	if len(requests) != len(responses) || invalidResponsesFound {
		if shouldPrint {
			fmt.Printf("Len req-res mismatch: lens: %v %v %v %v isComplete: %v\n",
				len(requests), len(responses),
				len(receiveBuffer), len(sentBuffer), isComplete)
		}

		if(shouldSendAllRequests){
			ParseAndProduceAllRequests(allRequests, allRequestsContent, sourceIp, destIp, vxlanID, isPending, trafficSource, isComplete, direction)
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

		reqHeader := make(map[string]string)
		for name, values := range req.Header {
			// Loop over all values for the name.
			for _, value := range values {
				if shouldPrint &&
					strings.EqualFold(name, "x-debug-token") {
					id = value
				}
				reqHeader[name] = value
			}
		}

		reqHeader["host"] = req.Host

		passes := utils.PassesFilter(trafficMetrics.FilterHeaderValueMap, reqHeader)
		//printLog("Req header: " + mapToString(reqHeader))
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

		var skipPacket = utils.FilterPacket(reqHeader)

		if skipPacket {
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
		}

		out, _ := json.Marshal(value)
		ctx := context.Background()

		// calculating the size of outgoing bytes and requests (1) and saving it in outgoingCounterMap
		// this number is the closest (slightly higher) to the actual connection transfer bytes.
		outgoingBytes := len(out)

		if checkAndUpdateBandwidthProcessed(outgoingBytes) {
			return
		}

		hostString := reqHeader["host"]
		if utils.CheckIfIpHost(hostString) {
			hostString = "ip-host"
		}
		oc := utils.GenerateOutgoingCounter(vxlanID, sourceIp, hostString)
		trafficMetrics.SubmitOutgoingTrafficMetrics(oc, outgoingBytes)

		if shouldPrint {
			if strings.Contains(responsesContent[i], id) {
				goodRequests++
			} else {
				fmt.Printf("req-resp.String() %v\n", string(out))
				badRequests++
			}

			if goodRequests%100 == 0 || badRequests%100 == 0 {
				fmt.Printf("Good requests: %v , Bad requests: %v\n", goodRequests, badRequests)
			}
		}

		go Produce(ctx, string(out), false)
		if(shouldSendAllRequests){
			go Produce(ctx, string(out), true)
		}
		i++
	}
}
