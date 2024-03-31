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
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/trafficMetrics"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

var goodRequests = 0
var badRequests = 0

func ParseAndProduce(receiveBuffer []byte, sentBuffer []byte,
	sourceIp string, vxlanID int, isPending bool, trafficSource string) {

	fmt.Printf("ParseAndProduce: receiveBuffer: %v, sentBuffer: %v	", string(receiveBuffer), string(sentBuffer))

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
		body, err := ioutil.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			utils.PrintLog(fmt.Sprintf("Got body err: %s\n", err))
			return
		}

		requests = append(requests, *req)
		requestsContent = append(requestsContent, string(body))
		i++
	}

	fmt.Printf("ParseAndProduce: Found count of requests: %v", i)

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
			utils.PrintLog(fmt.Sprintf("HTTP Request error: %s\n", err))
			return
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			utils.PrintLog(fmt.Sprintf("Got body err: %s\n", err))
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
			body, err = ioutil.ReadAll(r)
			if _, ok := r.(*gzip.Reader); ok {
				r.(*gzip.Reader).Close()
			}

		}

		responses = append(responses, *resp)
		responsesContent = append(responsesContent, string(body))

		i++
	}

	fmt.Printf("ParseAndProduce: Found count of responses: %v", i)

	if len(requests) != len(responses) {
		fmt.Printf("Len req-res mismatch: %v %v %v %v", len(requests), len(responses), len(receiveBuffer), len(sentBuffer))
		return
	}

	debug := os.Getenv("DEBUG")
	if len(debug) == 0 {
		debug = "false"
	}

	i = 0
	for {
		if len(requests) < i+1 {
			break
		}

		req := &requests[i]
		resp := &responses[i]

		id := ""

		reqHeader := make(map[string]string)
		for name, values := range req.Header {
			// Loop over all values for the name.
			for _, value := range values {
				if strings.EqualFold(name, "postman-token") {
					id = value
					if debug == "true" {
						fmt.Printf("Id found: %v\n", id)
					}
				}
				if debug == "true" {
					fmt.Printf("Key: %v Value: %v\n", name, value)
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
			"time":            fmt.Sprint(time.Now().Unix()),
			"statusCode":      fmt.Sprint(resp.StatusCode),
			"type":            string(req.Proto),
			"status":          resp.Status,
			"akto_account_id": fmt.Sprint(1000000),
			"akto_vxlan_id":   fmt.Sprint(vxlanID),
			"is_pending":      fmt.Sprint(isPending),
			"source":          trafficSource,
		}

		out, _ := json.Marshal(value)
		ctx := context.Background()

		// calculating the size of outgoing bytes and requests (1) and saving it in outgoingCounterMap
		// this number is the closest (slightly higher) to the actual connection transfer bytes.
		outgoingBytes := len(out)

		hostString := reqHeader["host"]
		if utils.CheckIfIpHost(hostString) {
			hostString = "ip-host"
		}
		oc := utils.GenerateOutgoingCounter(vxlanID, sourceIp, hostString)
		trafficMetrics.SubmitOutgoingTrafficMetrics(oc, outgoingBytes)

		if strings.Contains(responsesContent[i], id) {
			if debug == "true" {
				fmt.Printf("Id found in body: %v\n", id)
			}
			goodRequests++
		} else {
			fmt.Printf("seq: %v, req-resp.String() %v\n", vxlanID, string(out))
			badRequests++
		}

		if goodRequests%100 == 0 || badRequests%100 == 0 || debug == "true" {
			fmt.Printf("Good requests: %v , Bad requests: %v\n", goodRequests, badRequests)
		}

		go Produce(ctx, string(out))
		i++
	}
}
