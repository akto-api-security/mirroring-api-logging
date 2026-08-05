package kafkaUtil

// parser.go is the entry point: ParseAndProduce dispatches a captured
// request/response pair to either the zero-copy fast path (parse.go) or the
// standard-library slow path (parse.go), applying policy gates (policy.go) and
// building/producing payloads (payload.go) along the way.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/apiProcessor"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

func ParseAndProduce(receiveBuffer []byte, sentBuffer []byte, ctx TrafficContext) {
	if checkAndUpdateBandwidthProcessed(0) {
		return
	}

	shouldPrint := debugMode
	if shouldPrint {
		slog.Debug("ParseAndProduce", "receiveBuffer", string(receiveBuffer), "sentBuffer", string(sentBuffer))
	}

	// SkipPairProcessing isolates the parse cost: everything up to here (blob
	// assembly, pair plumbing) runs, but the HTTP parse/marshal/produce below is skipped.
	if SkipPairProcessing {
		return
	}

	if utils.FastIngestion {
		fastParseAndProduce(receiveBuffer, sentBuffer, ctx)
		return
	}

	parsed := parseHTTPTraffic(receiveBuffer, sentBuffer, shouldPrint)
	if parsed == nil {
		utils.Pipeline.PairsParseFailure.Add(1)
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
		if !shouldProcessRequestLegacy(req, headers.Request.StringMap, ctx) {
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

		value := buildJSONPayload(input)
		processName := PodInformerInstance.GetProcessNameByProcessId(int32(ctx.ProcessID))

		// Debug logging
		log := fmt.Sprintf("before resolving pod labels direction log: direction=%v, host=%v, path=%v, sourceIp=%v, destIp=%v, socketId=%v, processId=%v, hostName=%v, processName=%v, debugToken=%v",
			ctx.Direction,
			headers.Request.StringMap["host"],
			value["path"],
			ctx.SourceIP,
			ctx.DestIP,
			value["socket_id"],
			ctx.ProcessID,
			ctx.HostName,
			processName,
			headers.Request.StringMap["X-Debug-Token"],
		)
		checkDebugUrlAndPrint(url, req.Host, log)

		// Resolve pod labels for inbound traffic, then overlay any inject tags.
		// Only set the key when non-empty so an empty tag isn't emitted.
		if tag := mergeInjectTags(resolvePodLabelsTag(ctx, processName, url, req.Host)); tag != "" {
			value["tag"] = tag
		}

		// checkDebugUrlAndPrint(url, req.Host, "After pod labels URL,host marshalling to JSON")
		out, err := json.Marshal(value)
		if err != nil {
			slog.Error("Failed to json marshal the payload", "error", err)
			// checkDebugUrlAndPrint(url, req.Host, fmt.Sprintf("json marshal payload failed %v", err))
			return
		}

		// calculating the size of outgoing bytes and requests (1) and saving it in outgoingCounterMap
		// this number is the closest (slightly higher) to the actual connection transfer bytes.
		outgoingBytes := len(out)

		if checkAndUpdateBandwidthProcessed(outgoingBytes) {
			return
		}

		if apiProcessor.CloudProcessorInstance != nil {
			apiProcessor.CloudProcessorInstance.Produce(value)

		} else {
			// Produce to kafka with collection_details header
			go ProduceStr(bgCtx, string(out), url, req.Host, req.Method)

			// Only if threat enabled
			if utils.ThreatEnabled {
				payload := buildProtobufPayload(input)
				go Produce(bgCtx, payload)
			}
		}

		if token := headers.Request.StringMap["X-Debug-Token"]; token != "" {
			if !strings.Contains(responsesContent[i], token) {
				utils.Pipeline.PairsMismatched.Add(1)
			}
		}
		utils.Pipeline.PairsParseSuccess.Add(1)
		sendMetrics(headers, ctx, outgoingBytes, shouldPrint, responsesContent, i, out)
	}
}
