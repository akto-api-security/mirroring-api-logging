package kafkaUtil

// This file owns the "raw bytes -> parsed HTTP" concern: the standard-library
// slow path (parseHTTPTraffic) and the zero-copy fast path (fastParseAndProduce
// + its parser/encoder pools).

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/fastparser"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

// parseHTTPTraffic parses HTTP requests and responses from raw byte buffers.
// Returns nil if parsing fails (errors are logged).
func parseHTTPTraffic(reqBuffer, respBuffer []byte, shouldPrint bool) *ParsedTraffic {
	// Parse requests
	reader := bufio.NewReader(bytes.NewReader(reqBuffer))
	requests := []http.Request{}
	requestBodies := []string{}
	parseBodyFlags := []bool{} // track which requests should have body parsed

	for {
		req, err := http.ReadRequest(reader)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		} else if err != nil {
			utils.PrintLog(fmt.Sprintf("HTTP-request error: %s \n", err))
			return nil
		}

		// Determine if we should parse body for this request
		parseBody := shouldParseBody(req.Method, req.Host, req.URL.Path)

		var body []byte
		if parseBody {
			body, err = io.ReadAll(req.Body)
			if err != nil {
				utils.Pipeline.RequestBodyFailure.Add(1)
				utils.PrintLog(fmt.Sprintf("Got body err: %s\n", err))
				body = []byte{}
			}
		} else {
			// Skip body parsing - MUST drain from bufio.Reader to avoid corrupting next request
			io.Copy(io.Discard, req.Body)
			body = []byte{}
			// Inject discovery-only header in REQUEST
			req.Header.Set("x-akto-skip-sample-update", "true")
		}
		req.Body.Close()

		requests = append(requests, *req)
		requestBodies = append(requestBodies, string(body))
		parseBodyFlags = append(parseBodyFlags, parseBody)
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

	for i := 0; ; i++ {
		resp, err := http.ReadResponse(reader, nil)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		} else if err != nil {
			utils.PrintLog(fmt.Sprintf("HTTP-Response error: %s\n", err))
			return nil
		}

		var body []byte
		// Only parse response body if we parsed the corresponding request body
		shouldParseRespBody := i < len(parseBodyFlags) && parseBodyFlags[i]

		if shouldParseRespBody {
			body, err = io.ReadAll(resp.Body)
			if err != nil {
				utils.Pipeline.ResponseBodyFailure.Add(1)
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
		} else {
			// Skip response body - MUST drain from bufio.Reader
			io.Copy(io.Discard, resp.Body)
			body = []byte{}
		}
		resp.Body.Close()

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

// parserPool + encoderPool hand each goroutine its own zero-copy parser and its
// own encoder (both NOT concurrency-safe). The encoder kind is chosen once by
// FAST_ENCODER (resolved in init) and captured when the pool first allocates.
var parserPool = sync.Pool{New: func() any { return fastparser.NewFastParser() }}
var encoderPool = sync.Pool{New: func() any { return fastparser.NewEncoder(fastEncoderKind) }}

// fastPrinted counts fast-path payloads; the first 10 are logged for eyeballing.
var fastPrinted atomic.Int64

// fastParseAndProduce is the zero-copy path (USE_FAST_PARSER=true): one message
// per buffer, parse -> Encode -> ProduceStr. No filters, gzip, threat, or cloud
// path — minimal by design; only parse success/failure metrics are kept.
func fastParseAndProduce(receiveBuffer, sentBuffer []byte, ctx TrafficContext) {
	p := parserPool.Get().(*fastparser.Parser)
	defer parserPool.Put(p)
	enc := encoderPool.Get().(fastparser.Encoder)
	defer encoderPool.Put(enc)

	req, err := p.ParseRequest(receiveBuffer)
	if err != nil {
		utils.Pipeline.PairsParseFailure.Add(1)
		return
	}
	resp, err := p.ParseResponse(sentBuffer)
	if err != nil {
		utils.Pipeline.PairsParseFailure.Add(1)
		return
	}

	host := string(req.Host())

	// Shared method/host/envoy filtering (no header-map filters on the fast path).
	if !shouldProcessRequest(string(req.Method), host, ctx) {
		return
	}

	// Resolved once and reused for both ProcessName and pod-label resolution.
	processName := PodInformerInstance.GetProcessNameByProcessId(int32(ctx.ProcessID))

	meta := &fastparser.Meta{
		// Matches legacy buildJSONPayload: the JSON payload's "ip" is the raw
		// packet source IP, not the X-Forwarded-For-resolved one. getSourceIpFast
		// is reserved for the threat/protobuf path (where legacy applies it).
		SourceIP:      ctx.SourceIP,
		DestIP:        ctx.DestIP,
		TimeUnix:      time.Now().Unix(),
		AktoAccountID: fmt.Sprint(1000000),
		VxlanID:       ctx.VxlanID,
		IsPending:     ctx.IsPending,
		Source:        ctx.TrafficSource,
		Direction:     ctx.Direction,
		ProcessID:     ctx.ProcessID,
		SocketID:      ctx.SocketFD,
		DaemonsetID:   ctx.DaemonsetIdentifier,
		ProcessName:   processName,
		EnableGraph:   utils.EnableGraph,
		Tag:           mergeInjectTags(resolvePodLabelsTag(ctx, processName, string(req.Path), host)),
	}

	out := enc.Encode(req, resp, meta) // aliases the encoder's reused buffer; string(out) below copies it

	if n := fastPrinted.Add(1); n <= 10 {
		slog.Info("USE_FAST_PARSER sample", "n", n, "payload", string(out))
	}

	go ProduceStr(context.Background(), string(out), string(req.Path), string(req.Host()), string(req.Method))

	// PairsMismatched: X-Debug-Token from the request should echo in the response body.
	if token := req.Header("X-Debug-Token"); len(token) > 0 && !bytes.Contains(resp.Body, token) {
		utils.Pipeline.PairsMismatched.Add(1)
	}
	utils.Pipeline.PairsParseSuccess.Add(1)
}
