package kafkaUtil

// This file owns the "parsed HTTP -> outbound payload" concern: the payload
// DTOs, the protobuf/JSON payload builders, header conversion, and tag
// enrichment (pod labels + injected tags).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/fastparser"
	trafficpb "github.com/akto-api-security/mirroring-api-logging/trafficUtil/protobuf/traffic_payload"
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

// CLIENT_IP_HEADERS lists the request headers, in priority order, that may carry
// the real client IP behind proxies/load balancers.
var CLIENT_IP_HEADERS = []string{
	"x-forwarded-for",
	"x-real-ip",
	"x-cluster-client-ip",
	"true-client-ip",
	"x-original-forwarded-for",
	"x-client-ip",
	"client-ip",
}

// GetSourceIp returns the first non-empty client IP found in CLIENT_IP_HEADERS
// (taking the first comma-separated token), falling back to packetIp.
func GetSourceIp(reqHeaders map[string]*trafficpb.StringList, packetIp string) string {

	for _, header := range CLIENT_IP_HEADERS {
		if headerValues, exists := reqHeaders[header]; exists {
			for _, headerValue := range headerValues.Values {
				parts := strings.Split(headerValue, ",")
				for _, part := range parts {
					ip := strings.TrimSpace(part)
					if ip != "" {
						slog.Debug("Ip found in", "the header", header)
						return ip
					}
				}
			}
		}
	}

	return packetIp
}

// getSourceIpFast is the zero-copy counterpart of GetSourceIp for the fast path.
// It scans CLIENT_IP_HEADERS directly over the parsed request's header slices
// (no map, no strings.Split), taking the first comma-separated token. The only
// allocation is the returned string, since it lands in Meta.SourceIP.
func getSourceIpFast(req *fastparser.Request, packetIp string) string {
	for _, header := range CLIENT_IP_HEADERS {
		v := req.Header(header) // []byte view into the buffer; nil if absent
		if v == nil {
			continue
		}
		if end := bytes.IndexByte(v, ','); end >= 0 {
			v = v[:end]
		}
		v = bytes.TrimSpace(v)
		if len(v) > 0 {
			// No slog.Debug here: on the hot path its variadic args allocate even
			// when the level is disabled. This is the one intentional allocation.
			return string(v)
		}
	}
	return packetIp
}

// buildProtobufHeadersFast builds the protobuf header map from parsed headers,
// mirroring convertHeaders' Protobuf map: lowercase keys, single-element Values,
// last-wins on duplicate names. A wire Host header lands under "host" (lowercased),
// matching legacy's explicit host entry.
func buildProtobufHeadersFast(hs []fastparser.Header) map[string]*trafficpb.StringList {
	m := make(map[string]*trafficpb.StringList, len(hs))
	for i := range hs {
		m[strings.ToLower(string(hs[i].Name))] = &trafficpb.StringList{Values: []string{string(hs[i].Value)}}
	}
	return m
}

// fastStatus builds the "<code> <reason>" status string (reason omitted if empty).
func fastStatus(code int, reason []byte) string {
	if len(reason) > 0 {
		return strconv.Itoa(code) + " " + string(reason)
	}
	return strconv.Itoa(code)
}

// buildProtobufPayloadFast is the zero-net/http counterpart of buildProtobufPayload
// for the fast path. sourceIp is the resolved client IP (getSourceIpFast) — the
// threat payload uses the resolved IP, unlike the JSON payload's raw packet IP.
func buildProtobufPayloadFast(req *fastparser.Request, resp *fastparser.Response, ctx TrafficContext, sourceIp string) *trafficpb.HttpResponseParam {
	return &trafficpb.HttpResponseParam{
		Method:          string(req.Method),
		Path:            string(req.Path),
		Type:            string(req.Version),
		RequestHeaders:  buildProtobufHeadersFast(req.Headers),
		ResponseHeaders: buildProtobufHeadersFast(resp.Headers),
		RequestPayload:  string(req.Body),
		ResponsePayload: string(resp.Body),
		Ip:              sourceIp,
		DestIp:          ctx.DestIP,
		Time:            int32(time.Now().Unix()),
		StatusCode:      int32(resp.StatusCode),
		Status:          fastStatus(resp.StatusCode, resp.Reason),
		AktoAccountId:   fmt.Sprint(1000000),
		AktoVxlanId:     fmt.Sprint(ctx.VxlanID),
		IsPending:       ctx.IsPending,
		Source:          ctx.TrafficSource,
	}
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
		"process_name": PodInformerInstance.GetProcessNameByProcessId(int32(input.Context.ProcessID)),
		"enable_graph":    fmt.Sprint(utils.EnableGraph),
	}
}

func resolvePodLabelsTag(ctx TrafficContext, processName, url, host string) string {

	if PodInformerInstance == nil {
		checkDebugUrlAndPrint(url, host, "Pod labels not resolved, PodInformerInstance is nil")
		return ""
	}

	// On outbound traffic ctx.HostName is the pod that MADE the call, so the labels below
	// identify the caller, not the service being called. mini-runtime tells the two apart by the
	// "direction" field: it never routes collections by labels on outbound, and reads them only
	// to attribute the call to its calling service.
	//
	// Off by default: deployments without a tag whitelist would otherwise pick these up as
	// collection tags on the callee, one per calling service.
	if ctx.Direction == utils.DirectionOutbound && !utils.ResolveOutboundPodLabels {
		checkDebugUrlAndPrint(url, host, fmt.Sprintf("Pod labels not resolved for outbound request, podName: %s, direction: %v", ctx.HostName, ctx.Direction))
		return ""
	}

	if strings.Contains(processName, "envoy") {
		checkDebugUrlAndPrint(url, host, fmt.Sprintf("Pod labels not resolved for envoy request, podName: %s, direction: %v", ctx.HostName, ctx.Direction))
		return ""
	}

	if ctx.HostName == "" {
		checkDebugUrlAndPrint(url, host, "Failed to resolve pod name, hostName is empty for processId "+fmt.Sprint(ctx.ProcessID))
		slog.Debug("Failed to resolve pod name, hostName is empty for ", "processId", ctx.ProcessID, "hostName", ctx.HostName)
		return ""
	}

	podLabels, err := PodInformerInstance.ResolvePodLabels(ctx.HostName, url, host)
	if err != nil {
		slog.Error("Failed to resolve pod labels", "hostName", ctx.HostName, "error", err)
		checkDebugUrlAndPrint(url, host, "Error resolving pod labels "+ctx.HostName)
		return ""
	}

	checkDebugUrlAndPrint(url, host, "Pod labels found in ParseAndProduce, podLabels found "+fmt.Sprint(podLabels)+" for hostName "+ctx.HostName)
	return podLabels
}

func mergeInjectTags(existing string) string {
	if len(injectTagsMap) == 0 {
		return existing
	}

	merged := map[string]string{}
	for k, v := range injectTagsMap {
		merged[k] = v
	}

	// Parse and merge any existing tag JSON (e.g. from pod labels)
	if existing != "" {
		podLabelMap := map[string]string{}
		if err := json.Unmarshal([]byte(existing), &podLabelMap); err == nil {
			for k, v := range podLabelMap {
				merged[k] = v // pod labels overwrite inject tags on conflict
			}
		}
	}

	if b, err := json.Marshal(merged); err == nil {
		return string(b)
	}
	return existing
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
