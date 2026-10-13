package kafkaUtil

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/fastparser"
	trafficpb "github.com/akto-api-security/mirroring-api-logging/trafficUtil/protobuf/traffic_payload"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/trafficMetrics"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

// Zero-copy parse + hand-rolled JSON encode path (AKTO_FAST_PARSER=true).
// Assumes roughly one request and one response per buffer; if Content-Length
// shows leftover bytes (multi-message flush), the caller falls back to net/http.

var parserPool = sync.Pool{New: func() any { return fastparser.NewFastParser() }}
var encoderPool = sync.Pool{New: func() any { return fastparser.NewJSONEncoder() }}

var fastPrinted atomic.Int64

// tryFastParseAndProduce runs the fast path. Returns false when the caller
// should use the legacy ParseAndProduce body instead.
func tryFastParseAndProduce(receiveBuffer, sentBuffer []byte, ctx TrafficContext) bool {
	if !utils.FastParser {
		return false
	}
	if KafkaDisabled() {
		return true // nothing to produce; treat as handled
	}

	p := parserPool.Get().(*fastparser.Parser)
	defer parserPool.Put(p)
	p.Gunzip = utils.FastParserGunzip
	p.HandleChunkEncoding = utils.FastParserChunkEncoding

	req, err := p.ParseRequest(receiveBuffer)
	if err != nil {
		return false
	}
	if !singleMessageBody(req.Headers, req.Body) {
		return false
	}

	resp, err := p.ParseResponse(sentBuffer)
	if err != nil {
		if errors.Is(err, fastparser.ErrGunzip) {
			// Soft failure: keep pair with empty response body.
		} else {
			return false
		}
	}
	if resp != nil && !singleMessageBody(resp.Headers, resp.Body) {
		return false
	}

	host := string(req.Host())
	reqHeaderMap := headersToStringMap(req.Headers)
	if !shouldProcessRequestFast(string(req.Method), host, reqHeaderMap, ctx) {
		return true
	}

	processName := ""
	if PodInformerInstance != nil {
		processName = PodInformerInstance.GetProcessNameByProcessId(int32(ctx.ProcessID))
	}

	enc := encoderPool.Get().(*fastparser.JSONEncoder)
	defer encoderPool.Put(enc)

	meta := &fastparser.Meta{
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
		Tag:           mergeInjectTagsString(resolvePodLabelsTag(ctx, processName, string(req.Path), host)),
	}

	out := enc.Encode(req, resp, meta)

	if checkAndUpdateBandwidthProcessed(len(out)) {
		return true
	}

	if n := fastPrinted.Add(1); n <= 10 {
		slog.Info("AKTO_FAST_PARSER sample", "n", n, "payload", string(out))
	}

	path := string(req.Path)
	method := string(req.Method)
	go ProduceStr(context.Background(), string(out), path, host, method)

	if utils.ThreatEnabled {
		srcIP := getSourceIpFast(req, ctx.SourceIP)
		go Produce(context.Background(), buildProtobufPayloadFast(req, resp, ctx, srcIP))
	}

	checkDebugUrlAndPrint(path, host, "URL,host found in fastParseAndProduce")
	return true
}

// singleMessageBody reports whether body length matches Content-Length when set.
// If the buffer clearly contains more than one message, returns false so we fall back.
func singleMessageBody(hs []fastparser.Header, body []byte) bool {
	cl := headerValueBytes(hs, "Content-Length")
	if cl == nil {
		return true
	}
	n, err := strconv.Atoi(string(bytes.TrimSpace(cl)))
	if err != nil || n < 0 {
		return true
	}
	// Extra bytes after the declared body ⇒ likely another pipelined message.
	return len(body) <= n
}

func headerValueBytes(hs []fastparser.Header, name string) []byte {
	for i := range hs {
		if asciiEqualFoldHeader(hs[i].Name, name) {
			return hs[i].Value
		}
	}
	return nil
}

func asciiEqualFoldHeader(b []byte, s string) bool {
	if len(b) != len(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		c1, c2 := b[i], s[i]
		if 'A' <= c1 && c1 <= 'Z' {
			c1 += 'a' - 'A'
		}
		if 'A' <= c2 && c2 <= 'Z' {
			c2 += 'a' - 'A'
		}
		if c1 != c2 {
			return false
		}
	}
	return true
}

func headersToStringMap(hs []fastparser.Header) map[string]string {
	m := make(map[string]string, len(hs))
	for i := range hs {
		m[strings.ToLower(string(hs[i].Name))] = string(hs[i].Value)
	}
	return m
}

func shouldProcessRequestFast(method, host string, reqHeaders map[string]string, ctx TrafficContext) bool {
	if !IsValidMethod(method) {
		return false
	}
	if !utils.PassesFilter(trafficMetrics.FilterHeaderValueMap, reqHeaders) {
		return false
	}
	if utils.IgnoreIpTraffic && utils.CheckIfIp(host) {
		return false
	}
	if utils.IgnoreCloudMetadataCalls && host == "169.254.169.254" {
		return false
	}
	if utils.IgnoreEnvoyProxycalls && ctx.SourceIP == utils.EnvoyProxyIp && ctx.Direction == utils.DirectionOutbound {
		return false
	}
	if utils.FilterPacket(reqHeaders) {
		return false
	}
	return true
}

func getSourceIpFast(req *fastparser.Request, packetIp string) string {
	for _, header := range CLIENT_IP_HEADERS {
		v := req.Header(header)
		if v == nil {
			continue
		}
		if end := bytes.IndexByte(v, ','); end >= 0 {
			v = v[:end]
		}
		v = bytes.TrimSpace(v)
		if len(v) > 0 {
			return string(v)
		}
	}
	return packetIp
}

func buildProtobufHeadersFast(hs []fastparser.Header) map[string]*trafficpb.StringList {
	m := make(map[string]*trafficpb.StringList, len(hs))
	for i := range hs {
		m[strings.ToLower(string(hs[i].Name))] = &trafficpb.StringList{Values: []string{string(hs[i].Value)}}
	}
	return m
}

func fastStatus(code int, reason []byte) string {
	if len(reason) > 0 {
		return strconv.Itoa(code) + " " + string(reason)
	}
	return strconv.Itoa(code)
}

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

func resolvePodLabelsTag(ctx TrafficContext, processName, url, host string) string {
	if PodInformerInstance == nil {
		return ""
	}
	if ctx.Direction == utils.DirectionOutbound {
		return ""
	}
	if strings.Contains(processName, "envoy") {
		return ""
	}
	if ctx.HostName == "" {
		return ""
	}
	podLabels, err := PodInformerInstance.ResolvePodLabels(ctx.HostName, url, host)
	if err != nil {
		slog.Error("Failed to resolve pod labels", "hostName", ctx.HostName, "error", err)
		return ""
	}
	return podLabels
}

func mergeInjectTagsString(existing string) string {
	if len(injectTagsMap) == 0 {
		return existing
	}
	merged := map[string]string{}
	for k, v := range injectTagsMap {
		merged[k] = v
	}
	if existing != "" {
		podLabelMap := map[string]string{}
		if err := json.Unmarshal([]byte(existing), &podLabelMap); err == nil {
			for k, v := range podLabelMap {
				merged[k] = v
			}
		}
	}
	if b, err := json.Marshal(merged); err == nil {
		return string(b)
	}
	return existing
}
