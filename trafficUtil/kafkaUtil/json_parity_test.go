package kafkaUtil

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"testing"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/fastparser"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

// This test feeds identical raw request/response bytes through the legacy path
// (net/http -> convertHeaders -> buildJSONPayload -> json.Marshal) and the fast
// path (fastparser -> JSONEncoder) and diffs the resulting Kafka JSON. It exists
// to pin down where the two shapes differ so the fast path can be made
// wire-compatible. Volatile fields (time) are excluded.
//
// Known/expected divergences it will surface today:
//   - requestHeaders/responseHeaders: legacy emits a JSON-encoded STRING, the
//     fast path emits a nested OBJECT (logged, not failed — the fix is pending).
//   - header content differences (host key, headers net/http strips) are compared
//     on the normalized header maps and reported as failures.

// legacyJSON reproduces the production legacy payload for one pair.
func legacyJSON(t *testing.T, rawReq, rawResp []byte, ctx TrafficContext) map[string]any {
	t.Helper()
	reqR, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(rawReq)))
	if err != nil {
		t.Fatalf("legacy ReadRequest: %v", err)
	}
	reqBody, _ := io.ReadAll(reqR.Body)
	reqR.Body.Close()

	respR, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(rawResp)), reqR)
	if err != nil {
		t.Fatalf("legacy ReadResponse: %v", err)
	}
	respBody, _ := io.ReadAll(respR.Body)
	respR.Body.Close()

	headers := convertHeaders(reqR, respR, false)
	input := PayloadInput{
		Request:      reqR,
		Response:     respR,
		Headers:      headers,
		RequestBody:  string(reqBody),
		ResponseBody: string(respBody),
		SourceIP:     GetSourceIp(headers.Request.Protobuf, ctx.SourceIP),
		Context:      ctx,
	}
	value := buildJSONPayload(input)
	processName := PodInformerInstance.GetProcessNameByProcessId(int32(ctx.ProcessID))
	if tag := mergeInjectTags(resolvePodLabelsTag(ctx, processName, reqR.URL.String(), reqR.Host)); tag != "" {
		value["tag"] = tag
	}

	out, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("legacy marshal: %v", err)
	}
	return unmarshal(t, out)
}

// fastJSON reproduces the production fast-path payload for one pair (mirrors
// fastParseAndProduce's meta construction).
func fastJSON(t *testing.T, rawReq, rawResp []byte, ctx TrafficContext) map[string]any {
	t.Helper()
	p := fastparser.NewFastParser()
	freq, err := p.ParseRequest(rawReq)
	if err != nil {
		t.Fatalf("fast ParseRequest: %v", err)
	}
	fresp, err := p.ParseResponse(rawResp)
	if err != nil {
		t.Fatalf("fast ParseResponse: %v", err)
	}

	host := string(freq.Host())
	processName := PodInformerInstance.GetProcessNameByProcessId(int32(ctx.ProcessID))
	meta := &fastparser.Meta{
		SourceIP:      ctx.SourceIP, // mirrors legacy JSON "ip" (raw packet IP)
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
		Tag:           mergeInjectTags(resolvePodLabelsTag(ctx, processName, string(freq.Path), host)),
	}
	out := fastparser.NewJSONEncoder().Encode(freq, fresp, meta)
	return unmarshal(t, out)
}

func unmarshal(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal %s: %v", b, err)
	}
	return m
}

// toHeaderMap decodes a headers field (either a JSON-encoded string as legacy
// emits, or a nested object as the fast path currently emits) into a map, keeping
// keys EXACTLY as each version wrote them — no lowercasing. We compare the raw
// output of the two encoders, not what downstream would make of it.
func toHeaderMap(t *testing.T, v any) map[string]string {
	t.Helper()
	m := map[string]string{}
	switch x := v.(type) {
	case string:
		if x == "" {
			return m
		}
		raw := map[string]any{}
		if err := json.Unmarshal([]byte(x), &raw); err != nil {
			t.Fatalf("header string not JSON: %q: %v", x, err)
		}
		for k, val := range raw {
			m[k] = fmt.Sprint(val)
		}
	case map[string]any:
		for k, val := range x {
			m[k] = fmt.Sprint(val)
		}
	default:
		t.Fatalf("unexpected header field type %T", v)
	}
	return m
}

func compareHeaders(t *testing.T, field string, legacy, fast any) {
	t.Helper()

	// Both versions must emit the field as a JSON-encoded string (the downstream
	// consumer casts it to String and re-parses it).
	if _, ok := legacy.(string); !ok {
		t.Errorf("[%s] legacy must be a JSON string, got %T", field, legacy)
	}
	if _, ok := fast.(string); !ok {
		t.Errorf("[%s] fast must be a JSON string, got %T", field, fast)
	}

	lm := toHeaderMap(t, legacy)
	fm := toHeaderMap(t, fast)

	for k, lv := range lm {
		fv, ok := fm[k]
		if !ok {
			t.Errorf("[%s] key %q present in legacy, MISSING in fast (legacy=%q)", field, k, lv)
			continue
		}
		if lv != fv {
			t.Errorf("[%s] key %q value differs: legacy=%q fast=%q", field, k, lv, fv)
		}
	}
	// Extra headers in the fast path (hop-by-hop headers net/http strips, e.g.
	// Connection) are accepted, so this is logged, not failed.
	for k, fv := range fm {
		if _, ok := lm[k]; !ok {
			t.Logf("[%s] key %q EXTRA in fast (fast=%q), absent in legacy — allowed", field, k, fv)
		}
	}
}

func compareScalars(t *testing.T, legacy, fast map[string]any) {
	t.Helper()
	keys := map[string]struct{}{}
	for k := range legacy {
		keys[k] = struct{}{}
	}
	for k := range fast {
		keys[k] = struct{}{}
	}
	ordered := make([]string, 0, len(keys))
	for k := range keys {
		ordered = append(ordered, k)
	}
	sort.Strings(ordered)

	for _, k := range ordered {
		switch k {
		case "time": // volatile
			continue
		case "requestHeaders", "responseHeaders":
			continue // handled separately
		}
		lv, lok := legacy[k]
		fv, fok := fast[k]
		if lok != fok {
			t.Errorf("field %q presence differs: legacyPresent=%v fastPresent=%v (legacy=%v fast=%v)", k, lok, fok, lv, fv)
			continue
		}
		if fmt.Sprint(lv) != fmt.Sprint(fv) {
			t.Errorf("field %q value differs: legacy=%q fast=%q", k, fmt.Sprint(lv), fmt.Sprint(fv))
		}
	}
}

func TestJSONShapeParity(t *testing.T) {
	ctx := TrafficContext{
		SourceIP:            "9.9.9.9",
		DestIP:              "8.8.8.8",
		VxlanID:             42,
		IsPending:           false,
		TrafficSource:       "MIRRORING",
		Direction:           utils.DirectionInbound,
		ProcessID:           123,
		SocketFD:            7,
		DaemonsetIdentifier: "ds-1",
		HostName:            "",
	}

	tests := []struct {
		name    string
		rawReq  string
		rawResp string
	}{
		{
			name: "simple GET no body",
			rawReq: "GET /?request-num=9 HTTP/1.1\r\n" +
				"Host: localhost:8888\r\n" +
				"User-Agent: test-agent\r\n" +
				"X-Forwarded-For: 1.2.3.4\r\n" +
				"\r\n",
			rawResp: "HTTP/1.1 200 OK\r\n" +
				"Content-Type: application/json\r\n" +
				"Content-Length: 2\r\n" +
				"\r\n{}",
		},
		{
			name: "POST with body and content-length",
			rawReq: "POST /submit HTTP/1.1\r\n" +
				"Host: api.example.com\r\n" +
				"Content-Type: application/json\r\n" +
				"Content-Length: 13\r\n" +
				"\r\n{\"a\":\"hello\"}",
			rawResp: "HTTP/1.1 201 Created\r\n" +
				"Content-Type: application/json\r\n" +
				"Content-Length: 4\r\n" +
				"\r\ntrue",
		},
		{
			name: "connection and transfer-encoding-ish headers",
			rawReq: "GET /x HTTP/1.1\r\n" +
				"Host: h.example.com\r\n" +
				"Connection: keep-alive\r\n" +
				"Accept: */*\r\n" +
				"\r\n",
			rawResp: "HTTP/1.1 204 No Content\r\n" +
				"Connection: close\r\n" +
				"\r\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			legacy := legacyJSON(t, []byte(tc.rawReq), []byte(tc.rawResp), ctx)
			fast := fastJSON(t, []byte(tc.rawReq), []byte(tc.rawResp), ctx)

			compareScalars(t, legacy, fast)
			compareHeaders(t, "requestHeaders", legacy["requestHeaders"], fast["requestHeaders"])
			compareHeaders(t, "responseHeaders", legacy["responseHeaders"], fast["responseHeaders"])
		})
	}
}
