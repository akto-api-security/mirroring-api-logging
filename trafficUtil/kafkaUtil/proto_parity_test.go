package kafkaUtil

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/fastparser"
	trafficpb "github.com/akto-api-security/mirroring-api-logging/trafficUtil/protobuf/traffic_payload"
)

// This test feeds identical raw request/response bytes through the legacy
// protobuf builder (net/http -> convertHeaders -> buildProtobufPayload) and the
// fast one (fastparser -> buildProtobufPayloadFast) and compares the resulting
// *trafficpb.HttpResponseParam field-by-field. Volatile Time is excluded; the
// same resolved source IP is passed to both to isolate payload construction.

func legacyProto(t *testing.T, rawReq, rawResp []byte, ctx TrafficContext, srcIP string) *trafficpb.HttpResponseParam {
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
	return buildProtobufPayload(PayloadInput{
		Request:      reqR,
		Response:     respR,
		Headers:      headers,
		RequestBody:  string(reqBody),
		ResponseBody: string(respBody),
		SourceIP:     srcIP,
		Context:      ctx,
	})
}

func fastProto(t *testing.T, rawReq, rawResp []byte, ctx TrafficContext, srcIP string) *trafficpb.HttpResponseParam {
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
	return buildProtobufPayloadFast(freq, fresp, ctx, srcIP)
}

// compareProtoHeaders: every legacy header must be present in fast with the same
// value; extra headers in fast (hop-by-hop that net/http strips) are allowed.
func compareProtoHeaders(t *testing.T, field string, legacy, fast map[string]*trafficpb.StringList) {
	t.Helper()
	val := func(m map[string]*trafficpb.StringList, k string) (string, bool) {
		v, ok := m[k]
		if !ok || v == nil || len(v.Values) == 0 {
			return "", ok
		}
		return v.Values[0], true
	}
	for k, lv := range legacy {
		want := ""
		if len(lv.Values) > 0 {
			want = lv.Values[0]
		}
		got, ok := val(fast, k)
		if !ok {
			t.Errorf("[%s] key %q in legacy, MISSING in fast (legacy=%q)", field, k, want)
			continue
		}
		if got != want {
			t.Errorf("[%s] key %q value differs: legacy=%q fast=%q", field, k, want, got)
		}
	}
	for k := range fast {
		if _, ok := legacy[k]; !ok {
			g, _ := val(fast, k)
			t.Logf("[%s] key %q EXTRA in fast (%q) — allowed (hop-by-hop)", field, k, g)
		}
	}
}

func TestProtoShapeParity(t *testing.T) {
	ctx := TrafficContext{
		DestIP:        "8.8.8.8",
		VxlanID:       42,
		IsPending:     false,
		TrafficSource: "MIRRORING",
	}
	const srcIP = "1.2.3.4"

	tests := []struct {
		name    string
		rawReq  string
		rawResp string
	}{
		{
			name:    "GET no body",
			rawReq:  "GET /?q=9 HTTP/1.1\r\nHost: localhost:8888\r\nUser-Agent: ua\r\nX-Forwarded-For: 1.2.3.4\r\n\r\n",
			rawResp: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
		},
		{
			name:    "POST with body",
			rawReq:  "POST /submit HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"a\":\"hello\"}",
			rawResp: "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 4\r\n\r\ntrue",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l := legacyProto(t, []byte(tc.rawReq), []byte(tc.rawResp), ctx, srcIP)
			f := fastProto(t, []byte(tc.rawReq), []byte(tc.rawResp), ctx, srcIP)

			scalars := []struct {
				name             string
				legacy, fast any
			}{
				{"Method", l.Method, f.Method},
				{"Path", l.Path, f.Path},
				{"Type", l.Type, f.Type},
				{"RequestPayload", l.RequestPayload, f.RequestPayload},
				{"ResponsePayload", l.ResponsePayload, f.ResponsePayload},
				{"Ip", l.Ip, f.Ip},
				{"DestIp", l.DestIp, f.DestIp},
				{"StatusCode", l.StatusCode, f.StatusCode},
				{"Status", l.Status, f.Status},
				{"AktoAccountId", l.AktoAccountId, f.AktoAccountId},
				{"AktoVxlanId", l.AktoVxlanId, f.AktoVxlanId},
				{"IsPending", l.IsPending, f.IsPending},
				{"Source", l.Source, f.Source},
			}
			for _, s := range scalars {
				if fmt.Sprint(s.legacy) != fmt.Sprint(s.fast) {
					t.Errorf("field %q differs: legacy=%v fast=%v", s.name, s.legacy, s.fast)
				}
			}

			compareProtoHeaders(t, "RequestHeaders", l.RequestHeaders, f.RequestHeaders)
			compareProtoHeaders(t, "ResponseHeaders", l.ResponseHeaders, f.ResponseHeaders)
		})
	}
}
