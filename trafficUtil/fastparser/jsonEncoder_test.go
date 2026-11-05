package fastparser

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
)

func jsonSampleMeta() *Meta {
	return &Meta{
		SourceIP: "10.0.0.1", DestIP: "10.0.0.2", TimeUnix: 1690000000,
		AktoAccountID: "1000000", VxlanID: 42, IsPending: false, Source: "MIRRORING",
		Direction: 1, ProcessID: 1234, SocketID: 7, DaemonsetID: "ds-1",
		ProcessName: "svc", EnableGraph: true, Tag: `{"env":"prod"}`,
	}
}

// encodeToMap encodes and unmarshals the output into a generic map. It fails the
// test if the encoder produced invalid JSON.
func encodeToMap(t *testing.T, enc *JSONEncoder, req *Request, resp *Response, m *Meta) map[string]any {
	t.Helper()
	out := enc.Encode(req, resp, m)
	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatalf("encoder produced invalid JSON: %v\nout=%q", err, out)
	}
	return v
}

// headerMapOf decodes a header field (a JSON-encoded string) into a map.
func headerMapOf(t *testing.T, v any) map[string]any {
	t.Helper()
	s, ok := v.(string)
	if !ok {
		t.Fatalf("header field must be a JSON string, got %T (%v)", v, v)
	}
	m := map[string]any{}
	if s == "" {
		return m
	}
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("header field is not a JSON-encoded object: %q: %v", s, err)
	}
	return m
}

// ---- Tier 1: escaping, double-encoding, buffer reuse ----

// TestJSONEncodeEscaping covers the appendJSONEscaped paths: control chars,
// quotes/backslashes, and invalid UTF-8 (replaced with U+FFFD), plus the
// double-escaping of a quote inside a header value.
func TestJSONEncodeEscaping(t *testing.T) {
	req := &Request{
		Method:  []byte("POST"),
		Path:    []byte("/p"),
		Version: []byte("HTTP/1.1"),
		Headers: []Header{
			{Name: []byte("Host"), Value: []byte("h.example.com")},
			{Name: []byte("X-Quote"), Value: []byte(`a"b\c` + "\td")},
		},
		Body: []byte("line1\nline2\ttab\"quote\\back"),
	}
	resp := &Response{
		Version:    []byte("HTTP/1.1"),
		StatusCode: 200,
		Reason:     []byte("OK"),
		Body:       []byte{0xff, 0xfe, 'x'}, // invalid UTF-8 followed by a valid byte
	}

	v := encodeToMap(t, NewJSONEncoder(), req, resp, jsonSampleMeta())

	// Control chars / quotes / backslashes in the body round-trip exactly.
	if got := v["requestPayload"]; got != "line1\nline2\ttab\"quote\\back" {
		t.Errorf("requestPayload round-trip failed: %q", got)
	}
	// Invalid UTF-8 bytes each become U+FFFD; the trailing valid byte survives.
	if got := v["responsePayload"]; got != "��"+"x" {
		t.Errorf("invalid UTF-8 not replaced with U+FFFD: %q", got)
	}
	// Header value with a quote+backslash+tab survives BOTH escape layers.
	hm := headerMapOf(t, v["requestHeaders"])
	if got := hm["X-Quote"]; got != `a"b\c`+"\td" {
		t.Errorf("header value lost through double-encoding: %q", got)
	}
}

// TestJSONEncodeHostLowercasing verifies the request Host key is emitted as
// "host" while a response Host (if present) keeps its wire case.
func TestJSONEncodeHostLowercasing(t *testing.T) {
	req := &Request{
		Method: []byte("GET"), Path: []byte("/"), Version: []byte("HTTP/1.1"),
		Headers: []Header{{Name: []byte("Host"), Value: []byte("h.example.com")}},
	}
	resp := &Response{
		Version: []byte("HTTP/1.1"), StatusCode: 200, Reason: []byte("OK"),
		Headers: []Header{{Name: []byte("Host"), Value: []byte("srv")}},
	}
	v := encodeToMap(t, NewJSONEncoder(), req, resp, jsonSampleMeta())

	reqH := headerMapOf(t, v["requestHeaders"])
	if _, ok := reqH["host"]; !ok {
		t.Errorf("request Host not lowercased to \"host\": %v", reqH)
	}
	if _, ok := reqH["Host"]; ok {
		t.Errorf("request retained title-case \"Host\": %v", reqH)
	}
	respH := headerMapOf(t, v["responseHeaders"])
	if _, ok := respH["Host"]; !ok {
		t.Errorf("response Host should keep wire case: %v", respH)
	}
}

// TestJSONEncodeTagOmitted checks Tag is present only when non-empty.
func TestJSONEncodeTagOmitted(t *testing.T) {
	req := &Request{Method: []byte("GET"), Path: []byte("/"), Version: []byte("HTTP/1.1")}
	resp := &Response{Version: []byte("HTTP/1.1"), StatusCode: 200, Reason: []byte("OK")}

	m := jsonSampleMeta()
	m.Tag = ""
	if v := encodeToMap(t, NewJSONEncoder(), req, resp, m); v["tag"] != nil {
		t.Errorf("empty Tag should be omitted, got %v", v["tag"])
	}

	m.Tag = `{"x":"y"}`
	if v := encodeToMap(t, NewJSONEncoder(), req, resp, m); v["tag"] != `{"x":"y"}` {
		t.Errorf("Tag not emitted verbatim: %v", v["tag"])
	}
}

// TestJSONEncodeBufferReuse ensures reusing an encoder for a smaller message
// doesn't leak stale bytes from a previous larger one, and that copied outputs
// stay valid across subsequent Encode calls.
func TestJSONEncodeBufferReuse(t *testing.T) {
	enc := NewJSONEncoder()
	m := jsonSampleMeta()
	resp := &Response{Version: []byte("HTTP/1.1"), StatusCode: 200, Reason: []byte("OK")}

	many := &Request{Method: []byte("GET"), Path: []byte("/"), Version: []byte("HTTP/1.1")}
	for i := 0; i < 8; i++ {
		many.Headers = append(many.Headers, Header{Name: []byte(fmt.Sprintf("X-%d", i)), Value: []byte("value")})
	}
	first := string(enc.Encode(many, resp, m)) // copy before reuse

	few := &Request{
		Method: []byte("GET"), Path: []byte("/"), Version: []byte("HTTP/1.1"),
		Headers: []Header{{Name: []byte("Host"), Value: []byte("h")}},
	}
	v := encodeToMap(t, enc, few, resp, m)
	hm := headerMapOf(t, v["requestHeaders"])
	if len(hm) != 1 {
		t.Fatalf("stale headers leaked from previous Encode: %v", hm)
	}

	// The earlier copied string must be unaffected and still valid JSON.
	var fv map[string]any
	if err := json.Unmarshal([]byte(first), &fv); err != nil {
		t.Fatalf("earlier output corrupted after reuse: %v", err)
	}
	if fh := headerMapOf(t, fv["requestHeaders"]); len(fh) != 8 {
		t.Fatalf("earlier output header count changed: got %d want 8", len(fh))
	}
}

// FuzzJSONEncode asserts the encoder's headline guarantee: for any input that
// parses, Encode produces valid JSON whose header fields are themselves valid
// JSON-encoded strings.
func FuzzJSONEncode(f *testing.F) {
	for _, s := range sizes {
		f.Add(readFix("req-"+s+".bin"), readFix("resp-"+s+".bin"))
	}
	f.Add([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\n\r\n"))
	m := jsonSampleMeta()

	f.Fuzz(func(t *testing.T, reqBuf, respBuf []byte) {
		req, err := NewFastParser().ParseRequest(reqBuf)
		if err != nil {
			return
		}
		resp, err := NewFastParser().ParseResponse(respBuf)
		if err != nil {
			return
		}
		out := NewJSONEncoder().Encode(req, resp, m)

		var v map[string]any
		if err := json.Unmarshal(out, &v); err != nil {
			t.Fatalf("invalid JSON: %v\nout=%q", err, out)
		}
		for _, k := range []string{"requestHeaders", "responseHeaders"} {
			s, ok := v[k].(string)
			if !ok {
				t.Fatalf("%s must be a JSON string, got %T", k, v[k])
			}
			var hm map[string]any
			if err := json.Unmarshal([]byte(s), &hm); err != nil {
				t.Fatalf("%s inner is not valid JSON: %v\n%q", k, err, s)
			}
		}
	})
}

// ---- Tier 3: edges + concurrency ----

// TestJSONEncodeEmpties covers empty headers, empty body, and an empty reason.
func TestJSONEncodeEmpties(t *testing.T) {
	req := &Request{Method: []byte("GET"), Path: []byte("/"), Version: []byte("HTTP/1.1")} // no headers, no body
	resp := &Response{Version: []byte("HTTP/1.1"), StatusCode: 204}                        // no reason, no headers, no body

	v := encodeToMap(t, NewJSONEncoder(), req, resp, jsonSampleMeta())

	if v["requestHeaders"] != "{}" {
		t.Errorf("empty request headers should be \"{}\", got %q", v["requestHeaders"])
	}
	if v["responseHeaders"] != "{}" {
		t.Errorf("empty response headers should be \"{}\", got %q", v["responseHeaders"])
	}
	if v["requestPayload"] != "" {
		t.Errorf("empty body should be \"\", got %q", v["requestPayload"])
	}
	if v["status"] != "204" { // no trailing space when reason is empty
		t.Errorf("status with empty reason should be \"204\", got %q", v["status"])
	}
}

// TestJSONEncodeMissingHost confirms no host key appears when there's no Host header.
func TestJSONEncodeMissingHost(t *testing.T) {
	req := &Request{
		Method: []byte("GET"), Path: []byte("/"), Version: []byte("HTTP/1.1"),
		Headers: []Header{{Name: []byte("Accept"), Value: []byte("*/*")}},
	}
	resp := &Response{Version: []byte("HTTP/1.1"), StatusCode: 200, Reason: []byte("OK")}
	v := encodeToMap(t, NewJSONEncoder(), req, resp, jsonSampleMeta())
	if hm := headerMapOf(t, v["requestHeaders"]); hm["host"] != nil {
		t.Errorf("no host header should mean no \"host\" key, got %v", hm["host"])
	}
}

// TestJSONEncodeConcurrent runs many encoders, one per goroutine (the documented
// contract), producing the same input; each must yield identical valid output.
// Run with -race to catch accidental shared state.
func TestJSONEncodeConcurrent(t *testing.T) {
	req := &Request{
		Method: []byte("POST"), Path: []byte("/x"), Version: []byte("HTTP/1.1"),
		Headers: []Header{{Name: []byte("Host"), Value: []byte("h")}, {Name: []byte("Accept"), Value: []byte("*/*")}},
		Body:    []byte(`{"k":"v"}`),
	}
	resp := &Response{Version: []byte("HTTP/1.1"), StatusCode: 200, Reason: []byte("OK"), Body: []byte("ok")}
	m := jsonSampleMeta()
	want := string(NewJSONEncoder().Encode(req, resp, m))

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			enc := NewJSONEncoder()
			for i := 0; i < 1000; i++ {
				if got := string(enc.Encode(req, resp, m)); got != want {
					t.Errorf("per-goroutine encoder produced divergent output")
					return
				}
			}
		}()
	}
	wg.Wait()
}

// ---- Benchmarks ----

// BenchmarkJSONEncode: single-core encode throughput (parse-once), M/s + GiB/s.
func BenchmarkJSONEncode(b *testing.B) {
	m := jsonSampleMeta()
	for _, s := range sizes {
		req, resp, inBytes := fbParse(b, s)
		enc := NewJSONEncoder()
		enc.Encode(req, resp, m) // warm
		b.Run(s, func(b *testing.B) {
			b.ReportAllocs()
			var n int64
			for i := 0; i < b.N; i++ {
				_ = len(enc.Encode(req, resp, m))
				n++
			}
			mps(b, n)
			gibps(b, n, inBytes)
		})
	}
}

// BenchmarkJSONEncodeParallel: all-cores encode throughput (one encoder/goroutine).
func BenchmarkJSONEncodeParallel(b *testing.B) {
	m := jsonSampleMeta()
	for _, s := range sizes {
		req, resp, inBytes := fbParse(b, s)
		b.Run(s, func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				enc := NewJSONEncoder()
				for pb.Next() {
					_ = len(enc.Encode(req, resp, m))
				}
			})
			mps(b, int64(b.N))
			gibps(b, int64(b.N), inBytes)
		})
	}
}
