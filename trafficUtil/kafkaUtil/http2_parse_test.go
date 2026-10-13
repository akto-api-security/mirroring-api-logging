package kafkaUtil

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// h2Writer builds raw HTTP/2 frames for one direction of a connection.
type h2Writer struct {
	buf    bytes.Buffer
	framer *http2.Framer
	hbuf   bytes.Buffer
	enc    *hpack.Encoder
}

func newH2Writer(withPreface bool) *h2Writer {
	w := &h2Writer{}
	if withPreface {
		w.buf.Write(http2Preface)
	}
	w.framer = http2.NewFramer(&w.buf, nil)
	w.enc = hpack.NewEncoder(&w.hbuf)
	w.framer.WriteSettings()
	return w
}

func (w *h2Writer) headers(t *testing.T, streamID uint32, endStream bool, kv ...string) {
	t.Helper()
	w.hbuf.Reset()
	for i := 0; i < len(kv); i += 2 {
		if err := w.enc.WriteField(hpack.HeaderField{Name: kv[i], Value: kv[i+1]}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: w.hbuf.Bytes(),
		EndStream:     endStream,
		EndHeaders:    true,
	}); err != nil {
		t.Fatal(err)
	}
}

func (w *h2Writer) data(t *testing.T, streamID uint32, endStream bool, payload []byte) {
	t.Helper()
	if err := w.framer.WriteData(streamID, endStream, payload); err != nil {
		t.Fatal(err)
	}
}

func TestIsHTTP2(t *testing.T) {
	if !IsHTTP2(append(append([]byte{}, http2Preface...), 0, 0, 0)) {
		t.Error("expected preface to be detected")
	}
	if IsHTTP2([]byte("GET / HTTP/1.1\r\n\r\n")) {
		t.Error("HTTP/1 request detected as HTTP/2")
	}
	if IsHTTP2(http2Preface[:10]) {
		t.Error("partial preface detected as HTTP/2")
	}
}

func TestParseHTTP2Traffic_Get(t *testing.T) {
	req := newH2Writer(true)
	req.headers(t, 1, true, ":method", "GET", ":scheme", "http", ":path", "/users?id=1", ":authority", "api.svc.local", "x-custom", "abc")

	resp := newH2Writer(false)
	resp.headers(t, 1, false, ":status", "200", "content-type", "application/json")
	resp.data(t, 1, true, []byte(`{"ok":true}`))

	parsed := parseHTTP2Traffic(req.buf.Bytes(), resp.buf.Bytes(), TrafficContext{})
	if parsed == nil || len(parsed.Requests) != 1 || len(parsed.Responses) != 1 {
		t.Fatalf("expected 1 pair, got %+v", parsed)
	}
	r, s := parsed.Requests[0], parsed.Responses[0]
	if r.Method != "GET" || r.URL.String() != "/users?id=1" || r.Host != "api.svc.local" || r.Proto != "HTTP/2.0" {
		t.Errorf("unexpected request: method=%s url=%s host=%s proto=%s", r.Method, r.URL, r.Host, r.Proto)
	}
	if r.Header["x-custom"][0] != "abc" {
		t.Errorf("missing request header, got %v", r.Header)
	}
	if s.StatusCode != 200 || s.Status != "200 OK" || s.Header["content-type"][0] != "application/json" {
		t.Errorf("unexpected response: code=%d status=%q headers=%v", s.StatusCode, s.Status, s.Header)
	}
	if got := parsed.ResponseBodies[0]; got != `{"ok":true}` {
		t.Errorf("expected plain-text response body, got: %s", got)
	}
}

func TestParseHTTP2Traffic_GzipResponse(t *testing.T) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte(`{"compressed":true}`))
	zw.Close()

	req := newH2Writer(true)
	req.headers(t, 1, false, ":method", "POST", ":scheme", "http", ":path", "/items", ":authority", "svc", "content-type", "application/json")
	req.data(t, 1, true, []byte(`{"id":1}`))

	resp := newH2Writer(false)
	resp.headers(t, 1, false, ":status", "200", "content-encoding", "gzip")
	resp.data(t, 1, true, gz.Bytes())

	parsed := parseHTTP2Traffic(req.buf.Bytes(), resp.buf.Bytes(), TrafficContext{})
	if parsed == nil || len(parsed.Requests) != 1 {
		t.Fatalf("expected 1 pair, got %+v", parsed)
	}
	if got := parsed.RequestBodies[0]; got != `{"id":1}` {
		t.Errorf("unexpected request body: %s", got)
	}
	if got := parsed.ResponseBodies[0]; got != `{"compressed":true}` {
		t.Errorf("expected gunzipped response body, got: %s", got)
	}
}

func TestParseHTTP2Traffic_GRPCUnary(t *testing.T) {
	msg := []byte{0x0a, 0x03, 'b', 'o', 'b'}
	grpcFrame := append([]byte{0, 0, 0, 0, byte(len(msg))}, msg...)

	req := newH2Writer(true)
	req.headers(t, 1, false, ":method", "POST", ":scheme", "http", ":path", "/helloworld.Greeter/SayHello", ":authority", "greeter:50051", "content-type", "application/grpc")
	req.data(t, 1, true, grpcFrame)

	resp := newH2Writer(false)
	resp.headers(t, 1, false, ":status", "200", "content-type", "application/grpc")
	resp.data(t, 1, false, grpcFrame)
	resp.headers(t, 1, true, "grpc-status", "0")

	parsed := parseHTTP2Traffic(req.buf.Bytes(), resp.buf.Bytes(), TrafficContext{})
	if parsed == nil || len(parsed.Requests) != 1 {
		t.Fatalf("expected 1 pair, got %+v", parsed)
	}
	if parsed.Requests[0].Proto != "gRPC" {
		t.Errorf("expected gRPC proto, got %s", parsed.Requests[0].Proto)
	}
	if parsed.Responses[0].Header["grpc-status"][0] != "0" {
		t.Errorf("expected grpc-status trailer, got %v", parsed.Responses[0].Header)
	}
	if got := parsed.RequestBodies[0]; got != base64.StdEncoding.EncodeToString(msg) {
		t.Errorf("request body still has gRPC prefix: %s", got)
	}
	if got := parsed.ResponseBodies[0]; got != base64.StdEncoding.EncodeToString(msg) {
		t.Errorf("unexpected response body: %s", got)
	}
}

func TestParseHTTP2Traffic_MultiplexedIncomplete(t *testing.T) {
	req := newH2Writer(true)
	req.headers(t, 1, true, ":method", "GET", ":scheme", "http", ":path", "/a", ":authority", "svc")
	req.headers(t, 3, true, ":method", "GET", ":scheme", "http", ":path", "/b", ":authority", "svc")

	resp := newH2Writer(false)
	resp.headers(t, 3, true, ":status", "404")
	resp.headers(t, 1, false, ":status", "200") // stream 1 never ends

	parsed := parseHTTP2Traffic(req.buf.Bytes(), resp.buf.Bytes(), TrafficContext{})
	if parsed == nil || len(parsed.Requests) != 1 {
		t.Fatalf("expected only the completed stream, got %+v", parsed)
	}
	if parsed.Requests[0].URL.Path != "/b" || parsed.Responses[0].StatusCode != 404 {
		t.Errorf("unexpected pair: path=%s status=%d", parsed.Requests[0].URL.Path, parsed.Responses[0].StatusCode)
	}
}

func TestParseHTTP2Traffic_TruncatedFrame(t *testing.T) {
	req := newH2Writer(true)
	req.headers(t, 1, true, ":method", "GET", ":scheme", "http", ":path", "/a", ":authority", "svc")
	req.headers(t, 3, true, ":method", "GET", ":scheme", "http", ":path", "/b", ":authority", "svc")

	resp := newH2Writer(false)
	resp.headers(t, 1, true, ":status", "200")
	resp.headers(t, 3, false, ":status", "200")
	resp.data(t, 3, true, []byte("partial body"))
	respBytes := resp.buf.Bytes()
	respBytes = respBytes[:len(respBytes)-5]

	parsed := parseHTTP2Traffic(req.buf.Bytes(), respBytes, TrafficContext{})
	if parsed == nil || len(parsed.Requests) != 1 || parsed.Requests[0].URL.Path != "/a" {
		t.Fatalf("expected stream parsed before truncation, got %+v", parsed)
	}
}

func TestParseHTTP2Traffic_NoCompleteStreams(t *testing.T) {
	req := newH2Writer(true)
	req.headers(t, 1, true, ":method", "GET", ":scheme", "http", ":path", "/a", ":authority", "svc")

	if parsed := parseHTTP2Traffic(req.buf.Bytes(), nil, TrafficContext{}); parsed != nil {
		t.Fatalf("expected nil, got %+v", parsed)
	}
}

func TestParseHTTP2Traffic_CookiesAndInterimResponse(t *testing.T) {
	req := newH2Writer(true)
	req.headers(t, 1, true, ":method", "GET", ":scheme", "https", ":path", "/me", ":authority", "svc", "cookie", "a=1", "cookie", "b=2")

	resp := newH2Writer(false)
	resp.headers(t, 1, false, ":status", "103", "link", "</x.css>; rel=preload")
	resp.headers(t, 1, true, ":status", "200")

	parsed := parseHTTP2Traffic(req.buf.Bytes(), resp.buf.Bytes(), TrafficContext{})
	if parsed == nil || len(parsed.Requests) != 1 {
		t.Fatalf("expected 1 pair, got %+v", parsed)
	}
	headers := convertHeaders(&parsed.Requests[0], &parsed.Responses[0], false)
	if got := headers.Request.StringMap["cookie"]; got != "a=1; b=2" {
		t.Errorf("expected all cookies, got %q", got)
	}
	if _, ok := headers.Response.StringMap["link"]; ok {
		t.Error("headers from the 103 interim response should not be kept")
	}
	payload := buildJSONPayload(PayloadInput{Request: &parsed.Requests[0], Response: &parsed.Responses[0], Headers: headers})
	if payload["status"] != "200 OK" || payload["statusCode"] != "200" {
		t.Errorf("expected final status, got status=%q statusCode=%q", payload["status"], payload["statusCode"])
	}
}
