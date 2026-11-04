package fastparser

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// frameWriter builds a stream of HTTP/2 frames for ONE direction, sharing one
// HPACK encoder across all header blocks (so the dynamic table is cumulative,
// matching a real peer and our per-direction decoder).
type frameWriter struct {
	buf  bytes.Buffer
	fr   *http2.Framer
	enc  *hpack.Encoder
	hbuf bytes.Buffer
}

func newFrameWriter() *frameWriter {
	w := &frameWriter{}
	w.fr = http2.NewFramer(&w.buf, nil)
	w.enc = hpack.NewEncoder(&w.hbuf)
	return w
}

func (w *frameWriter) headers(t *testing.T, streamID uint32, endStream, endHeaders bool, hs ...hpack.HeaderField) {
	t.Helper()
	w.hbuf.Reset()
	for _, h := range hs {
		if err := w.enc.WriteField(h); err != nil {
			t.Fatalf("hpack WriteField: %v", err)
		}
	}
	if err := w.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: w.hbuf.Bytes(),
		EndStream:     endStream,
		EndHeaders:    endHeaders,
	}); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}
}

func (w *frameWriter) data(t *testing.T, streamID uint32, endStream bool, data []byte) {
	t.Helper()
	if err := w.fr.WriteData(streamID, endStream, data); err != nil {
		t.Fatalf("WriteData: %v", err)
	}
}

func (w *frameWriter) bytes() []byte { return w.buf.Bytes() }

// grpcMsg wraps a payload in gRPC's length-prefixed framing.
func grpcMsg(payload []byte) []byte {
	b := make([]byte, 5+len(payload))
	b[0] = 0 // uncompressed
	binary.BigEndian.PutUint32(b[1:5], uint32(len(payload)))
	copy(b[5:], payload)
	return b
}

func TestHTTP2UnaryGRPC(t *testing.T) {
	reqMsg := []byte("\x0a\x05world")
	respMsg := []byte("\x0a\x0bhello world")

	req := newFrameWriter()
	req.headers(t, 1, false, true,
		hpack.HeaderField{Name: ":method", Value: "POST"},
		hpack.HeaderField{Name: ":scheme", Value: "http"},
		hpack.HeaderField{Name: ":path", Value: "/helloworld.Greeter/SayHello"},
		hpack.HeaderField{Name: ":authority", Value: "localhost:50051"},
		hpack.HeaderField{Name: "content-type", Value: "application/grpc"},
	)
	req.data(t, 1, true, grpcMsg(reqMsg))

	resp := newFrameWriter()
	resp.headers(t, 1, false, true,
		hpack.HeaderField{Name: ":status", Value: "200"},
		hpack.HeaderField{Name: "content-type", Value: "application/grpc"},
	)
	resp.data(t, 1, false, grpcMsg(respMsg))
	// gRPC trailing HEADERS carry grpc-status and END_STREAM.
	resp.headers(t, 1, true, true, hpack.HeaderField{Name: "grpc-status", Value: "0"})

	c := NewHTTP2Conn(0)
	if err := c.Feed(true, append([]byte(h2ClientPreface), req.bytes()...)); err != nil {
		t.Fatalf("Feed request: %v", err)
	}
	if err := c.Feed(false, resp.bytes()); err != nil {
		t.Fatalf("Feed response: %v", err)
	}

	done := c.TakeComplete()
	if len(done) != 1 {
		t.Fatalf("TakeComplete = %d streams, want 1", len(done))
	}
	s := done[0]
	if s.Method != "POST" || s.Path != "/helloworld.Greeter/SayHello" {
		t.Fatalf("method/path = %q %q", s.Method, s.Path)
	}
	if !s.IsGRPC {
		t.Fatalf("IsGRPC = false, want true")
	}
	if s.StatusCode != 200 {
		t.Fatalf("StatusCode = %d, want 200", s.StatusCode)
	}
	if s.GRPCStatus != "0" {
		t.Fatalf("GRPCStatus = %q, want 0", s.GRPCStatus)
	}

	r, resp2 := s.ToRequestResponse()
	if string(r.Version) != "gRPC" {
		t.Fatalf("version = %q, want gRPC", r.Version)
	}
	wantReqBody := base64.StdEncoding.EncodeToString(reqMsg)
	if string(r.Body) != wantReqBody {
		t.Fatalf("req body = %q, want %q", r.Body, wantReqBody)
	}
	wantRespBody := base64.StdEncoding.EncodeToString(respMsg)
	if string(resp2.Body) != wantRespBody {
		t.Fatalf("resp body = %q, want %q", resp2.Body, wantRespBody)
	}
	if string(r.Host()) != "localhost:50051" {
		t.Fatalf("host = %q, want localhost:50051", r.Host())
	}
}

func TestHTTP2PlainH2(t *testing.T) {
	body := []byte(`{"hello":"world"}`)

	req := newFrameWriter()
	req.headers(t, 3, false, true,
		hpack.HeaderField{Name: ":method", Value: "GET"},
		hpack.HeaderField{Name: ":path", Value: "/api/v1/thing"},
		hpack.HeaderField{Name: ":authority", Value: "example.com"},
		hpack.HeaderField{Name: "content-type", Value: "application/json"},
	)
	req.data(t, 3, true, nil) // empty request body, END_STREAM

	resp := newFrameWriter()
	resp.headers(t, 3, false, true,
		hpack.HeaderField{Name: ":status", Value: "200"},
		hpack.HeaderField{Name: "content-type", Value: "application/json"},
	)
	resp.data(t, 3, true, body)

	c := NewHTTP2Conn(0)
	if err := c.Feed(true, append([]byte(h2ClientPreface), req.bytes()...)); err != nil {
		t.Fatalf("Feed request: %v", err)
	}
	if err := c.Feed(false, resp.bytes()); err != nil {
		t.Fatalf("Feed response: %v", err)
	}

	done := c.TakeComplete()
	if len(done) != 1 {
		t.Fatalf("TakeComplete = %d streams, want 1", len(done))
	}
	s := done[0]
	if s.IsGRPC {
		t.Fatalf("IsGRPC = true, want false for plain h2")
	}
	r, resp2 := s.ToRequestResponse()
	if string(r.Method) != "GET" || string(r.Path) != "/api/v1/thing" {
		t.Fatalf("method/path = %q %q", r.Method, r.Path)
	}
	if string(r.Version) != "HTTP/2.0" {
		t.Fatalf("version = %q, want HTTP/2.0", r.Version)
	}
	// Plain h2 body is raw (not base64/unwrapped).
	if !bytes.Equal(resp2.Body, body) {
		t.Fatalf("resp body = %q, want %q", resp2.Body, body)
	}
}

// TestHTTP2SplitFeed feeds the request bytes split mid-frame across two Feed
// calls, proving incremental decode: persistent HPACK + partial-frame buffering.
func TestHTTP2SplitFeed(t *testing.T) {
	reqMsg := []byte("payload-bytes-here")

	req := newFrameWriter()
	req.headers(t, 1, false, true,
		hpack.HeaderField{Name: ":method", Value: "POST"},
		hpack.HeaderField{Name: ":path", Value: "/svc/M"},
		hpack.HeaderField{Name: ":authority", Value: "h"},
		hpack.HeaderField{Name: "content-type", Value: "application/grpc"},
	)
	req.data(t, 1, true, grpcMsg(reqMsg))
	reqBytes := append([]byte(h2ClientPreface), req.bytes()...)

	resp := newFrameWriter()
	resp.headers(t, 1, false, true, hpack.HeaderField{Name: ":status", Value: "200"},
		hpack.HeaderField{Name: "content-type", Value: "application/grpc"})
	resp.headers(t, 1, true, true, hpack.HeaderField{Name: "grpc-status", Value: "0"})

	c := NewHTTP2Conn(0)
	// Split the request across a boundary that lands inside a frame.
	mid := len(reqBytes) / 2
	if err := c.Feed(true, reqBytes[:mid]); err != nil {
		t.Fatalf("Feed part 1: %v", err)
	}
	// Nothing complete yet (request not fully fed).
	if got := c.TakeComplete(); len(got) != 0 {
		t.Fatalf("premature complete after partial feed: %d", len(got))
	}
	if err := c.Feed(true, reqBytes[mid:]); err != nil {
		t.Fatalf("Feed part 2: %v", err)
	}
	if err := c.Feed(false, resp.bytes()); err != nil {
		t.Fatalf("Feed response: %v", err)
	}

	done := c.TakeComplete()
	if len(done) != 1 {
		t.Fatalf("TakeComplete = %d, want 1", len(done))
	}
	r, _ := done[0].ToRequestResponse()
	want := base64.StdEncoding.EncodeToString(reqMsg)
	if string(r.Body) != want {
		t.Fatalf("split-feed req body = %q, want %q", r.Body, want)
	}
}

// TestHTTP2Preface ensures the 24-byte client connection preface is stripped.
func TestHTTP2Preface(t *testing.T) {
	req := newFrameWriter()
	req.headers(t, 1, true, true,
		hpack.HeaderField{Name: ":method", Value: "POST"},
		hpack.HeaderField{Name: ":path", Value: "/p"},
		hpack.HeaderField{Name: ":authority", Value: "h"})
	withPreface := append([]byte(h2ClientPreface), req.bytes()...)

	resp := newFrameWriter()
	resp.headers(t, 1, true, true, hpack.HeaderField{Name: ":status", Value: "200"})

	c := NewHTTP2Conn(0)
	if err := c.Feed(true, withPreface); err != nil {
		t.Fatalf("Feed request (with preface): %v", err)
	}
	if err := c.Feed(false, resp.bytes()); err != nil {
		t.Fatalf("Feed response: %v", err)
	}
	done := c.TakeComplete()
	if len(done) != 1 {
		t.Fatalf("TakeComplete = %d, want 1 (preface not stripped?)", len(done))
	}
	if done[0].Path != "/p" {
		t.Fatalf("path = %q, want /p", done[0].Path)
	}
}

func TestHTTP2MissingPrefaceFails(t *testing.T) {
	req := newFrameWriter()
	req.headers(t, 1, true, true, hpack.HeaderField{Name: ":method", Value: "GET"})
	c := NewHTTP2Conn(0)
	if err := c.Feed(true, req.bytes()); err == nil {
		t.Fatal("frames without the client preface must not be decoded")
	}
}

// A server push sends a header block on the response side. Skipping it would
// leave the response decoder's dynamic table behind the encoder's, and the
// next response's headers would decode wrong.
func TestHTTP2PushPromiseKeepsHPACKInSync(t *testing.T) {
	req := newFrameWriter()
	req.headers(t, 1, true, true,
		hpack.HeaderField{Name: ":method", Value: "GET"},
		hpack.HeaderField{Name: ":path", Value: "/a"},
		hpack.HeaderField{Name: ":authority", Value: "h"})
	req.headers(t, 3, true, true,
		hpack.HeaderField{Name: ":method", Value: "GET"},
		hpack.HeaderField{Name: ":path", Value: "/b"},
		hpack.HeaderField{Name: ":authority", Value: "h"})

	resp := newFrameWriter()
	resp.hbuf.Reset()
	for _, h := range []hpack.HeaderField{
		{Name: ":method", Value: "GET"}, {Name: ":path", Value: "/pushed.css"},
		{Name: "x-pushed", Value: "added-to-dynamic-table"},
	} {
		resp.enc.WriteField(h)
	}
	if err := resp.fr.WritePushPromise(http2.PushPromiseParam{
		StreamID: 1, PromiseID: 2, BlockFragment: resp.hbuf.Bytes(), EndHeaders: true,
	}); err != nil {
		t.Fatal(err)
	}
	resp.headers(t, 1, true, true, hpack.HeaderField{Name: ":status", Value: "200"},
		hpack.HeaderField{Name: "x-pushed", Value: "added-to-dynamic-table"})
	resp.headers(t, 3, true, true, hpack.HeaderField{Name: ":status", Value: "204"})

	c := NewHTTP2Conn(0)
	if err := c.Feed(true, append([]byte(h2ClientPreface), req.bytes()...)); err != nil {
		t.Fatal(err)
	}
	if err := c.Feed(false, resp.bytes()); err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, s := range c.TakeComplete() {
		got[s.Path] = s.StatusCode
		if s.Path == "/a" {
			found := false
			for _, h := range s.RespHeaders {
				if string(h.Name) == "x-pushed" && string(h.Value) == "added-to-dynamic-table" {
					found = true
				}
			}
			if !found {
				t.Fatalf("stream 1 response headers decoded wrong: %+v", s.RespHeaders)
			}
		}
	}
	if got["/a"] != 200 || got["/b"] != 204 || len(got) != 2 {
		t.Fatalf("streams = %v", got)
	}
}

// Peers may grow the HPACK table past 4096 (after advertising it in SETTINGS).
func TestHTTP2LargeHeaderTableSizeUpdate(t *testing.T) {
	req := newFrameWriter()
	req.enc.SetMaxDynamicTableSizeLimit(65536)
	req.enc.SetMaxDynamicTableSize(65536)
	big := string(bytes.Repeat([]byte("v"), 6000))
	req.headers(t, 1, true, true,
		hpack.HeaderField{Name: ":method", Value: "GET"},
		hpack.HeaderField{Name: ":path", Value: "/x"},
		hpack.HeaderField{Name: "x-big", Value: big})
	req.headers(t, 3, true, true,
		hpack.HeaderField{Name: ":method", Value: "GET"},
		hpack.HeaderField{Name: ":path", Value: "/y"},
		hpack.HeaderField{Name: "x-big", Value: big})
	resp := newFrameWriter()
	resp.headers(t, 1, true, true, hpack.HeaderField{Name: ":status", Value: "200"})
	resp.headers(t, 3, true, true, hpack.HeaderField{Name: ":status", Value: "200"})

	c := NewHTTP2Conn(0)
	if err := c.Feed(true, append([]byte(h2ClientPreface), req.bytes()...)); err != nil {
		t.Fatal(err)
	}
	if err := c.Feed(false, resp.bytes()); err != nil {
		t.Fatal(err)
	}
	done := c.TakeComplete()
	if len(done) != 2 {
		t.Fatalf("got %d streams", len(done))
	}
	for _, s := range done {
		ok := false
		for _, h := range s.ReqHeaders {
			if string(h.Name) == "x-big" && len(h.Value) == 6000 {
				ok = true
			}
		}
		if !ok {
			t.Fatalf("stream %d lost x-big", s.StreamID)
		}
	}
}

func TestHTTP2BodyCapTruncatesButEmits(t *testing.T) {
	req := newFrameWriter()
	req.headers(t, 1, false, true,
		hpack.HeaderField{Name: ":method", Value: "POST"},
		hpack.HeaderField{Name: ":path", Value: "/up"})
	req.data(t, 1, false, bytes.Repeat([]byte("a"), 300))
	req.data(t, 1, true, bytes.Repeat([]byte("b"), 300))
	resp := newFrameWriter()
	resp.headers(t, 1, true, true, hpack.HeaderField{Name: ":status", Value: "201"})

	c := NewHTTP2Conn(400)
	c.Feed(true, append([]byte(h2ClientPreface), req.bytes()...))
	c.Feed(false, resp.bytes())
	done := c.TakeComplete()
	if len(done) != 1 || len(done[0].ReqBody) != 400 || !done[0].Truncated {
		t.Fatalf("want one truncated stream with a 400 byte body, got %d", len(done))
	}
}

func TestHTTP2RSTStreamForgetsStream(t *testing.T) {
	req := newFrameWriter()
	req.headers(t, 1, false, true,
		hpack.HeaderField{Name: ":method", Value: "POST"},
		hpack.HeaderField{Name: ":path", Value: "/cancel"})
	req.fr.WriteRSTStream(1, http2.ErrCodeCancel)
	c := NewHTTP2Conn(0)
	c.Feed(true, append([]byte(h2ClientPreface), req.bytes()...))
	if len(c.streams) != 0 {
		t.Fatalf("cancelled stream still tracked")
	}
}

func TestHTTP2InformationalHeadersDropped(t *testing.T) {
	req := newFrameWriter()
	req.headers(t, 1, true, true,
		hpack.HeaderField{Name: ":method", Value: "POST"},
		hpack.HeaderField{Name: ":path", Value: "/x"})
	resp := newFrameWriter()
	resp.headers(t, 1, false, true, hpack.HeaderField{Name: ":status", Value: "103"},
		hpack.HeaderField{Name: "link", Value: "</a.css>"})
	resp.headers(t, 1, true, true, hpack.HeaderField{Name: ":status", Value: "200"})
	c := NewHTTP2Conn(0)
	c.Feed(true, append([]byte(h2ClientPreface), req.bytes()...))
	c.Feed(false, resp.bytes())
	done := c.TakeComplete()
	if len(done) != 1 || done[0].StatusCode != 200 || len(done[0].RespHeaders) != 1 {
		t.Fatalf("got %+v", done)
	}
}
