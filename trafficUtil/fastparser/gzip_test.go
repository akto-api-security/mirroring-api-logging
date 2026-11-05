package fastparser

import (
	"bytes"
	"compress/gzip"
	"errors"
	"strings"
	"testing"
)

// gzipBytes compresses b (helper: the tests' inverse of gunzipBody).
func gzipBytes(b []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(b)
	_ = zw.Close()
	return buf.Bytes()
}

// gzipResponse builds "HTTP/1.1 200 ... Content-Encoding: gzip" with a gzipped body.
func gzipResponse(payload []byte) []byte {
	comp := gzipBytes(payload)
	var sb bytes.Buffer
	sb.WriteString("HTTP/1.1 200 OK\r\n")
	sb.WriteString("Content-Type: application/json\r\n")
	sb.WriteString("Content-Encoding: gzip\r\n")
	sb.WriteString("\r\n")
	sb.Write(comp)
	return sb.Bytes()
}

// 1. round-trip: Gunzip=true decompresses to the original payload.
func TestGunzipRoundTrip(t *testing.T) {
	payload := []byte(`{"name":"John Doe","age":30,"note":"long enough for gzip to matter"}`)
	p := newParser(withGunzip())
	r, err := p.ParseResponse(gzipResponse(payload))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(r.Body, payload) {
		t.Fatalf("body got %q want %q", r.Body, payload)
	}
}

// 2. soft error: corrupt gzip -> ErrGunzip, but resp is valid with empty body.
func TestGunzipCorruptIsSoftError(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 11\r\n\r\nnotgzipdata")
	p := newParser(withGunzip())
	r, err := p.ParseResponse(raw)
	if !errors.Is(err, ErrGunzip) {
		t.Fatalf("err = %v, want ErrGunzip", err)
	}
	if r == nil {
		t.Fatal("resp must be non-nil on soft error")
	}
	if r.StatusCode != 200 {
		t.Fatalf("status not parsed: %d", r.StatusCode)
	}
	if len(r.Body) != 0 {
		t.Fatalf("body must be empty on gunzip failure, got %d bytes", len(r.Body))
	}
}

// 3. flag off: a gzip response is left compressed, no error, no decode.
func TestGunzipDisabledLeavesBodyCompressed(t *testing.T) {
	payload := []byte(`{"k":"v"}`)
	raw := gzipResponse(payload)
	p := newParser() // Gunzip defaults false
	r, err := p.ParseResponse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// still the raw gzip stream: begins with the gzip magic 1f 8b.
	if len(r.Body) < 2 || r.Body[0] != 0x1f || r.Body[1] != 0x8b {
		t.Fatalf("body should be untouched gzip bytes, got %d bytes prefix %x", len(r.Body), r.Body[:min(2, len(r.Body))])
	}
	if bytes.Equal(r.Body, payload) {
		t.Fatal("body was decompressed with Gunzip=false")
	}
}

// 4. isGzip table: only single-coding gzip (case-insensitive, OWS-trimmed, last-wins).
func TestIsGzip(t *testing.T) {
	cases := []struct {
		name string
		hs   []Header
		want bool
	}{
		{"plain", mkHeaders("Content-Encoding", "gzip"), true},
		{"uppercase", mkHeaders("Content-Encoding", "GZIP"), true},
		{"mixedcase-name", mkHeaders("content-ENCODING", "gzip"), true},
		{"ows", mkHeaders("Content-Encoding", "  gzip \t"), true},
		{"stacked-not-plain-gzip", mkHeaders("Content-Encoding", "gzip, br"), false}, // coding list: out of scope
		{"identity", mkHeaders("Content-Encoding", "identity"), false},
		{"br", mkHeaders("Content-Encoding", "br"), false},
		{"deflate", mkHeaders("Content-Encoding", "deflate"), false},
		{"empty", mkHeaders("Content-Encoding", ""), false},
		{"absent", mkHeaders("Content-Type", "application/json"), false},
		{"no-headers", nil, false},
		{"multi-last-wins-gzip", mkHeaders("Content-Encoding", "br", "Content-Encoding", "gzip"), true},
		{"multi-last-wins-not-gzip", mkHeaders("Content-Encoding", "gzip", "Content-Encoding", "br"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isGzip(c.hs); got != c.want {
				t.Fatalf("isGzip=%v want %v", got, c.want)
			}
		})
	}
}

// 5. combined: the real wire shape — gzip INSIDE chunked. De-chunk then gunzip.
func TestChunkedThenGzip(t *testing.T) {
	payload := []byte(`{"method":"POST","echo":"the full round trip through chunked+gzip"}`)
	comp := gzipBytes(payload)

	// Reuse the chunkedBody generator to frame the gzip bytes as 2 chunks
	// (exercises multi-chunk de-framing) instead of hand-rolling chunk lines.
	var sb strings.Builder
	sb.WriteString("HTTP/1.1 200 OK\r\n")
	sb.WriteString("Content-Encoding: gzip\r\n")
	sb.WriteString("Transfer-Encoding: chunked\r\n")
	sb.WriteString("\r\n")
	sb.WriteString(chunkedBody(comp, 2))

	p := newParser(withChunk(), withGunzip()) // de-chunk runs before gunzip (gzip is inside chunked)
	r, err := p.ParseResponse([]byte(sb.String()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(r.Body, payload) {
		t.Fatalf("chunked+gzip body got %q want %q", r.Body, payload)
	}
}
