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
	p := NewFastParser()
	p.Gunzip = true
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
	p := NewFastParser()
	p.Gunzip = true
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
	p := NewFastParser() // Gunzip defaults false
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
	hdr := func(pairs ...string) []Header {
		hs := make([]Header, 0, len(pairs)/2)
		for i := 0; i+1 < len(pairs); i += 2 {
			hs = append(hs, Header{Name: []byte(pairs[i]), Value: []byte(pairs[i+1])})
		}
		return hs
	}
	cases := []struct {
		name string
		hs   []Header
		want bool
	}{
		{"plain", hdr("Content-Encoding", "gzip"), true},
		{"uppercase", hdr("Content-Encoding", "GZIP"), true},
		{"mixedcase-name", hdr("content-ENCODING", "gzip"), true},
		{"ows", hdr("Content-Encoding", "  gzip \t"), true},
		{"stacked-not-plain-gzip", hdr("Content-Encoding", "gzip, br"), false}, // coding list: out of scope
		{"identity", hdr("Content-Encoding", "identity"), false},
		{"br", hdr("Content-Encoding", "br"), false},
		{"deflate", hdr("Content-Encoding", "deflate"), false},
		{"empty", hdr("Content-Encoding", ""), false},
		{"absent", hdr("Content-Type", "application/json"), false},
		{"no-headers", nil, false},
		{"multi-last-wins-gzip", hdr("Content-Encoding", "br", "Content-Encoding", "gzip"), true},
		{"multi-last-wins-not-gzip", hdr("Content-Encoding", "gzip", "Content-Encoding", "br"), false},
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

	var sb strings.Builder
	sb.WriteString("HTTP/1.1 200 OK\r\n")
	sb.WriteString("Content-Encoding: gzip\r\n")
	sb.WriteString("Transfer-Encoding: chunked\r\n")
	sb.WriteString("\r\n")
	// frame the gzip bytes as two chunks to exercise multi-chunk de-framing
	half := len(comp) / 2
	fmtChunk := func(b []byte) {
		sb.WriteString(itoaHex(len(b)))
		sb.WriteString("\r\n")
		sb.Write(b)
		sb.WriteString("\r\n")
	}
	fmtChunk(comp[:half])
	fmtChunk(comp[half:])
	sb.WriteString("0\r\n\r\n")

	p := NewFastParser()
	p.Gunzip = true
	r, err := p.ParseResponse([]byte(sb.String()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(r.Body, payload) {
		t.Fatalf("chunked+gzip body got %q want %q", r.Body, payload)
	}
}

// itoaHex renders n as lowercase hex (chunk-size line).
func itoaHex(n int) string {
	if n == 0 {
		return "0"
	}
	const digits = "0123456789abcdef"
	var buf [16]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = digits[n&0xf]
		n >>= 4
	}
	return string(buf[i:])
}
