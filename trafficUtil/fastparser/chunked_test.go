package fastparser

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"testing"
)

// chunkedBody frames payload into `nChunks` chunked segments (last-but-one may be
// short) plus the terminating 0-chunk. Deterministic given the split.
func chunkedBody(payload []byte, nChunks int) string {
	var sb strings.Builder
	if nChunks < 1 {
		nChunks = 1
	}
	n := len(payload)
	// even-ish split; ensure every chunk (except a possibly-empty tail) is >0
	base := n / nChunks
	if base == 0 {
		base = 1
	}
	off := 0
	for off < n {
		end := off + base
		if end > n {
			end = n
		}
		seg := payload[off:end]
		fmt.Fprintf(&sb, "%x\r\n%s\r\n", len(seg), seg)
		off = end
	}
	sb.WriteString("0\r\n\r\n")
	return sb.String()
}

// buildChunkedResponse builds a full chunked HTTP/1.1 response and returns the
// raw bytes plus the payload they must decode to. Mirrors buildRequest's role:
// one generator that both the correctness tests and the benchmark share.
func buildChunkedResponse(payload []byte, nChunks int) (raw []byte, wantBody []byte) {
	var sb strings.Builder
	sb.WriteString("HTTP/1.1 200 OK\r\n")
	sb.WriteString("Content-Type: application/json\r\n")
	sb.WriteString("Transfer-Encoding: chunked\r\n")
	sb.WriteString("\r\n")
	sb.WriteString(chunkedBody(payload, nChunks))
	return []byte(sb.String()), payload
}

// ---- Unit cases ----

func TestParseResponseChunked(t *testing.T) {
	p := NewFastParser()
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{
			// the exact shape seen in production (Transfer-Encoding: chunked JSON)
			name: "prod-single-chunk",
			raw:  "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1c6\r\n" + strings.Repeat("a", 0x1c6) + "\r\n0\r\n\r\n",
			want: strings.Repeat("a", 0x1c6),
		},
		{
			name: "multi-chunk",
			raw:  "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n",
			want: "helloworld",
		},
		{
			name: "empty-body",
			raw:  "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
			want: "",
		},
		{
			name: "chunk-extension-ignored",
			raw:  "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;foo=bar\r\nhello\r\n0\r\n\r\n",
			want: "hello",
		},
		{
			name: "trailer-ignored",
			raw:  "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-Trace: abc\r\n\r\n",
			want: "hello",
		},
		{
			name: "uppercase-hex-size",
			raw:  "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nA\r\n0123456789\r\n0\r\n\r\n",
			want: "0123456789",
		},
		{
			// "gzip, chunked" — chunked is the last coding, must still decode
			name: "te-list-chunked-last",
			raw:  "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
			want: "abc",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := p.ParseResponse([]byte(c.raw))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(r.Body) != c.want {
				t.Fatalf("body got %q want %q", r.Body, c.want)
			}
		})
	}
}

func TestParseRequestChunked(t *testing.T) {
	p := NewFastParser()
	raw := "POST /u HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n"
	r, err := p.ParseRequest([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if string(r.Body) != "body" {
		t.Fatalf("body got %q want %q", r.Body, "body")
	}
}

func TestParseChunkedMalformed(t *testing.T) {
	p := NewFastParser()
	cases := []string{
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",               // no chunks at all
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhi\r\n",     // size 5 but only 2 bytes
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nxyz\r\nhi\r\n",   // non-hex size
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello",      // missing trailing CRLF + terminator
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloXX0\r\n\r\n", // bad post-data CRLF
	}
	for i, raw := range cases {
		if _, err := p.ParseResponse([]byte(raw)); err == nil {
			t.Fatalf("case %d: expected ErrMalformed, got nil", i)
		}
	}
}

func TestNonChunkedUnaffected(t *testing.T) {
	// A Transfer-Encoding that is NOT chunked (e.g. only gzip) must be treated as
	// identity here — body returned verbatim, no decode attempt.
	p := NewFastParser()
	raw := "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nContent-Length: 5\r\n\r\nhello"
	r, err := p.ParseResponse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if string(r.Body) != "hello" {
		t.Fatalf("body got %q want %q", r.Body, "hello")
	}
}

// ---- isChunked unit table: boundary cases the ParseResponse tests don't isolate ----

func TestIsChunked(t *testing.T) {
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
		{"plain", hdr("Transfer-Encoding", "chunked"), true},
		{"uppercase-value", hdr("Transfer-Encoding", "CHUNKED"), true},
		{"mixedcase-name", hdr("transfer-ENCODING", "chunked"), true},
		{"chunked-last-in-list", hdr("Transfer-Encoding", "gzip, chunked"), true},
		{"ows-around-value", hdr("Transfer-Encoding", "  chunked \t"), true},
		{"ows-in-list", hdr("Transfer-Encoding", "gzip ,\tchunked "), true},

		// chunked present but NOT the final coding -> body is not chunk-framed,
		// must be false or we'd corrupt a non-chunked body.
		{"chunked-not-last", hdr("Transfer-Encoding", "chunked, gzip"), false},

		{"only-gzip", hdr("Transfer-Encoding", "gzip"), false},
		{"empty-value", hdr("Transfer-Encoding", ""), false},
		{"absent", hdr("Content-Length", "5"), false},
		{"no-headers", nil, false},
		{"substring-prefix", hdr("Transfer-Encoding", "xchunked"), false},
		{"substring-suffix", hdr("Transfer-Encoding", "chunkedx"), false},

		// multiple Transfer-Encoding headers: last one wins.
		{"multi-te-last-chunked", hdr("Transfer-Encoding", "gzip", "Transfer-Encoding", "chunked"), true},
		{"multi-te-last-not-chunked", hdr("Transfer-Encoding", "chunked", "Transfer-Encoding", "gzip"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isChunked(c.hs); got != c.want {
				t.Fatalf("isChunked=%v want %v", got, c.want)
			}
		})
	}
}

// A response whose Transfer-Encoding lists chunked NOT last must have its body
// returned verbatim (no decode attempt) — the end-to-end guard for chunked-not-last.
func TestChunkedNotLastNotDecoded(t *testing.T) {
	p := NewFastParser()
	raw := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
	r, err := p.ParseResponse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	// Not decoded: body is the raw chunk framing, untouched.
	if string(r.Body) != "5\r\nhello\r\n0\r\n\r\n" {
		t.Fatalf("body should be verbatim (not decoded), got %q", r.Body)
	}
}

// ---- Differential vs net/http: the standard library de-chunks; we must match ----

func TestChunkedMatchesNetHTTP(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	p := NewFastParser()
	for i := 0; i < 500; i++ {
		size := rng.Intn(5000)
		payload := make([]byte, size)
		for j := range payload {
			payload[j] = byte(32 + rng.Intn(94))
		}
		nChunks := 1 + rng.Intn(8)
		raw, want := buildChunkedResponse(payload, nChunks)

		// oracle: net/http de-chunks transparently
		std, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), nil)
		if err != nil {
			t.Fatalf("iter %d: net/http rejected our fixture: %v", i, err)
		}
		stdBody, _ := io.ReadAll(std.Body)
		if !bytes.Equal(stdBody, want) {
			t.Fatalf("iter %d: generator/net-http disagree (gen bug)", i)
		}

		got, err := p.ParseResponse(raw) // note: mutates raw in place
		if err != nil {
			t.Fatalf("iter %d: our parser errored: %v", i, err)
		}
		if !bytes.Equal(got.Body, want) {
			t.Fatalf("iter %d: body mismatch len got %d want %d", i, len(got.Body), len(want))
		}
	}
}

// ---- In-place contract: Body aliases the input buffer, zero allocation ----

func TestChunkedDecodeAliasesAndZeroAlloc(t *testing.T) {
	p := NewFastParser()
	raw, want := buildChunkedResponse([]byte("helloworld"), 2)

	// aliasing: decoded Body must point INTO raw (compacted to the body region),
	// not a fresh allocation. The body starts right after the header terminator.
	r, err := p.ParseResponse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(r.Body) != string(want) {
		t.Fatalf("body got %q want %q", r.Body, want)
	}
	hdrEnd := bytes.Index(raw, []byte("\r\n\r\n")) + 4
	// &r.Body[0] must be within raw's backing array at hdrEnd (compacted to front).
	if len(r.Body) > 0 && &r.Body[0] != &raw[hdrEnd] {
		t.Fatalf("Body is not an in-place sub-slice of the input buffer")
	}

	// zero-alloc: decoding a chunked response allocates nothing on the hot path.
	fixture, _ := buildChunkedResponse([]byte(strings.Repeat("x", 1000)), 4)
	scratch := make([]byte, len(fixture))
	if n := testing.AllocsPerRun(1000, func() {
		copy(scratch, fixture) // refresh: decode mutates in place each iter
		rr, err := p.ParseResponse(scratch)
		if err != nil {
			t.Fatal(err)
		}
		sinkResp = rr
	}); n != 0 {
		t.Errorf("chunked ParseResponse allocated %v allocs/op, want 0", n)
	}
}

// ---- Fuzz: chunked framing must never panic ----

func FuzzDecodeChunked(f *testing.F) {
	for _, seed := range []string{
		"0\r\n\r\n",
		"5\r\nhello\r\n0\r\n\r\n",
		"5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n",
		"5;ext\r\nhello\r\n0\r\n\r\n",
		"", "\r\n", "z\r\n", "5\r\nhi", "ffffffffffffffff\r\n",
	} {
		f.Add([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + seed))
	}
	p := NewFastParser()
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("PANIC on input %q: %v", data, r)
			}
		}()
		if r, err := p.ParseResponse(data); err == nil {
			_ = string(r.Body)
		}
	})
}

// ---- Benchmark: unlike identity bodies (never scanned), the de-chunker DOES
// scan+copy the body, so cost scales with body size — the new axis worth tracking.

func BenchmarkParseResponseChunked(b *testing.B) {
	for _, s := range sizes {
		payload := make([]byte, sizeBytes(s))
		for i := range payload {
			payload[i] = byte('a' + i%26)
		}
		fixture, _ := buildChunkedResponse(payload, 8) // 8 chunks
		p := NewFastParser()
		scratch := make([]byte, len(fixture))
		b.Run(s, func(b *testing.B) {
			b.ReportAllocs()
			var n int64
			for b.Loop() {
				copy(scratch, fixture) // decode mutates in place; refresh each iter
				r, err := p.ParseResponse(scratch)
				if err != nil {
					b.Fatal(err)
				}
				_ = len(r.Body)
				n++
			}
			mps(b, n)
		})
	}
}

// sizeBytes maps the "256b".."64kb" labels used by the size sweep to byte counts.
func sizeBytes(s string) int {
	switch s {
	case "256b":
		return 256
	case "1kb":
		return 1024
	case "4kb":
		return 4096
	case "10kb":
		return 10240
	case "20kb":
		return 20480
	case "64kb":
		return 65536
	}
	return 1024
}
