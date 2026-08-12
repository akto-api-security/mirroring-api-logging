package fastparser

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var sizes = []string{"256b", "1kb", "4kb", "10kb", "20kb", "64kb"}

func load(t testing.TB, name string) []byte {
	// fixtures live at repo-root/testdata; tests run from this package dir.
	b, err := os.ReadFile(filepath.Join("../../", "testdata", name))
	if err != nil {
		t.Skipf("testdata fixture missing (%v); copy from fix/search-lost-call or generate fixtures", err)
	}
	return b
}

func TestParseRequest(t *testing.T) {
	p := NewFastParser()
	r, err := p.ParseRequest(load(t, "req-1kb.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if string(r.Method) != "POST" || string(r.Path) != "/?request-num=9" || string(r.Version) != "HTTP/1.1" {
		t.Fatalf("bad line: %q %q %q", r.Method, r.Path, r.Version)
	}
	if len(r.Headers) != 7 {
		t.Fatalf("want 7 headers got %d", len(r.Headers))
	}
	if string(r.Headers[0].Name) != "Host" || string(r.Headers[0].Value) != "localhost:8888" {
		t.Fatalf("bad header0: %q=%q", r.Headers[0].Name, r.Headers[0].Value)
	}
	if len(r.Body) != 1021 {
		t.Fatalf("body len %d want 1021", len(r.Body))
	}
}

func TestHostAndHeaderLookup(t *testing.T) {
	p := NewFastParser()
	// mixed-case header names + an absent one
	raw := []byte("GET /x HTTP/1.1\r\nhOsT: example.com:9090\r\nContent-Length: 5\r\nX-A: v1\r\n\r\nhello")
	r, err := p.ParseRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(r.Host()) != "example.com:9090" {
		t.Fatalf("Host() case-insensitive failed: %q", r.Host())
	}
	if string(r.Header("CONTENT-LENGTH")) != "5" {
		t.Fatalf("Header() case-insensitive failed: %q", r.Header("CONTENT-LENGTH"))
	}
	if string(r.Header("x-a")) != "v1" {
		t.Fatalf("Header lower->orig failed: %q", r.Header("x-a"))
	}
	if r.Header("X-Missing") != nil {
		t.Fatalf("absent header must be nil, got %q", r.Header("X-Missing"))
	}
	// no Host header at all
	r2, _ := p.ParseRequest([]byte("GET / HTTP/1.1\r\nAccept: */*\r\n\r\n"))
	if r2.Host() != nil {
		t.Fatalf("missing Host must be nil, got %q", r2.Host())
	}
}

func TestParseResponse(t *testing.T) {
	p := NewFastParser()
	r, err := p.ParseResponse(load(t, "resp-1kb.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if string(r.Version) != "HTTP/1.1" || r.StatusCode != 200 || string(r.Reason) != "OK" {
		t.Fatalf("bad status line: %q %d %q", r.Version, r.StatusCode, r.Reason)
	}
	if len(r.Headers) != 7 {
		t.Fatalf("want 7 headers got %d", len(r.Headers))
	}
}

func TestMalformedReturnsError(t *testing.T) {
	p := NewFastParser()
	cases := [][]byte{
		[]byte("GET / garbage no NewFastParserline"),
		[]byte("GET / HTTP/1.1\r\nBadHeaderNoColon\r\n\r\n"),
		[]byte("GET / HTTP/1.1\r\nHost: partial"), // no terminator
		[]byte(""),
	}
	for i, c := range cases {
		if _, err := p.ParseRequest(c); err == nil {
			t.Fatalf("case %d: expected error, got nil (would crash in prod)", i)
		}
	}
}

// mps adds an "M/s" (millions of ops/sec) column to a benchmark result.
func mps(b *testing.B, ops int64) {
	b.ReportMetric(float64(ops)/b.Elapsed().Seconds()/1e6, "M/s")
}

// --- SINGLE-CORE (one goroutine) ---

func BenchmarkParseRequest(b *testing.B) {
	for _, s := range sizes {
		buf := load(b, "req-"+s+".bin")
		p := NewFastParser()
		b.Run(s, func(b *testing.B) {
			b.ReportAllocs()
			var n int64
			for b.Loop() {
				r, err := p.ParseRequest(buf)
				if err != nil {
					b.Fatal(err)
				}
				_ = len(r.Headers) + len(r.Body)
				n++
			}
			mps(b, n)
			gibps(b, n, int64(len(buf)))
		})
	}
}

func BenchmarkParseResponse(b *testing.B) {
	for _, s := range sizes {
		buf := load(b, "resp-"+s+".bin")
		p := NewFastParser()
		b.Run(s, func(b *testing.B) {
			b.ReportAllocs()
			var n int64
			for b.Loop() {
				r, err := p.ParseResponse(buf)
				if err != nil {
					b.Fatal(err)
				}
				_ = r.StatusCode + len(r.Body)
				n++
			}
			mps(b, n)
			gibps(b, n, int64(len(buf)))
		})
	}
}

// --- ALL-CORES (GOMAXPROCS goroutines via RunParallel) ---

func BenchmarkParseRequestParallel(b *testing.B) {
	for _, s := range sizes {
		buf := load(b, "req-"+s+".bin")
		b.Run(s, func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				p := NewFastParser() // one parser per goroutine — never share
				for pb.Next() {
					r, err := p.ParseRequest(buf)
					if err != nil {
						b.Fatal(err)
					}
					_ = len(r.Headers) + len(r.Body)
				}
			})
			mps(b, int64(b.N)) // b.N = total iterations across all goroutines
		})
	}
}

func BenchmarkParseResponseParallel(b *testing.B) {
	for _, s := range sizes {
		buf := load(b, "resp-"+s+".bin")
		b.Run(s, func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				p := NewFastParser()
				for pb.Next() {
					r, err := p.ParseResponse(buf)
					if err != nil {
						b.Fatal(err)
					}
					_ = r.StatusCode + len(r.Body)
				}
			})
			mps(b, int64(b.N))
		})
	}
}

// --- HEADER-COUNT SWEEP (fixed 4kb body, varying header count) ---
//
// The size sweeps above vary the BODY, which the parser never scans (zero-copy),
// so they're flat. This sweep varies the axis that actually costs: header count.
// Points straddle the 128-entry scratch array (120/128/129/200) to expose the
// heap-grow alloc cliff. The extra ns/hdr metric is the marginal per-header cost;
// watching it fall as count rises reveals the fixed per-message overhead.
func BenchmarkParseRequestHeaders(b *testing.B) {
	counts := []int{4, 8, 16, 32, 64, 120, 128, 129, 200}
	rng := rand.New(rand.NewSource(1))
	for _, hc := range counts {
		req := buildRequest(rng, hc, 4096) // built ONCE, outside the timed loop
		p := NewFastParser()
		b.Run(fmt.Sprintf("%dhdr", hc), func(b *testing.B) {
			b.ReportAllocs()
			var n int64
			for b.Loop() {
				r, err := p.ParseRequest(req.raw)
				if err != nil {
					b.Fatal(err)
				}
				_ = len(r.Headers) + len(r.Body)
				n++
			}
			mps(b, n)
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(n)/float64(hc), "ns/hdr")
		})
	}
}

// BenchmarkParseRequestHeadersParallel is the all-cores counterpart: same header
// sweep, GOMAXPROCS goroutines, one Parser each (never shared).
func BenchmarkParseRequestHeadersParallel(b *testing.B) {
	counts := []int{4, 8, 16, 32, 64, 120, 128, 129, 200}
	rng := rand.New(rand.NewSource(1))
	for _, hc := range counts {
		req := buildRequest(rng, hc, 4096) // built ONCE, outside the timed loop
		b.Run(fmt.Sprintf("%dhdr", hc), func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				p := NewFastParser() // one parser per goroutine — never share
				for pb.Next() {
					r, err := p.ParseRequest(req.raw)
					if err != nil {
						b.Fatal(err)
					}
					_ = len(r.Headers) + len(r.Body)
				}
			})
			mps(b, int64(b.N))
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(hc), "ns/hdr")
		})
	}
}

func readFix(name string) []byte {
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		return nil
	}
	return b
}

// lowerMap builds name(lower)->value from our parsed headers (last value wins,
// matching how the old map-based pipeline behaved).
func ourHeaders(hs []Header) map[string]string {
	m := make(map[string]string, len(hs))
	for _, h := range hs {
		m[strings.ToLower(string(h.Name))] = string(h.Value)
	}
	return m
}

// ---- Differential: our parser vs net/http on the real fixtures ----

func TestFixturesMatchNetHTTP(t *testing.T) {
	if readFix("req-256b.bin") == nil {
		t.Skip("testdata fixtures missing")
	}
	p := NewFastParser()
	for _, s := range sizes {
		// request
		raw := readFix("req-" + s + ".bin")
		std, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
		if err != nil {
			t.Fatalf("%s: net/http rejected our fixture: %v", s, err)
		}
		got, err := p.ParseRequest(raw)
		if err != nil {
			t.Fatalf("%s: our parser errored: %v", s, err)
		}
		if string(got.Method) != std.Method {
			t.Errorf("%s method: got %q want %q", s, got.Method, std.Method)
		}
		if string(got.Path) != std.RequestURI {
			t.Errorf("%s path: got %q want %q", s, got.Path, std.RequestURI)
		}
		if string(got.Version) != std.Proto {
			t.Errorf("%s proto: got %q want %q", s, got.Version, std.Proto)
		}
		stdBody, _ := io.ReadAll(std.Body)
		if !bytes.Equal(got.Body, stdBody) {
			t.Errorf("%s body mismatch (len got %d want %d)", s, len(got.Body), len(stdBody))
		}
		// headers: every header we produced must agree with net/http
		om := ourHeaders(got.Headers)
		for name, val := range om {
			if name == "host" {
				if val != std.Host {
					t.Errorf("%s host: got %q want %q", s, val, std.Host)
				}
				continue
			}
			if canon := std.Header.Get(http.CanonicalHeaderKey(name)); canon != val {
				t.Errorf("%s header %q: got %q want %q", s, name, val, canon)
			}
		}

		// response
		rraw := readFix("resp-" + s + ".bin")
		rstd, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(rraw)), nil)
		if err != nil {
			t.Fatalf("%s: net/http rejected our resp fixture: %v", s, err)
		}
		rgot, err := p.ParseResponse(rraw)
		if err != nil {
			t.Fatalf("%s: our resp parser errored: %v", s, err)
		}
		if rgot.StatusCode != rstd.StatusCode {
			t.Errorf("%s status: got %d want %d", s, rgot.StatusCode, rstd.StatusCode)
		}
		rBody, _ := io.ReadAll(rstd.Body)
		if !bytes.Equal(rgot.Body, rBody) {
			t.Errorf("%s resp body mismatch", s)
		}
		for name, val := range ourHeaders(rgot.Headers) {
			if canon := rstd.Header.Get(http.CanonicalHeaderKey(name)); canon != val {
				t.Errorf("%s resp header %q: got %q want %q", s, name, val, canon)
			}
		}
	}
}

// ---- Shared random request builder ----
//
// buildRequest generates one well-formed HTTP/1.1 request and the oracle of what
// it should parse to. It's shared by the generative correctness test (random
// small header counts, cross-checked against net/http) and the header-count
// benchmark (fixed large header counts, timed). Keeping one generator means the
// benchmark exercises exactly the shape the correctness test already validates.

// genHdrNames are realistic header names used first; past this pool the builder
// synthesizes unique "X-Gen-N" names so any header count is reachable while
// every name stays unique (the generative test asserts header-count equality).
var genHdrNames = []string{
	"Accept", "User-Agent", "X-Trace", "X-Custom-Header", "Cookie", "Referer",
	"Accept-Encoding", "Accept-Language", "Cache-Control", "Origin",
}

// genRequest is a built request plus the values it must parse back to.
type genRequest struct {
	raw     []byte
	method  string
	path    string
	body    string
	headers map[string]string // lower(name) -> value, incl. Host + Content-Length
}

// buildRequest constructs a request with numHeaders custom headers (unique
// names) plus Host and Content-Length, and a body of exactly bodyLen bytes.
func buildRequest(rng *rand.Rand, numHeaders, bodyLen int) genRequest {
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}
	method := methods[rng.Intn(len(methods))]
	path := "/" + randToken(rng, 1+rng.Intn(20))
	if rng.Intn(2) == 0 {
		path += "?q=" + randToken(rng, rng.Intn(10))
	}
	host := randToken(rng, 3+rng.Intn(10)) + ":8080"
	body := randBody(rng, bodyLen)

	want := map[string]string{}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s HTTP/1.1\r\nHost: %s\r\n", method, path, host)
	want["host"] = host

	perm := rng.Perm(len(genHdrNames))
	for i := 0; i < numHeaders; i++ {
		name := fmt.Sprintf("X-Gen-%d", i) // unique beyond the realistic pool
		if i < len(genHdrNames) {
			name = genHdrNames[perm[i]]
		}
		val := randHeaderValue(rng, 1+rng.Intn(30))
		fmt.Fprintf(&sb, "%s: %s\r\n", name, val)
		want[strings.ToLower(name)] = val
	}
	fmt.Fprintf(&sb, "Content-Length: %d\r\n\r\n", len(body))
	want["content-length"] = fmt.Sprintf("%d", len(body))
	sb.WriteString(body)

	return genRequest{raw: []byte(sb.String()), method: method, path: path, body: body, headers: want}
}

// ---- Generative differential: random well-formed requests, ours vs the values
// we generated (a clean oracle) plus net/http cross-check on line+body ----

func TestParserGenerative(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	p := NewFastParser()

	for iter := 0; iter < 2000; iter++ {
		req := buildRequest(rng, rng.Intn(len(genHdrNames)+1), rng.Intn(200))

		got, err := p.ParseRequest(req.raw)
		if err != nil {
			t.Fatalf("iter %d: parser errored on well-formed input: %v\n%q", iter, err, req.raw)
		}
		if string(got.Method) != req.method {
			t.Fatalf("iter %d: method got %q want %q", iter, got.Method, req.method)
		}
		if string(got.Path) != req.path {
			t.Fatalf("iter %d: path got %q want %q", iter, got.Path, req.path)
		}
		if string(got.Body) != req.body {
			t.Fatalf("iter %d: body got %q want %q", iter, got.Body, req.body)
		}
		om := ourHeaders(got.Headers)
		if len(om) != len(req.headers) {
			t.Fatalf("iter %d: header count got %d want %d\n%q", iter, len(om), len(req.headers), req.raw)
		}
		for k, v := range req.headers {
			if om[k] != v {
				t.Fatalf("iter %d: header %q got %q want %q", iter, k, om[k], v)
			}
		}
		// cross-check line+body against net/http
		if std, e := http.ReadRequest(bufio.NewReader(bytes.NewReader(req.raw))); e == nil {
			if std.Method != req.method || std.RequestURI != req.path {
				t.Fatalf("iter %d: net/http disagreed: %q %q", iter, std.Method, std.RequestURI)
			}
		}
	}
}

func randToken(rng *rand.Rand, n int) string {
	const cs = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
	b := make([]byte, n)
	for i := range b {
		b[i] = cs[rng.Intn(len(cs))]
	}
	return string(b)
}

// header values: printable ASCII, no CR/LF, trimmed (no leading/trailing space).
func randHeaderValue(rng *rand.Rand, n int) string {
	const cs = "abcdefghijklmnopqrstuvwxyz0123456789/.:;=+()[]" // safe, no CR/LF/leading-space
	b := make([]byte, n)
	for i := range b {
		b[i] = cs[rng.Intn(len(cs))]
	}
	return string(b)
}

func randBody(rng *rand.Rand, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(32 + rng.Intn(94)) // printable ascii
	}
	return string(b)
}

// ---- Edge-case table ----

func TestEdgeCases(t *testing.T) {
	p := NewFastParser()
	t.Run("no-headers", func(t *testing.T) {
		r, err := p.ParseRequest([]byte("GET / HTTP/1.1\r\n\r\n"))
		if err != nil || len(r.Headers) != 0 || len(r.Body) != 0 {
			t.Fatalf("err=%v headers=%d body=%d", err, len(r.Headers), len(r.Body))
		}
	})
	t.Run("empty-value", func(t *testing.T) {
		r, err := p.ParseRequest([]byte("GET / HTTP/1.1\r\nX-Empty:\r\n\r\n"))
		if err != nil || len(r.Headers) != 1 || string(r.Headers[0].Value) != "" {
			t.Fatalf("err=%v v=%q", err, r.Headers[0].Value)
		}
	})
	t.Run("tab-OWS", func(t *testing.T) {
		r, err := p.ParseRequest([]byte("GET / HTTP/1.1\r\nX:\t v \t\r\n\r\n"))
		if err != nil || string(r.Headers[0].Value) != "v" {
			t.Fatalf("err=%v v=%q", err, r.Headers[0].Value)
		}
	})
	t.Run("duplicate-headers", func(t *testing.T) {
		r, err := p.ParseRequest([]byte("GET / HTTP/1.1\r\nSet: a\r\nSet: b\r\n\r\n"))
		if err != nil || len(r.Headers) != 2 {
			t.Fatalf("err=%v n=%d (duplicates must be preserved)", err, len(r.Headers))
		}
	})
	t.Run("no-reason-status", func(t *testing.T) {
		r, err := p.ParseResponse([]byte("HTTP/1.1 200\r\nX: y\r\n\r\n"))
		if err != nil || r.StatusCode != 200 || len(r.Reason) != 0 {
			t.Fatalf("err=%v code=%d reason=%q", err, r.StatusCode, r.Reason)
		}
	})
	t.Run("crlf-in-body", func(t *testing.T) {
		body := "line1\r\nline2\r\nline3"
		r, err := p.ParseRequest([]byte("POST /d HTTP/1.1\r\nContent-Length: 19\r\n\r\n" + body))
		if err != nil || string(r.Body) != body {
			t.Fatalf("err=%v body=%q", err, r.Body)
		}
	})
	t.Run("over-128-headers", func(t *testing.T) {
		var sb strings.Builder
		sb.WriteString("GET / HTTP/1.1\r\n")
		for i := 0; i < 200; i++ {
			fmt.Fprintf(&sb, "H%d: v%d\r\n", i, i)
		}
		sb.WriteString("\r\n")
		r, err := p.ParseRequest([]byte(sb.String()))
		if err != nil || len(r.Headers) != 200 {
			t.Fatalf("err=%v n=%d (must heap-grow past scratch cap)", err, len(r.Headers))
		}
		if string(r.Headers[199].Name) != "H199" {
			t.Fatalf("last header wrong: %q", r.Headers[199].Name)
		}
	})
}

// ---- Fuzz: the parser must NEVER panic on arbitrary bytes (invariant #2) ----

func FuzzParseRequest(f *testing.F) {
	for _, s := range sizes {
		if b := readFix("req-" + s + ".bin"); b != nil {
			f.Add(b)
		}
	}
	for _, seed := range []string{
		"", "\r\n", "GET", "GET / HTTP/1.1", "GET / HTTP/1.1\r\n",
		":\r\n\r\n", "GET / HTTP/1.1\r\n:\r\n\r\n", "\n", "G\r", "GET  HTTP/1.1\r\n\r\n",
		"GET / HTTP/1.1\r\nNoColon\r\n\r\n", "GET / HTTP/1.1\r\nHost: x",
	} {
		f.Add([]byte(seed))
	}
	p := NewFastParser()
	f.Fuzz(func(t *testing.T, data []byte) {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("PANIC on input %q: %v", data, r)
				}
			}()
			if r, err := p.ParseRequest(data); err == nil {
				// on success, accessing every field must also not panic
				_ = string(r.Method) + string(r.Path) + string(r.Version) + string(r.Body)
				for i := range r.Headers {
					_ = string(r.Headers[i].Name) + string(r.Headers[i].Value)
				}
			}
		}()
	})
}

func FuzzParseResponse(f *testing.F) {
	for _, s := range sizes {
		if b := readFix("resp-" + s + ".bin"); b != nil {
			f.Add(b)
		}
	}
	for _, seed := range []string{"", "\r\n", "HTTP/1.1", "HTTP/1.1 200 OK\r\n", "HTTP/1.1 2 OK\r\n\r\n", "HTTP/1.1 abc OK\r\n\r\n"} {
		f.Add([]byte(seed))
	}
	p := NewFastParser()
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("PANIC on input %q: %v", data, r)
			}
		}()
		if r, err := p.ParseResponse(data); err == nil {
			_ = string(r.Version) + string(r.Reason) + string(r.Body)
			for i := range r.Headers {
				_ = string(r.Headers[i].Name) + string(r.Headers[i].Value)
			}
		}
	})
}

// ---- Zero-copy + allocation-free invariants (#2) ----
//
// The whole point of this parser is that it aliases the input buffer and
// allocates nothing on the hot path. These lock that contract in as tests, not
// just benchmark ReportAllocs output.

// sink keeps parsed results reachable so AllocsPerRun's closure isn't optimized away.
var (
	sinkReq  *Request
	sinkResp *Response
)

func TestParseRequestZeroAlloc(t *testing.T) {
	p := NewFastParser()
	buf := load(t, "req-1kb.bin")
	if _, err := p.ParseRequest(buf); err != nil { // warm + validate before measuring
		t.Fatal(err)
	}
	if n := testing.AllocsPerRun(1000, func() {
		r, err := p.ParseRequest(buf)
		if err != nil {
			t.Fatal(err)
		}
		sinkReq = r
	}); n != 0 {
		t.Errorf("ParseRequest allocated %v allocs/op, want 0", n)
	}
}

func TestParseResponseZeroAlloc(t *testing.T) {
	p := NewFastParser()
	buf := load(t, "resp-1kb.bin")
	if _, err := p.ParseResponse(buf); err != nil {
		t.Fatal(err)
	}
	if n := testing.AllocsPerRun(1000, func() {
		r, err := p.ParseResponse(buf)
		if err != nil {
			t.Fatal(err)
		}
		sinkResp = r
	}); n != 0 {
		t.Errorf("ParseResponse allocated %v allocs/op, want 0", n)
	}
}

// TestParseAliasesInputBuffer proves the returned fields are VIEWS into the
// input, not copies: mutating the buffer in place changes what they report.
func TestParseAliasesInputBuffer(t *testing.T) {
	p := NewFastParser()
	raw := []byte("POST /p HTTP/1.1\r\nHost: ex.com\r\nX-A: v1\r\n\r\nbody!")
	r, err := p.ParseRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(r.Method) != "POST" || string(r.Header("X-A")) != "v1" || string(r.Body) != "body!" {
		t.Fatalf("pre-mutation: method=%q x-a=%q body=%q", r.Method, r.Header("X-A"), r.Body)
	}
	// Mutate the underlying bytes in place (same lengths); aliased slices must follow.
	raw[0] = 'X'                   // method: POST -> XOST
	copy(r.Headers[1].Value, "z2") // X-A value: v1 -> z2 (writes through the alias)
	raw[len(raw)-1] = '?'          // body: body! -> body?
	if string(r.Method) != "XOST" {
		t.Errorf("Method is a copy, not a view: got %q", r.Method)
	}
	if string(r.Header("X-A")) != "z2" {
		t.Errorf("header Value is a copy, not a view: got %q", r.Header("X-A"))
	}
	if string(r.Body) != "body?" {
		t.Errorf("Body is a copy, not a view: got %q", r.Body)
	}
}

// ---- Parser reuse & result-invalidation contract (#3) ----
//
// A Parser reuses one Request/Response struct + scratch header array. The doc
// says the returned pointer is valid only until the next like call. These pin
// down that reuse, the invalidation of the prior handle, and per-call resets.

func TestParserReuseInvalidatesPriorRequest(t *testing.T) {
	p := NewFastParser()
	first, err := p.ParseRequest([]byte("GET /one HTTP/1.1\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\nxx"))
	if err != nil {
		t.Fatal(err)
	}
	if string(first.Path) != "/one" || len(first.Headers) != 3 || string(first.Body) != "xx" {
		t.Fatalf("first: path=%q headers=%d body=%q", first.Path, len(first.Headers), first.Body)
	}
	second, err := p.ParseRequest([]byte("POST /two HTTP/1.1\r\nX: y\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	// Same backing struct is reused → the two handles are the same pointer...
	if first != second {
		t.Fatalf("expected reused *Request, got distinct pointers")
	}
	// ...so the earlier handle now reflects the SECOND parse (documented invalidation).
	if string(first.Method) != "POST" || string(first.Path) != "/two" {
		t.Errorf("prior result not invalidated: method=%q path=%q", first.Method, first.Path)
	}
	// Header slice length must reset — no stale headers from the 3-header parse.
	if len(second.Headers) != 1 || string(second.Headers[0].Name) != "X" {
		t.Errorf("headers not reset: n=%d %+v", len(second.Headers), second.Headers)
	}
	// Body must reset too — first had "xx", second has none.
	if len(second.Body) != 0 {
		t.Errorf("body not reset: got %q", second.Body)
	}
}

func TestParserReuseResetsResponse(t *testing.T) {
	p := NewFastParser()
	if _, err := p.ParseResponse([]byte("HTTP/1.1 200 OK\r\nA: 1\r\nB: 2\r\n\r\nhi")); err != nil {
		t.Fatal(err)
	}
	r2, err := p.ParseResponse([]byte("HTTP/1.1 404 Not Found\r\nX: y\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if r2.StatusCode != 404 || string(r2.Reason) != "Not Found" {
		t.Errorf("status line not reset: code=%d reason=%q", r2.StatusCode, r2.Reason)
	}
	if len(r2.Headers) != 1 || string(r2.Headers[0].Name) != "X" {
		t.Errorf("headers not reset: n=%d", len(r2.Headers))
	}
	if len(r2.Body) != 0 {
		t.Errorf("body not reset: got %q", r2.Body)
	}
}

// Request and Response use SEPARATE scratch, so a parsed request survives a
// subsequent response parse (and vice versa) — both handles stay valid at once.
func TestRequestAndResponseUseSeparateScratch(t *testing.T) {
	p := NewFastParser()
	req, err := p.ParseRequest([]byte("GET /r HTTP/1.1\r\nA: 1\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := p.ParseResponse([]byte("HTTP/1.1 201 Created\r\nB: 2\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if string(req.Path) != "/r" || len(req.Headers) != 1 || string(req.Headers[0].Name) != "A" {
		t.Errorf("request clobbered by response parse: path=%q headers=%+v", req.Path, req.Headers)
	}
	if resp.StatusCode != 201 {
		t.Errorf("resp code=%d want 201", resp.StatusCode)
	}
}
