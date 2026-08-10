package fastparser

import (
	"bytes"
	"testing"
)

// mkHeaders builds a []Header from alternating name,value string args. Shared by
// the isChunked / isGzip table tests (and any other header-level unit test).
func mkHeaders(pairs ...string) []Header {
	hs := make([]Header, 0, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		hs = append(hs, Header{Name: []byte(pairs[i]), Value: []byte(pairs[i+1])})
	}
	return hs
}

// parserOpt configures a Parser built by newParser (Go has no per-test setup
// hooks; a functional-options constructor is the idiomatic shared-setup stand-in).
type parserOpt func(*Parser)

func withChunk() parserOpt  { return func(p *Parser) { p.HandleChunkEncoding = true } }
func withGunzip() parserOpt { return func(p *Parser) { p.Gunzip = true } }

// newParser returns a Parser with the given options applied. Call sites read as
// e.g. newParser(withChunk()) or newParser(withChunk(), withGunzip()).
func newParser(opts ...parserOpt) *Parser {
	p := NewFastParser()
	for _, o := range opts {
		o(p)
	}
	return p
}

// trimOWS: leading/trailing space & tab only, nothing in the middle.
func TestTrimOWS(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"x", "x"},
		{"  x", "x"},
		{"x  ", "x"},
		{"\t x \t", "x"},
		{"   ", ""}, // all-OWS -> empty
		{"\t\t", ""},
		{"a b", "a b"}, // interior space preserved
		{" a b ", "a b"},
		{"gzip", "gzip"},
	}
	for _, c := range cases {
		got := trimOWS([]byte(c.in))
		if string(got) != c.want {
			t.Errorf("trimOWS(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// nil in -> nil/empty out, no panic
	if got := trimOWS(nil); len(got) != 0 {
		t.Errorf("trimOWS(nil) = %q, want empty", got)
	}
}

// lastHeaderValue: LAST match wins (unlike headerValue which returns the first),
// case-insensitive on the name, nil when absent.
func TestLastHeaderValue(t *testing.T) {
	hs := []Header{
		{Name: []byte("Content-Encoding"), Value: []byte("br")},
		{Name: []byte("X-Other"), Value: []byte("v")},
		{Name: []byte("content-encoding"), Value: []byte("gzip")}, // mixed case, later
	}
	if got := lastHeaderValue(hs, "Content-Encoding"); string(got) != "gzip" {
		t.Errorf("last-wins failed: got %q want %q", got, "gzip")
	}
	if got := lastHeaderValue(hs, "CONTENT-ENCODING"); string(got) != "gzip" {
		t.Errorf("case-insensitive name failed: got %q", got)
	}
	if got := lastHeaderValue(hs, "X-Missing"); got != nil {
		t.Errorf("absent header must be nil, got %q", got)
	}
	// contrast with headerValue (first-wins) so the intentional difference is pinned.
	if got := headerValue(hs, "Content-Encoding"); string(got) != "br" {
		t.Errorf("headerValue should be FIRST-wins (br), got %q", got)
	}
}

// Micro-benchmark: trimOWS is now on the hot per-header path (parseHeaders), so
// keep an eye on it. Should be a handful of ns and 0 allocs.
func BenchmarkTrimOWS(b *testing.B) {
	in := []byte("\t  application/json  \t")
	b.ReportAllocs()
	var out []byte
	for b.Loop() {
		out = trimOWS(in)
	}
	if !bytes.Equal(out, []byte("application/json")) {
		b.Fatalf("unexpected: %q", out)
	}
}
