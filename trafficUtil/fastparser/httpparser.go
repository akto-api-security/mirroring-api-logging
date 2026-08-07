package fastparser
// Package httpparser is a zero-copy, allocation-free HTTP/1.x message parser.
//
// It parses one complete request or response held entirely in a single []byte.
// All returned fields (method, path, header names/values, body) are SLICES that
// alias the input buffer — nothing is copied. The parser returns an error on
// malformed input instead of panicking, so callers can log-and-skip.
//
// Chunked bodies are the one exception to "nothing is copied": when a message
// carries `Transfer-Encoding: chunked`, the body is decoded IN PLACE — the chunk
// data is compacted toward the front of the body region (each decoded byte only
// ever moves leftward, over framing already consumed), and Body is returned as a
// sub-slice of the input. It still aliases the input buffer (zero allocation),
// but the framing bytes in the body region are overwritten. Callers therefore
// must own the buffer they pass in; in this codebase the parse buffer is a fresh
// per-message allocation (fragmentsToBytes / convertToSingleByteArr), so this is
// safe. Identity / Content-Length bodies are untouched: pure alias, no writes.
//
// A Parser holds reusable scratch state; create one per goroutine and reuse it.

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
)

var ErrMalformed = errors.New("httpparser: malformed HTTP message")

// ErrGunzip is a SOFT error: the message parsed fine (status line + headers are
// valid) but its gzip body could not be decoded. ParseResponse returns a VALID
// *Response with an empty Body alongside this error, so a caller that recognises
// it (errors.Is) can keep the pair — with an empty response body — instead of
// dropping it. Callers that treat every error as fatal will simply drop the pair,
// which is safe. Distinct from ErrMalformed, which always returns a nil result.
var ErrGunzip = errors.New("httpparser: gzip body decode failed")

const maxHeaders = 128

// Header is a name/value pair, both slices into the parsed buffer (zero-copy).
type Header struct {
	Name  []byte
	Value []byte
}

// Request is the parsed request. All fields alias the input buffer.
type Request struct {
	Method  []byte
	Path    []byte // raw request-target, e.g. "/?request-num=9"
	Version []byte // e.g. "HTTP/1.1"
	Headers []Header
	Body    []byte
}

// Host returns the value of the Host header (zero-copy slice into the buffer),
// or nil if absent. Case-insensitive on the header name.
func (r *Request) Host() []byte { return headerValue(r.Headers, "Host") }

// Header returns the first matching header value (case-insensitive), or nil.
func (r *Request) Header(name string) []byte { return headerValue(r.Headers, name) }

func headerValue(hs []Header, name string) []byte {
	for i := range hs {
		if asciiEqualFold(hs[i].Name, name) {
			return hs[i].Value
		}
	}
	return nil
}

func asciiEqualFold(b []byte, s string) bool {
	if len(b) != len(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		c1, c2 := b[i], s[i]
		if 'A' <= c1 && c1 <= 'Z' {
			c1 += 'a' - 'A'
		}
		if 'A' <= c2 && c2 <= 'Z' {
			c2 += 'a' - 'A'
		}
		if c1 != c2 {
			return false
		}
	}
	return true
}

// Response is the parsed response. All fields alias the input buffer.
type Response struct {
	Version    []byte
	StatusCode int
	Reason     []byte // reason phrase, e.g. "OK" (may be empty)
	Headers    []Header
	Body       []byte
}

// Parser holds reusable scratch so parsing allocates nothing on the hot path.
// Not safe for concurrent use; use one Parser per goroutine.
type Parser struct {
	req         Request
	resp        Response
	reqHeaders  [maxHeaders]Header
	respHeaders [maxHeaders]Header
	// Gunzip, when true, makes ParseResponse decompress gzip response bodies
	// (Content-Encoding: gzip) after de-chunking. This is the one path that
	// ALLOCATES and whose Body does NOT alias the input (decompression expands),
	// so it's opt-in; leave false to keep the zero-copy/zero-alloc default. Set
	// by the caller from utils.FastParserGunzip.
	Gunzip bool

	HandleChunkEncoding bool
}

func NewFastParser() *Parser { return &Parser{} }

// ParseRequest parses one complete HTTP request from buf. The returned *Request
// is owned by the Parser and valid until the next ParseRequest call.
func (p *Parser) ParseRequest(buf []byte) (*Request, error) {
	r := &p.req
	r.Method, r.Path, r.Version, r.Body = nil, nil, nil, nil
	r.Headers = p.reqHeaders[:0]

	n := len(buf)
	nl := bytes.IndexByte(buf, '\n')
	if nl < 1 || buf[nl-1] != '\r' {
		return nil, ErrMalformed
	}
	line := buf[:nl-1]
	sp1 := bytes.IndexByte(line, ' ')
	if sp1 < 0 {
		return nil, ErrMalformed
	}
	r.Method = line[:sp1]
	rest := line[sp1+1:]
	sp2 := bytes.IndexByte(rest, ' ')
	if sp2 < 0 {
		return nil, ErrMalformed
	}
	r.Path = rest[:sp2]
	r.Version = rest[sp2+1:]

	i, err := parseHeaders(buf, nl+1, &r.Headers, p.reqHeaders[:])
	if err != nil {
		return nil, err
	}
	body := buf[i:n]
	if p.HandleChunkEncoding && isChunked(r.Headers) {
		body, err = decodeChunkedInPlace(body)
		if err != nil {
			return nil, err
		}
	}
	r.Body = body
	return r, nil
}

// ParseResponse parses one complete HTTP response from buf.
//
// Return contract: on a hard failure (bad status line/headers) it returns
// (nil, ErrMalformed). When Gunzip is enabled and the gzip body fails to decode,
// it returns a VALID *Response with an empty Body plus ErrGunzip (a soft error) —
// callers may keep such a response. All other successes return (resp, nil).
func (p *Parser) ParseResponse(buf []byte) (*Response, error) {
	r := &p.resp
	r.Version, r.Reason, r.Body = nil, nil, nil
	r.StatusCode = 0
	r.Headers = p.respHeaders[:0]

	n := len(buf)
	nl := bytes.IndexByte(buf, '\n')
	if nl < 1 || buf[nl-1] != '\r' {
		return nil, ErrMalformed
	}
	line := buf[:nl-1]
	sp1 := bytes.IndexByte(line, ' ')
	if sp1 < 0 {
		return nil, ErrMalformed
	}
	r.Version = line[:sp1]
	after := line[sp1+1:]
	sp2 := bytes.IndexByte(after, ' ')
	var codeBytes []byte
	if sp2 < 0 {
		codeBytes = after // "HTTP/1.1 200" with no reason
	} else {
		codeBytes = after[:sp2]
		r.Reason = after[sp2+1:]
	}
	if len(codeBytes) != 3 || codeBytes[0] < '0' || codeBytes[0] > '9' {
		return nil, ErrMalformed
	}
	r.StatusCode = int(codeBytes[0]-'0')*100 + int(codeBytes[1]-'0')*10 + int(codeBytes[2]-'0')

	i, err := parseHeaders(buf, nl+1, &r.Headers, p.respHeaders[:])
	if err != nil {
		return nil, err
	}
	body := buf[i:n]
	// Decoding order mirrors the wire order in reverse: on the wire the body is
	// gzipped first, then chunk-framed, so we de-chunk first, then gunzip.
	if p.HandleChunkEncoding && isChunked(r.Headers) {
		body, err = decodeChunkedInPlace(body)
		if err != nil {
			return nil, err
		}
	}
	if p.Gunzip && isGzip(r.Headers) {
		dec, derr := gunzipBody(body)
		if derr != nil {
			// Soft failure: status line + headers are valid, only the body could
			// not be decompressed. Return the usable response with an empty body
			// and ErrGunzip so the caller can keep the pair (see ErrGunzip doc).
			r.Body = nil
			return r, ErrGunzip
		}
		body = dec
	}
	r.Body = body
	return r, nil
}

// parseHeaders scans header lines starting at offset `start`, appending into
// *out (backed by scratch). Returns the offset just past the blank line (body start).
func parseHeaders(buf []byte, start int, out *[]Header, scratch []Header) (int, error) {
	n := len(buf)
	i := start
	for {
		if i >= n {
			return 0, ErrMalformed // no header terminator
		}
		if buf[i] == '\r' { // blank line -> end of headers
			if i+1 >= n || buf[i+1] != '\n' {
				return 0, ErrMalformed
			}
			return i + 2, nil
		}
		rel := bytes.IndexByte(buf[i:], '\n')
		if rel < 0 {
			return 0, ErrMalformed
		}
		abs := i + rel
		if abs < 1 || buf[abs-1] != '\r' {
			return 0, ErrMalformed
		}
		lineSeg := buf[i : abs-1]
		colon := bytes.IndexByte(lineSeg, ':')
		if colon < 0 {
			return 0, ErrMalformed
		}
		name := lineSeg[:colon]
		val := lineSeg[colon+1:]
		for len(val) > 0 && (val[0] == ' ' || val[0] == '\t') {
			val = val[1:]
		}
		for len(val) > 0 && (val[len(val)-1] == ' ' || val[len(val)-1] == '\t') {
			val = val[:len(val)-1]
		}
		if len(*out) < len(scratch) {
			*out = append(*out, Header{Name: name, Value: val})
		} else {
			*out = append(*out, Header{Name: name, Value: val}) // overflow: heap-grows (rare)
		}
		i = abs + 1
	}
}

// isChunked reports whether the message body uses chunked transfer-encoding.
// Per RFC 7230 §3.3.1 "chunked" must be the final coding; we match it as the
// last token of the last Transfer-Encoding header (case-insensitive), which also
// covers the common single-value "Transfer-Encoding: chunked".
func isChunked(hs []Header) bool {
	var te []byte
	for i := range hs {
		if asciiEqualFold(hs[i].Name, "Transfer-Encoding") {
			te = hs[i].Value // last one wins
		}
	}
	if te == nil {
		return false
	}
	// take the token after the last comma, trim OWS
	if c := bytes.LastIndexByte(te, ','); c >= 0 {
		te = te[c+1:]
	}
	for len(te) > 0 && (te[0] == ' ' || te[0] == '\t') {
		te = te[1:]
	}
	for len(te) > 0 && (te[len(te)-1] == ' ' || te[len(te)-1] == '\t') {
		te = te[:len(te)-1]
	}
	return asciiEqualFold(te, "chunked")
}

// isGzip reports whether the body is gzip-compressed via Content-Encoding.
// Last Content-Encoding header wins; value matched case-insensitively after OWS
// trim. Only the single-coding "gzip" is treated as gzip (coding lists like
// "gzip, br" are left alone — decoding a stacked encoding is out of scope).
func isGzip(hs []Header) bool {
	var ce []byte
	for i := range hs {
		if asciiEqualFold(hs[i].Name, "Content-Encoding") {
			ce = hs[i].Value // last one wins
		}
	}
	for len(ce) > 0 && (ce[0] == ' ' || ce[0] == '\t') {
		ce = ce[1:]
	}
	for len(ce) > 0 && (ce[len(ce)-1] == ' ' || ce[len(ce)-1] == '\t') {
		ce = ce[:len(ce)-1]
	}
	return asciiEqualFold(ce, "gzip")
}

// gunzipBody decompresses a gzip body. UNLIKE the rest of the parser this
// ALLOCATES (decompression expands; the result can't alias or fit the input),
// so it runs only behind the Parser.Gunzip opt-in. Any gzip error (bad header,
// corrupt stream, truncated) returns ErrMalformed rather than panicking, matching
// the parser's log-and-skip contract.
func gunzipBody(body []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, ErrMalformed
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		return nil, ErrMalformed
	}
	return out, nil
}

// decodeChunkedInPlace decodes an HTTP/1.1 chunked-transfer body IN PLACE and
// returns the decoded body as a sub-slice of the same backing array — zero
// allocation. Decoded bytes only ever move leftward (the framing they replace was
// already consumed), so a single read cursor r ahead of a write cursor w never
// clobbers unread data. Chunk extensions (";name=value" after the size) and
// trailer headers (after the terminating 0-chunk) are ignored. Malformed framing
// (bad hex size, truncated chunk, missing CRLF, no terminator) returns
// ErrMalformed rather than panicking.
func decodeChunkedInPlace(body []byte) ([]byte, error) {
	n := len(body)
	w, r := 0, 0
	for {
		// ---- chunk-size line: hex digits up to ';' (extension) or CR ----
		size := 0
		digits := 0
		for r < n {
			c := body[r]
			hv, ok := hexVal(c)
			if !ok {
				break
			}
			// guard against overflow / absurd sizes
			if size > (1<<28) { // 256MB ceiling; larger is malformed for our use
				return nil, ErrMalformed
			}
			size = size<<4 | int(hv)
			digits++
			r++
		}
		if digits == 0 {
			return nil, ErrMalformed // size line had no hex digit
		}
		// skip optional chunk extension: everything up to CR
		for r < n && body[r] != '\r' {
			r++
		}
		// require CRLF ending the size line
		if r+1 >= n || body[r] != '\r' || body[r+1] != '\n' {
			return nil, ErrMalformed
		}
		r += 2

		if size == 0 {
			// last chunk. trailers/final CRLF (if any) are ignored.
			return body[:w], nil
		}

		// ---- chunk data: exactly `size` bytes, then CRLF ----
		if r+size+2 > n { // data + trailing CRLF must fit
			return nil, ErrMalformed
		}
		// compact leftward; copy handles w<r safely (and w==r is a no-op copy).
		copy(body[w:w+size], body[r:r+size])
		w += size
		r += size
		if body[r] != '\r' || body[r+1] != '\n' {
			return nil, ErrMalformed
		}
		r += 2
	}
}

// hexVal returns the value of a single hex digit and whether c was a hex digit.
func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
