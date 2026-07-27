// Package httpparser is a zero-copy, allocation-free HTTP/1.x message parser.
//
// It parses one complete request or response held entirely in a single []byte.
// All returned fields (method, path, header names/values, body) are SLICES that
// alias the input buffer — nothing is copied. The parser returns an error on
// malformed input instead of panicking, so callers can log-and-skip.
//
// A Parser holds reusable scratch state; create one per goroutine and reuse it.
package utils
 
import (
	"bytes"
	"errors"
)

var ErrMalformed = errors.New("httpparser: malformed HTTP message")

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
	r.Body = buf[i:n]
	return r, nil
}

// ParseResponse parses one complete HTTP response from buf.
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
	r.Body = buf[i:n]
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
