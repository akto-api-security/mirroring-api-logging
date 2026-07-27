// Package kafkashape encodes parsed HTTP (from httpparser) into the Akto Kafka
// JSON payload — hand-rolled, zero-allocation, single pass. Output is always
// valid JSON: invalid UTF-8 in bodies is replaced with U+FFFD and control chars
// are escaped.
//
// Integration is parse-then-encode:
//
//	b := kafkashape.NewBuilder()          // one per goroutine — NOT concurrency-safe
//	p := b.Parser()
//	req,  _ := p.ParseRequest(reqBuf)
//	resp, _ := p.ParseResponse(respBuf)
//	out := b.Encode(req, resp, meta)      // Kafka JSON
//	method, path, host := req.Method, req.Path, req.Host()  // already parsed — free
//
// The returned bytes alias the Builder's internal buffer; copy (e.g. string(out))
// before the next Encode on the same Builder.
package utils 

import (
	"strconv"
	"unicode/utf8"
)

// Meta holds the non-parsed fields (from TrafficContext + globals). Emitted as
// strings to match the legacy map[string]string payload data.
type Meta struct {
	SourceIP      string // -> "ip"
	DestIP        string // -> "destIp"
	TimeUnix      int64  // -> "time"
	AktoAccountID string // -> "akto_account_id"
	VxlanID       int    // -> "akto_vxlan_id"
	IsPending     bool   // -> "is_pending"
	Source        string // -> "source"
	Direction     int    // -> "direction"
	ProcessID     uint32 // -> "process_id"
	SocketID      uint32 // -> "socket_id"
	DaemonsetID   string // -> "daemonset_id"
	ProcessName   string // -> "process_name"
	EnableGraph   bool   // -> "enable_graph"
	Tag           string // -> "tag" (omitted if empty)
}

// Builder reuses a parser + output buffer. NOT safe for concurrent use — one per goroutine.
type Builder struct {
	p       *Parser
	scratch []byte
}

func NewBuilder() *Builder {
	return &Builder{p: NewFastParser(), scratch: make([]byte, 0, 8192)}
}

// Parser exposes the reusable parser so callers can parse first (and read
// method/path/Host off the result) and then Encode.
func (b *Builder) Parser() *Parser { return b.p }

// Encode writes the Kafka JSON from already-parsed structs into the Builder's
// reused buffer. Returned bytes are valid until the next Encode on this Builder.
func (b *Builder) Encode(req *Request, resp *Response, m *Meta) []byte {
	buf := b.scratch[:0]
	buf = append(buf, `{"method":`...)
	buf = appendJSONString(buf, req.Method)
	buf = kv(buf, "path", req.Path)
	buf = kv(buf, "type", req.Version)
	buf = kvStatusCode(buf, resp.StatusCode)
	buf = append(buf, `,"status":`...)
	buf = appendStatus(buf, resp.StatusCode, resp.Reason)
	buf = append(buf, `,"requestHeaders":`...)
	buf = appendHeaders(buf, req.Headers)
	buf = append(buf, `,"responseHeaders":`...)
	buf = appendHeaders(buf, resp.Headers)
	buf = kv(buf, "requestPayload", req.Body)
	buf = kv(buf, "responsePayload", resp.Body)
	buf = kvStr(buf, "ip", m.SourceIP)
	buf = kvStr(buf, "destIp", m.DestIP)
	buf = kvInt(buf, "time", m.TimeUnix)
	buf = kvStr(buf, "akto_account_id", m.AktoAccountID)
	buf = kvInt(buf, "akto_vxlan_id", int64(m.VxlanID))
	buf = kvBool(buf, "is_pending", m.IsPending)
	buf = kvStr(buf, "source", m.Source)
	buf = kvInt(buf, "direction", int64(m.Direction))
	buf = kvInt(buf, "process_id", int64(m.ProcessID))
	buf = kvInt(buf, "socket_id", int64(m.SocketID))
	buf = kvStr(buf, "daemonset_id", m.DaemonsetID)
	buf = kvStr(buf, "process_name", m.ProcessName)
	buf = kvBool(buf, "enable_graph", m.EnableGraph)
	if m.Tag != "" {
		buf = kvStr(buf, "tag", m.Tag)
	}
	buf = append(buf, '}')
	b.scratch = buf
	return buf
}

// ---- JSON encoding helpers (zero-alloc; a leading comma is assumed) ----

func kv(dst []byte, key string, val []byte) []byte {
	return appendJSONString(appendKey(dst, key), val)
}
func kvStr(dst []byte, key, val string) []byte {
	dst = appendKey(dst, key)
	dst = append(dst, '"')
	dst = appendJSONEscapedStr(dst, val)
	return append(dst, '"')
}
func kvInt(dst []byte, key string, val int64) []byte {
	dst = appendKey(dst, key)
	dst = append(dst, '"')
	dst = strconv.AppendInt(dst, val, 10)
	return append(dst, '"')
}
func kvBool(dst []byte, key string, val bool) []byte {
	dst = appendKey(dst, key)
	if val {
		return append(dst, `"true"`...)
	}
	return append(dst, `"false"`...)
}
func kvStatusCode(dst []byte, code int) []byte {
	dst = append(dst, `,"statusCode":"`...)
	dst = strconv.AppendInt(dst, int64(code), 10)
	return append(dst, '"')
}
func appendKey(dst []byte, key string) []byte {
	dst = append(dst, ',', '"')
	dst = append(dst, key...)
	return append(dst, '"', ':')
}
func appendStatus(dst []byte, code int, reason []byte) []byte {
	dst = append(dst, '"')
	dst = strconv.AppendInt(dst, int64(code), 10)
	if len(reason) > 0 {
		dst = append(dst, ' ')
		dst = appendJSONEscaped(dst, reason)
	}
	return append(dst, '"')
}
func appendHeaders(dst []byte, hs []Header) []byte {
	dst = append(dst, '{')
	for i := range hs {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = appendJSONString(dst, hs[i].Name)
		dst = append(dst, ':')
		dst = appendJSONString(dst, hs[i].Value)
	}
	return append(dst, '}')
}
func appendJSONString(dst, s []byte) []byte {
	dst = append(dst, '"')
	dst = appendJSONEscaped(dst, s)
	return append(dst, '"')
}

const hexdigits = "0123456789abcdef"

// appendJSONEscaped escapes ", \, control chars (<0x20), and replaces invalid
// UTF-8 with U+FFFD so the output is always valid JSON. Valid input takes the
// allocation-free fast path.
func appendJSONEscaped(dst, s []byte) []byte {
	start, i := 0, 0
	for i < len(s) {
		c := s[i]
		if c < 0x80 {
			if c >= 0x20 && c != '"' && c != '\\' {
				i++
				continue
			}
			dst = append(dst, s[start:i]...)
			dst = appendEscByte(dst, c)
			i++
			start = i
			continue
		}
		r, size := utf8.DecodeRune(s[i:])
		if r == utf8.RuneError && size == 1 {
			dst = append(dst, s[start:i]...)
			dst = append(dst, '\\', 'u', 'f', 'f', 'f', 'd')
			i++
			start = i
			continue
		}
		i += size
	}
	return append(dst, s[start:]...)
}

func appendJSONEscapedStr(dst []byte, s string) []byte {
	start, i := 0, 0
	for i < len(s) {
		c := s[i]
		if c < 0x80 {
			if c >= 0x20 && c != '"' && c != '\\' {
				i++
				continue
			}
			dst = append(dst, s[start:i]...)
			dst = appendEscByte(dst, c)
			i++
			start = i
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			dst = append(dst, s[start:i]...)
			dst = append(dst, '\\', 'u', 'f', 'f', 'f', 'd')
			i++
			start = i
			continue
		}
		i += size
	}
	return append(dst, s[start:]...)
}

func appendEscByte(dst []byte, c byte) []byte {
	switch c {
	case '"':
		return append(dst, '\\', '"')
	case '\\':
		return append(dst, '\\', '\\')
	case '\n':
		return append(dst, '\\', 'n')
	case '\r':
		return append(dst, '\\', 'r')
	case '\t':
		return append(dst, '\\', 't')
	default:
		return append(dst, '\\', 'u', '0', '0', hexdigits[c>>4], hexdigits[c&0xf])
	}
}
