package fastparser

// HTTP/2 + gRPC parser for the eBPF fast path.
//
// Unlike the HTTP/1.1 parser (stateless, one call per assembled req/resp blob),
// HTTP/2 needs PERSISTENT per-connection state: HPACK's dynamic table is
// per-connection, per-direction, and cumulative, so header blocks must be decoded
// in arrival order across the whole connection — you cannot decode one stream's
// headers in isolation. HTTP2Conn is that persistent object: created once per
// connection, fed ordered bytes incrementally via Feed, emitting completed unary
// streams via TakeComplete.
//
// Framing: the 9-byte HTTP/2 frame header (length/type/flags/stream_id) is NOT
// HPACK-compressed, so we hand-parse it (trivial) to slice frames and demux by
// stream_id. Only the header BLOCK is HPACK — decoded with a persistent
// hpack.Decoder per direction (stdlib). Hand-parsing the frame header also avoids
// http2.Framer's cross-call CONTINUATION state, which doesn't fit incremental feeds.
//
// Scope: UNARY (1:1) request/response. Streaming (1:N / N:1 / N:M) is not emitted
// (a streaming stream never completes-as-unary); a per-stream body cap bounds its
// memory until the connection ends.

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/net/http2/hpack"
)

const (
	h2FrameData         = 0x0
	h2FrameHeaders      = 0x1
	h2FrameRSTStream    = 0x3
	h2FrameSettings     = 0x4
	h2FrameContinuation = 0x9

	h2FlagEndStream  = 0x1
	h2FlagEndHeaders = 0x4
	h2FlagPadded     = 0x8
	h2FlagPriority   = 0x20

	h2FrameHeaderLen = 9

	// Guards against a corrupt/huge length field and unbounded per-stream growth.
	h2MaxFrameSize        = 1 << 20  // 1 MB single frame
	h2MaxStreamBodyBytes  = 8 << 20  // 8 MB accumulated per stream, then dropped
	h2DefaultHeaderTable  = 4096
	h2ClientPreface       = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
)

var errShortFrame = errors.New("http2: short frame payload")

// HTTP2Stream is one RPC/exchange, keyed by stream_id. Request and response share
// the same stream_id, told apart by direction.
type HTTP2Stream struct {
	StreamID    uint32
	Method      string
	Path        string
	Authority   string
	StatusCode  int
	IsGRPC      bool
	GRPCStatus  string
	ReqHeaders  []Header
	RespHeaders []Header
	ReqBody     []byte
	RespBody    []byte
	reqEnded    bool
	respEnded   bool
	dropped     bool // exceeded body cap (likely streaming) — never emitted
}

// dirState is the persistent decode state for ONE direction.
type dirState struct {
	dec              *hpack.Decoder
	buf              []byte // leftover partial-frame bytes carried across Feed calls
	pendingHdr       []byte // header block being accumulated across HEADERS+CONTINUATION
	pendingStream    uint32
	pendingEndStream bool
}

// HTTP2Conn is the persistent per-connection parser. NOT concurrency-safe: it is
// owned by one connection and mutated under that connection's lock.
type HTTP2Conn struct {
	req            dirState // client -> server
	resp           dirState // server -> client
	streams        map[uint32]*HTTP2Stream
	prefaceSkipped bool
	failed         bool // gap or HPACK desync — decoding this connection is abandoned
}

func NewHTTP2Conn() *HTTP2Conn {
	return &HTTP2Conn{streams: make(map[uint32]*HTTP2Stream)}
}

// Failed reports whether the connection was abandoned (gap / HPACK desync). Once
// failed, Feed is a no-op — HPACK cannot resynchronize mid-connection.
func (c *HTTP2Conn) Failed() bool { return c.failed }

// Fail marks the connection unrecoverable. Called by the tracker on a byte gap
// (dropped chunk), which desyncs HPACK for the remainder of the connection.
func (c *HTTP2Conn) Fail() { c.failed = true }

func (c *HTTP2Conn) dir(isRequest bool) *dirState {
	if isRequest {
		return &c.req
	}
	return &c.resp
}

// Feed consumes ordered, contiguous bytes for one direction (isRequest =
// client->server). It decodes every whole frame now buffered and retains any
// trailing partial frame for the next call. Returns an error only on a
// malformed/undecodable stream, after which the connection is marked failed.
func (c *HTTP2Conn) Feed(isRequest bool, data []byte) error {
	if c.failed || len(data) == 0 {
		return nil
	}
	d := c.dir(isRequest)
	if d.dec == nil {
		d.dec = hpack.NewDecoder(h2DefaultHeaderTable, nil)
	}
	d.buf = append(d.buf, data...)

	// Strip the 24-byte client connection preface (request direction, once).
	if isRequest && !c.prefaceSkipped {
		pf := []byte(h2ClientPreface)
		if len(d.buf) < len(pf) {
			if bytes.HasPrefix(pf, d.buf) {
				return nil // still accumulating the preface
			}
			c.prefaceSkipped = true // not a preface (started mid-connection)
		} else {
			d.buf = bytes.TrimPrefix(d.buf, pf)
			c.prefaceSkipped = true
		}
	}

	consumed, err := c.parseFrames(d, isRequest)
	if err != nil {
		c.failed = true
		return err
	}
	// Compact the leftover partial frame to the front.
	if consumed > 0 {
		n := copy(d.buf, d.buf[consumed:])
		d.buf = d.buf[:n]
	}
	return nil
}

// parseFrames walks complete frames from d.buf, returning the number of bytes
// consumed (stops at the first partial frame).
func (c *HTTP2Conn) parseFrames(d *dirState, isRequest bool) (int, error) {
	buf := d.buf
	off := 0
	for {
		if len(buf)-off < h2FrameHeaderLen {
			break
		}
		length := int(buf[off])<<16 | int(buf[off+1])<<8 | int(buf[off+2])
		if length > h2MaxFrameSize {
			return off, errors.New("http2: frame length exceeds cap")
		}
		total := h2FrameHeaderLen + length
		if len(buf)-off < total {
			break // partial frame; wait for more bytes
		}
		typ := buf[off+3]
		flags := buf[off+4]
		streamID := binary.BigEndian.Uint32(buf[off+5:off+9]) & 0x7fffffff
		payload := buf[off+9 : off+total]
		if err := c.handleFrame(d, isRequest, typ, flags, streamID, payload); err != nil {
			return off, err
		}
		off += total
	}
	return off, nil
}

func (c *HTTP2Conn) handleFrame(d *dirState, isRequest bool, typ, flags byte, streamID uint32, payload []byte) error {
	switch typ {
	case h2FrameHeaders:
		block, err := stripHeadersPadding(flags, payload)
		if err != nil {
			return err
		}
		if d.pendingHdr != nil && d.pendingStream != streamID {
			return errors.New("http2: interleaved header block")
		}
		d.pendingStream = streamID
		d.pendingEndStream = flags&h2FlagEndStream != 0
		d.pendingHdr = append(d.pendingHdr, block...)
		if flags&h2FlagEndHeaders != 0 {
			return c.decodePending(d, isRequest)
		}
	case h2FrameContinuation:
		if d.pendingHdr == nil || d.pendingStream != streamID {
			return errors.New("http2: unexpected CONTINUATION")
		}
		d.pendingHdr = append(d.pendingHdr, payload...)
		if flags&h2FlagEndHeaders != 0 {
			return c.decodePending(d, isRequest)
		}
	case h2FrameData:
		data, err := stripDataPadding(flags, payload)
		if err != nil {
			return err
		}
		c.applyData(streamID, isRequest, data, flags&h2FlagEndStream != 0)
	case h2FrameRSTStream, h2FrameSettings:
		// Ignored: RST/SETTINGS don't carry request/response content. (SETTINGS
		// header-table-size changes are honored via HPACK size-update instructions
		// inside the header block, which hpack.Decoder handles.)
	}
	return nil
}

// decodePending HPACK-decodes the accumulated header block (persistent dynamic
// table) and applies it to the stream.
func (c *HTTP2Conn) decodePending(d *dirState, isRequest bool) error {
	fields, err := d.dec.DecodeFull(d.pendingHdr)
	streamID := d.pendingStream
	endStream := d.pendingEndStream
	d.pendingHdr = nil
	if err != nil {
		return err // HPACK desync — unrecoverable for this connection
	}
	c.applyHeaders(streamID, isRequest, fields, endStream)
	return nil
}

func (c *HTTP2Conn) stream(streamID uint32) *HTTP2Stream {
	s, ok := c.streams[streamID]
	if !ok {
		s = &HTTP2Stream{StreamID: streamID}
		c.streams[streamID] = s
	}
	return s
}

func (c *HTTP2Conn) applyHeaders(streamID uint32, isRequest bool, fields []hpack.HeaderField, endStream bool) {
	s := c.stream(streamID)
	if s.dropped {
		return
	}
	for _, hf := range fields {
		if isRequest {
			switch hf.Name {
			case ":method":
				s.Method = hf.Value
			case ":path":
				s.Path = hf.Value
			case ":authority":
				s.Authority = hf.Value
			case "content-type":
				if strings.HasPrefix(hf.Value, "application/grpc") {
					s.IsGRPC = true
				}
			}
			s.ReqHeaders = append(s.ReqHeaders, Header{Name: []byte(hf.Name), Value: []byte(hf.Value)})
		} else {
			switch hf.Name {
			case ":status":
				if n, e := strconv.Atoi(hf.Value); e == nil {
					s.StatusCode = n
				}
			case "content-type":
				if strings.HasPrefix(hf.Value, "application/grpc") {
					s.IsGRPC = true
				}
			case "grpc-status":
				s.GRPCStatus = hf.Value
			}
			s.RespHeaders = append(s.RespHeaders, Header{Name: []byte(hf.Name), Value: []byte(hf.Value)})
		}
	}
	if endStream {
		c.markEnded(s, isRequest)
	}
}

func (c *HTTP2Conn) applyData(streamID uint32, isRequest bool, data []byte, endStream bool) {
	s := c.stream(streamID)
	if s.dropped {
		return
	}
	if isRequest {
		if len(s.ReqBody)+len(data) > h2MaxStreamBodyBytes {
			s.dropped = true
			return
		}
		s.ReqBody = append(s.ReqBody, data...)
		if endStream {
			c.markEnded(s, true)
		}
	} else {
		if len(s.RespBody)+len(data) > h2MaxStreamBodyBytes {
			s.dropped = true
			return
		}
		s.RespBody = append(s.RespBody, data...)
		if endStream {
			c.markEnded(s, false)
		}
	}
}

func (c *HTTP2Conn) markEnded(s *HTTP2Stream, isRequest bool) {
	if isRequest {
		s.reqEnded = true
	} else {
		s.respEnded = true
	}
}

// TakeComplete removes and returns unary streams whose request AND response have
// both ended (END_STREAM seen each way). Dropped streams are discarded.
func (c *HTTP2Conn) TakeComplete() []*HTTP2Stream {
	if len(c.streams) == 0 {
		return nil
	}
	var out []*HTTP2Stream
	for id, s := range c.streams {
		if s.dropped {
			delete(c.streams, id)
			continue
		}
		if s.reqEnded && s.respEnded {
			out = append(out, s)
			delete(c.streams, id)
		}
	}
	return out
}

// ToRequestResponse maps a completed stream onto the fast path's Request/Response
// so the existing encode + produce pipeline is reused unchanged. gRPC bodies are
// unwrapped from the length-prefixed framing and base64-encoded (binary protobuf
// is not valid UTF-8 for the JSON payload).
func (s *HTTP2Stream) ToRequestResponse() (*Request, *Response) {
	version := "HTTP/2.0"
	if s.IsGRPC {
		version = "gRPC"
	}

	reqBody, respBody := s.ReqBody, s.RespBody
	if s.IsGRPC {
		reqBody = []byte(base64.StdEncoding.EncodeToString(unwrapGRPC(reqBody)))
		respBody = []byte(base64.StdEncoding.EncodeToString(unwrapGRPC(respBody)))
	}

	reqHeaders := s.ReqHeaders
	// Downstream host filtering reads the "host" header; h2 carries it as
	// :authority, so surface it under "host" too.
	if s.Authority != "" {
		reqHeaders = append(reqHeaders, Header{Name: []byte("host"), Value: []byte(s.Authority)})
	}

	req := &Request{
		Method:  []byte(s.Method),
		Path:    []byte(s.Path),
		Version: []byte(version),
		Headers: reqHeaders,
		Body:    reqBody,
	}
	resp := &Response{
		Version:    []byte(version),
		StatusCode: s.StatusCode,
		Headers:    s.RespHeaders,
		Body:       respBody,
	}
	return req, resp
}

// unwrapGRPC extracts message payloads from gRPC's length-prefixed DATA framing:
// [1B compressed flag][4B big-endian length][message], concatenating messages.
// Compressed messages are passed through as-is (decompression is a TODO).
func unwrapGRPC(data []byte) []byte {
	var out []byte
	off := 0
	for off+5 <= len(data) {
		msgLen := int(binary.BigEndian.Uint32(data[off+1 : off+5]))
		if off+5+msgLen > len(data) {
			break
		}
		out = append(out, data[off+5:off+5+msgLen]...)
		off += 5 + msgLen
	}
	return out
}

// stripHeadersPadding removes PADDED pad length + padding and PRIORITY's 5 bytes,
// returning the header block fragment.
func stripHeadersPadding(flags byte, payload []byte) ([]byte, error) {
	p := payload
	padLen := 0
	if flags&h2FlagPadded != 0 {
		if len(p) < 1 {
			return nil, errShortFrame
		}
		padLen = int(p[0])
		p = p[1:]
	}
	if flags&h2FlagPriority != 0 {
		if len(p) < 5 {
			return nil, errShortFrame
		}
		p = p[5:]
	}
	if padLen > len(p) {
		return nil, errShortFrame
	}
	return p[:len(p)-padLen], nil
}

// stripDataPadding removes PADDED pad length + trailing padding from a DATA frame.
func stripDataPadding(flags byte, payload []byte) ([]byte, error) {
	p := payload
	if flags&h2FlagPadded != 0 {
		if len(p) < 1 {
			return nil, errShortFrame
		}
		padLen := int(p[0])
		p = p[1:]
		if padLen > len(p) {
			return nil, errShortFrame
		}
		p = p[:len(p)-padLen]
	}
	return p, nil
}
