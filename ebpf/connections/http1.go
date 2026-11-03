package connections

// HTTP/1 framing and pairing.
//
// Each direction is a byte stream, cut into messages by HTTP framing (header
// block, then Content-Length, chunked encoding, or until close). Requests
// queue in order; a response, once its headers are in, takes its request:
//
//   - normally (one request in flight) it is the last request before the
//     response, and only if nothing in the request stream came after it: no
//     other request began (epoch) and no request byte was lost after the last
//     one delivered (both directions stamp both chunk counters, so the
//     response's first chunk says how many request chunks preceded it).
//     Otherwise the response is an orphan. A request whose response was lost
//     is dropped, never paired with the next response.
//   - a pipelining client (a new request while the previous one had no
//     response bytes yet) is paired strictly in order. If its framing is then
//     lost the connection is dropped, since order can't be rebuilt.
//
// A pair is emitted as soon as the response is complete. Lost bytes inside a
// body keep framing intact (the body is cut at the hole); lost bytes anywhere
// else desync that direction until the next run of the stream starts with a
// fresh message.

import (
	"bytes"
)

const (
	phStart      uint8 = iota // between messages
	phHead                    // reading the header block
	phBody                    // Content-Length body
	phChunkSize               // chunk-size line
	phChunkData               // chunk data
	phChunkCRLF               // CRLF after chunk data
	phTrailer                 // trailer lines after the last chunk
	phUntilClose              // response body delimited by close
)

const (
	maxHeaderBytes = 64 << 10
	maxQueued      = 64
	maxLineBytes   = 1024
)

type h1msg struct {
	buf       []byte // stored bytes; nil once emitted or dropped
	seen      int    // bytes of the message seen, stored or not
	truncated bool   // buf holds only a prefix (cap or lost bytes)
	done      bool   // framing complete
	ord       uint32 // request-direction counter at the message's first chunk
	epoch     uint32 // request: http1State.reqEpoch when it started
	respOrd   uint32 // request: response-direction counter when it started
	headLen   int
	head      bool // request method HEAD
	connect   bool // request method CONNECT
	expect    bool // request: Expect: 100-continue
}

type framer struct {
	synced bool
	phase  uint8
	remain int64
	m      *h1msg
	line   int // bytes in the current chunk-size / trailer line
	lineCR bool
	lineHx int64 // chunk size parsed so far
	lineSz bool  // still in the hex digits of the size line
}

type http1State struct {
	fr      [2]framer
	queue   []*h1msg // requests without a response yet, oldest first
	partner *h1msg   // request of the response being framed
	status  int      // status of the response being framed

	pipelined     bool
	lastReqOrd    uint32 // request-direction counter of the last request chunk
	reqEpoch      uint32 // bumped whenever a request may have begun
	abandonExpect bool   // a final answer came before a 100-continue body
}

func (h *http1State) reset(c *conn) {
	for d := range h.fr {
		c.dropMsg(h.fr[d].m)
	}
	for _, m := range h.queue {
		c.dropMsg(m)
	}
	c.dropMsg(h.partner)
	*h = http1State{}
}

func (c *conn) dropMsg(m *h1msg) {
	if m == nil || m.buf == nil {
		return
	}
	c.addHeld(-len(m.buf))
	putBuf(m.buf)
	m.buf = nil
}

func (c *conn) store(m *h1msg, b []byte) {
	m.seen += len(b)
	if m.buf == nil || m.truncated {
		return
	}
	if room := groupCap() - len(m.buf); len(b) > room {
		b = b[:max(room, 0)]
		m.truncated = true
		cappedMessages.Add(1)
	}
	m.buf = append(m.buf, b...)
	c.addHeld(len(b))
}

// runStart is true for the first chunk of a run of dir with nothing of that
// run lost before it.
func (c *conn) onHTTP1(dir uint8, data []byte, lost int64, runStart bool, reqOrd, otherOrd uint32) {
	h := &c.h1
	if lost > 0 {
		c.h1Lose(dir, lost)
		if c.state != stateHTTP1 {
			return
		}
	}
	f := &h.fr[dir]
	if dir == c.reqDir {
		h.lastReqOrd = reqOrd
		if runStart && (!f.synced || f.phase == phStart) {
			h.reqEpoch++ // a request we may not be able to parse begins here
		}
	}
	if dir == c.reqDir && h.abandonExpect && runStart {
		// The client got a final answer to "Expect: 100-continue" and may
		// send its next request instead of the body.
		h.abandonExpect = false
		if f.m != nil && f.m.expect && f.m.seen == f.m.headLen && requestLineStart(data) == 1 {
			c.dropMsg(f.m)
			f.m, f.phase = nil, phStart
		}
	}
	if !f.synced {
		// Resume only where a run really starts (runStart is false when
		// bytes of this chunk's own run were lost before it).
		if !runStart || !looksLikeStart(dir == c.reqDir, data) {
			return
		}
		f.synced, f.phase, f.m = true, phStart, nil
	}
	c.h1Feed(dir, data, reqOrd, otherOrd) // otherOrd is the response counter for requests
}

func looksLikeStart(isReq bool, b []byte) bool {
	if isReq {
		return requestLineStart(b) == 1
	}
	return bytes.HasPrefix(b, []byte("HTTP/1."))
}

// h1Lose accounts for n bytes of dir that never arrived.
func (c *conn) h1Lose(dir uint8, n int64) {
	f := &c.h1.fr[dir]
	if n <= 0 || !f.synced {
		return
	}
	switch f.phase {
	case phBody, phChunkData:
		if n <= f.remain {
			f.remain -= n
			f.m.seen += int(n)
			f.m.truncated = true
			if f.remain == 0 {
				if f.phase == phBody {
					c.h1Complete(dir)
				} else {
					f.phase, f.remain = phChunkCRLF, 2
				}
			}
			return
		}
	case phUntilClose:
		f.m.seen += int(n)
		f.m.truncated = true
		return
	}
	c.h1Desync(dir)
}

// h1Desync gives up on the message in progress in dir. The stream resumes at
// its next run that starts with a fresh message.
func (c *conn) h1Desync(dir uint8) {
	h := &c.h1
	if h.pipelined {
		desyncedConns.Add(1)
		c.ignore()
		return
	}
	f := &h.fr[dir]
	if dir == c.reqDir {
		h.reqEpoch++
	}
	if m := f.m; m != nil {
		if dir == c.reqDir {
			c.unqueue(m)
		} else if h.partner != nil {
			c.dropMsg(h.partner)
			h.partner = nil
		}
		c.dropMsg(m)
	}
	*f = framer{}
	desyncs.Add(1)
}

func (c *conn) unqueue(m *h1msg) {
	q := c.h1.queue
	for i := range q {
		if q[i] == m {
			c.h1.queue = append(q[:i], q[i+1:]...)
			return
		}
	}
}

// h1Feed frames data (synced stream). ords are the chunk counters of the
// request / response direction stamped on this chunk.
func (c *conn) h1Feed(dir uint8, data []byte, reqOrd, respOrd uint32) {
	f := &c.h1.fr[dir]
	isReq := dir == c.reqDir
	for len(data) > 0 && c.state == stateHTTP1 && f.synced {
		switch f.phase {
		case phStart:
			if isReq && (data[0] == '\r' || data[0] == '\n') {
				data = data[1:] // tolerated empty lines between requests
				continue
			}
			if isReq {
				c.h1.reqEpoch++
			}
			f.m = &h1msg{buf: getBuf(), ord: reqOrd, epoch: c.h1.reqEpoch, respOrd: respOrd}
			f.phase = phHead
		case phHead:
			k := headerEnd(f.m.buf, data)
			if k < 0 {
				k = len(data)
			}
			c.store(f.m, data[:k])
			data = data[k:]
			if !bytes.HasSuffix(f.m.buf, []byte("\r\n\r\n")) {
				if f.m.seen > maxHeaderBytes {
					c.h1Desync(dir)
				}
				continue
			}
			f.m.headLen = f.m.seen
			if isReq {
				c.h1RequestHead(respOrd)
			} else {
				c.h1ResponseHead()
			}
		case phBody, phChunkData:
			n := int(min(f.remain, int64(len(data))))
			c.store(f.m, data[:n])
			data = data[n:]
			f.remain -= int64(n)
			if f.remain == 0 {
				if f.phase == phBody {
					c.h1Complete(dir)
				} else {
					f.phase, f.remain = phChunkCRLF, 2
				}
			}
		case phChunkCRLF:
			n := int(min(f.remain, int64(len(data))))
			c.store(f.m, data[:n])
			data = data[n:]
			if f.remain -= int64(n); f.remain == 0 {
				f.phase, f.line, f.lineHx, f.lineSz = phChunkSize, 0, 0, true
			}
		case phChunkSize, phTrailer:
			nl := bytes.IndexByte(data, '\n')
			n := len(data)
			if nl >= 0 {
				n = nl + 1
			}
			line := data[:n]
			c.store(f.m, line)
			data = data[n:]
			if f.phase == phChunkSize {
				for _, ch := range line {
					if !f.lineSz {
						break
					}
					if v, ok := hexDigit(ch); ok {
						if f.lineHx > 1<<40 {
							c.h1Desync(dir)
							return
						}
						f.lineHx = f.lineHx<<4 | int64(v)
					} else {
						f.lineSz = false
					}
				}
			}
			f.line += n
			if f.line > maxLineBytes {
				c.h1Desync(dir)
				return
			}
			if nl < 0 {
				continue
			}
			empty := f.line <= 2
			size := f.lineHx
			f.line, f.lineHx, f.lineSz = 0, 0, true
			if f.phase == phTrailer {
				if empty {
					c.h1Complete(dir)
				}
			} else if size == 0 {
				f.phase = phTrailer
			} else {
				f.phase, f.remain = phChunkData, size
			}
		case phUntilClose:
			c.store(f.m, data)
			data = nil
		}
	}
}

func hexDigit(ch byte) (byte, bool) {
	switch {
	case ch >= '0' && ch <= '9':
		return ch - '0', true
	case ch >= 'a' && ch <= 'f':
		return ch - 'a' + 10, true
	case ch >= 'A' && ch <= 'F':
		return ch - 'A' + 10, true
	}
	return 0, false
}

// headerEnd returns how many bytes of data complete the header block that
// prev started (the "\r\n\r\n" may straddle the two), or -1.
func headerEnd(prev, data []byte) int {
	const term = "\r\n\r\n"
	for j := 3; j >= 1; j-- {
		if bytes.HasSuffix(prev, []byte(term[:j])) && bytes.HasPrefix(data, []byte(term[j:])) {
			return 4 - j
		}
	}
	if i := bytes.Index(data, []byte(term)); i >= 0 {
		return i + 4
	}
	return -1
}

func (c *conn) h1RequestHead(respOrd uint32) {
	h := &c.h1
	f := &h.fr[c.reqDir]
	m := f.m
	if requestLineStart(m.buf) != 1 {
		c.h1Desync(c.reqDir)
		return
	}
	m.head = bytes.HasPrefix(m.buf, []byte("HEAD "))
	m.connect = bytes.HasPrefix(m.buf, []byte("CONNECT "))
	hdr := m.buf[:m.headLen]
	m.expect = headerHas(hdr, "expect", "100-continue")

	if len(h.queue) > 0 && h.queue[len(h.queue)-1].respOrd == respOrd {
		// A new request while the previous one has not had a single response
		// byte since it started: pipelining. Older queued requests did get response bytes (lost
		// ones), so they will never be answered in order.
		if !h.pipelined {
			pipelinedConns.Add(1)
			last := h.queue[len(h.queue)-1]
			for _, o := range h.queue[:len(h.queue)-1] {
				c.dropMsg(o)
			}
			h.queue = append(h.queue[:0], last)
		}
		h.pipelined = true
	}
	if len(h.queue) >= maxQueued {
		if h.pipelined {
			c.ignore()
			return
		}
		c.dropMsg(h.queue[0])
		h.queue = h.queue[1:]
	}
	h.queue = append(h.queue, m)

	switch cl, chunked := bodyFraming(hdr); {
	case chunked:
		f.phase, f.line, f.lineHx, f.lineSz = phChunkSize, 0, 0, true
	case cl > 0:
		f.phase, f.remain = phBody, cl
	default:
		c.h1Complete(c.reqDir)
	}
}

func (c *conn) h1ResponseHead() {
	h := &c.h1
	dir := 1 - c.reqDir
	f := &h.fr[dir]
	m := f.m
	b := m.buf
	if len(b) < 12 || !bytes.HasPrefix(b, []byte("HTTP/1.")) || b[8] != ' ' {
		c.h1Desync(dir)
		return
	}
	status := 0
	for _, ch := range b[9:12] {
		if ch < '0' || ch > '9' {
			c.h1Desync(dir)
			return
		}
		status = status*10 + int(ch-'0')
	}
	h.status = status
	if status >= 100 && status < 200 && status != 101 {
		// Informational: no body, and the request is still waiting.
		c.dropMsg(m)
		f.m, f.phase = nil, phStart
		return
	}

	h.partner = c.takePartner(m.ord)
	if h.partner == nil {
		orphanMessages.Add(1)
		c.dropMsg(m) // keep framing it, but don't buffer
	}

	hdr := m.buf
	if hdr != nil {
		hdr = hdr[:m.headLen]
	}
	req := h.partner
	switch cl, chunked := bodyFraming(hdr); {
	case status == 101, req != nil && req.connect && status/100 == 2:
		c.h1Complete(dir)
		c.ignore() // the connection now carries another protocol
	case req != nil && req.head, status == 204, status == 304:
		c.h1Complete(dir)
	case chunked:
		f.phase, f.line, f.lineHx, f.lineSz = phChunkSize, 0, 0, true
	case cl >= 0:
		if f.phase, f.remain = phBody, cl; cl == 0 {
			c.h1Complete(dir)
		}
	case hdr == nil:
		// Orphan without framing headers: can't tell where it ends.
		c.h1Desync(dir)
	default:
		f.phase = phUntilClose
	}
}

// takePartner picks the request a response answers. ord is the
// request-direction counter stamped on the response's first chunk.
func (c *conn) takePartner(ord uint32) *h1msg {
	h := &c.h1
	q := h.queue
	if len(q) == 0 {
		return nil
	}
	i := 0
	if !h.pipelined {
		// The last request, if nothing in the request stream followed it;
		// everything before it lost its response.
		i = -1
		for j := range q {
			if q[j].ord <= ord {
				i = j
			}
		}
		if i < 0 {
			return nil
		}
		if ord != h.lastReqOrd || q[i].epoch != h.reqEpoch {
			// The partner is a request we don't have: everything up to i
			// lost its response, and this response is an orphan.
			for _, o := range q[:i+1] {
				orphanMessages.Add(1)
				c.dropMsg(o)
			}
			h.queue = append(q[:0], q[i+1:]...)
			return nil
		}
		for _, o := range q[:i] {
			orphanMessages.Add(1)
			c.dropMsg(o)
		}
	}
	m := q[i]
	h.queue = append(q[:0], q[i+1:]...)
	return m
}

// h1Complete ends the message being framed in dir.
func (c *conn) h1Complete(dir uint8) {
	h := &c.h1
	f := &h.fr[dir]
	m := f.m
	f.m, f.phase = nil, phStart
	if m == nil {
		return
	}
	m.done = true
	if dir == c.reqDir {
		// Answered early (response came before the body ended): free it now.
		if !c.queued(m) && m != h.partner {
			c.dropMsg(m)
		}
		return
	}
	req := h.partner
	h.partner = nil
	if req != nil && m.buf != nil && req.buf != nil {
		if req.truncated || m.truncated {
			truncatedPairs.Add(1)
		}
		emitHTTP1(c, req.buf, m.buf)
	}
	if req != nil && req.expect && !req.done && req.seen == req.headLen && h.status >= 200 {
		h.abandonExpect = true
	}
	c.dropMsg(m)
	c.dropMsg(req)
	if req != nil {
		req.truncated = true // body bytes still to come are only counted
	}
}

func (c *conn) queued(m *h1msg) bool {
	for _, q := range c.h1.queue {
		if q == m {
			return true
		}
	}
	return false
}

// h1Finish ends the connection: a close-delimited response is complete; one
// cut short by the server is emitted with what arrived.
func (c *conn) h1Finish() {
	unansweredAtEnd.Add(uint64(len(c.h1.queue)))
	f := &c.h1.fr[1-c.reqDir]
	if f.synced && f.m != nil && f.m.headLen > 0 {
		f.m.truncated = f.m.truncated || f.phase != phUntilClose
		c.h1Complete(1 - c.reqDir)
	}
}

// bodyFraming reads Content-Length (-1 if absent) and chunked encoding.
func bodyFraming(hdr []byte) (cl int64, chunked bool) {
	if hdr == nil {
		return -1, false
	}
	if headerHas(hdr, "transfer-encoding", "chunked") {
		return -1, true
	}
	v := headerValue(hdr, "content-length")
	if v == nil {
		return -1, false
	}
	n := int64(0)
	for _, ch := range v {
		if ch < '0' || ch > '9' || n > 1<<40 {
			return -1, false
		}
		n = n*10 + int64(ch-'0')
	}
	return n, false
}

// headerValue returns the trimmed value of the first header named name
// (lower case) in an HTTP/1 header block.
func headerValue(head []byte, name string) []byte {
	for len(head) > 0 {
		nl := bytes.IndexByte(head, '\n')
		if nl < 0 {
			return nil
		}
		line := head[:nl]
		head = head[nl+1:]
		if bytes.IndexByte(line, ':') != len(name) {
			continue
		}
		match := true
		for i := 0; i < len(name); i++ {
			ch := line[i]
			if 'A' <= ch && ch <= 'Z' {
				ch += 'a' - 'A'
			}
			if ch != name[i] {
				match = false
				break
			}
		}
		if match {
			return bytes.TrimSpace(line[len(name)+1:])
		}
	}
	return nil
}

func headerHas(head []byte, name, token string) bool {
	v := headerValue(head, name)
	return v != nil && bytes.Contains(bytes.ToLower(v), []byte(token))
}
