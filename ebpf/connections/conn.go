package connections

// Per-connection capture state.
//
// The kernel sends every record of one connection (open, data, close) to the
// same ring buffer shard, and each shard has exactly one reader goroutine, so a
// conn sees its events in syscall order and is never touched concurrently. No
// locks, timers or goroutines live here.
//
// Every data event says how many bytes of its direction were not delivered
// right before it (attr.Lost: ring full, failed user read, chunk-limit cut,
// ingest paused). So each direction is a byte stream whose holes are known
// exactly. HTTP/1 is framed on those streams (http1.go); HTTP/2 is decoded
// from them (http2.go) and abandoned at the first hole.

import (
	"bytes"
	"sync"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/structs"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/fastparser"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/kafkaUtil"
)

type connState uint8

const (
	stateUnknown connState = iota // classify from the first bytes
	stateHTTP1
	stateHTTP2
	stateTLS    // handshake ciphertext; waiting for the SSL uprobes to flip the conn
	stateIgnore // not HTTP, or unrecoverable; events are dropped
)

const (
	dirRecv uint8 = 0 // read by the traced process
	dirSend uint8 = 1 // written by the traced process
)

// Bytes buffered per direction while the protocol is still unknown.
const maxClassifyBytes = 64 << 10

type conn struct {
	id    structs.ConnID
	laddr uint32
	lport uint16 // local port, host byte order (id.Port is the remote port, network order)

	ssl    bool
	state  connState
	reqDir uint8

	// Counter of the other direction stamped on the last event of each
	// direction. When it moved, the other side spoke in between: this event
	// starts a new run. Lost events count too, so this holds across holes.
	lastOther [2]uint32
	seenDir   [2]bool
	// Bytes of a direction dropped in userspace (ingest filters) that the
	// next delivered chunk must account for.
	ulost [2]uint32

	h1 http1State
	h2 *fastparser.HTTP2Conn

	// stateUnknown
	pre [2][]byte
	// Bytes were lost before detection finished: wait for a run that starts
	// cleanly (a message start) and detect from there.
	preLost bool

	ctx *kafkaUtil.TrafficContext // built on the first pair (parser.go)

	lastSeen int64 // unix nanos of the last event
	held     int   // bytes currently buffered
}

var bufPool = sync.Pool{New: func() any { b := make([]byte, 0, 4096); return &b }}

func getBuf() []byte { return (*bufPool.Get().(*[]byte))[:0] }

func putBuf(b []byte) {
	if b == nil || cap(b) > 1<<20 {
		return
	}
	b = b[:0]
	bufPool.Put(&b)
}

// lostUnknownBytes stands for a hole of unknown size: larger than any body, so
// framing never counts it as part of a message and resyncs instead.
const lostUnknownBytes int64 = 1 << 62

// addLost adds lost counts, keeping the unknown-size flag.
func addLost(a, b uint32) uint32 {
	flag := (a | b) & structs.LostUnknown
	sum := uint64(a&^structs.LostUnknown) + uint64(b&^structs.LostUnknown)
	if sum >= uint64(structs.LostUnknown) {
		sum = uint64(structs.LostUnknown) - 1
	}
	return uint32(sum) | flag
}

// lostSize turns a lost count into bytes for framing; an unknown-size hole is
// lostUnknownBytes.
func lostSize(v uint32) int64 {
	if v&structs.LostUnknown != 0 {
		return lostUnknownBytes
	}
	return int64(v)
}

func (c *conn) addHeld(n int) {
	c.held += n
	heldBytes.Add(int64(n))
}

// resetCapture drops all buffered state and restarts protocol detection, as
// after the TLS flip (the kernel restarts its counters at that point).
func (c *conn) resetCapture() {
	c.h1.reset(c)
	c.dropPre()
	c.preLost = false
	c.h2 = nil
	c.state = stateUnknown
	c.lastOther, c.seenDir, c.ulost = [2]uint32{}, [2]bool{}, [2]uint32{}
}

func (c *conn) dropPre() {
	for d := range c.pre {
		c.addHeld(-len(c.pre[d]))
		putBuf(c.pre[d])
		c.pre[d] = nil
	}
}

func (c *conn) ignore() {
	if c.state != stateIgnore {
		ignoredConns.Add(1)
		if c.state == stateUnknown {
			ignoredUnknown.Add(1)
		}
	}
	c.resetCapture()
	c.state = stateIgnore
	ignoreInKernel(c.id)
}

// dropData records a data chunk that userspace chose not to deliver.
func (c *conn) dropData(attr *structs.SocketDataEventAttr, n int) {
	dir := dirRecv
	if attr.Bytes_sent > 0 {
		dir = dirSend
	}
	if attr.Ssl == c.ssl {
		c.ulost[dir] = addLost(c.ulost[dir], addLost(attr.Lost, uint32(n)))
	}
}

// onData handles one data chunk. data is only valid during the call.
func (c *conn) onData(attr *structs.SocketDataEventAttr, data []byte) {
	if attr.Ssl && !c.ssl {
		// SSL uprobes took over: earlier bytes were ciphertext.
		c.resetCapture()
		c.ssl = true
	}
	if attr.Ssl != c.ssl || c.state == stateIgnore {
		return
	}

	dir, own, other := dirRecv, attr.ReadEventsCount, attr.WriteEventsCount
	if attr.Bytes_sent > 0 {
		dir, own, other = dirSend, attr.WriteEventsCount, attr.ReadEventsCount
	}
	lostCount := addLost(attr.Lost, c.ulost[dir])
	lost := lostSize(lostCount)
	// Bytes dropped in userspace may sit in this run; count them as such.
	cleanRun := attr.LostRun == 0 && c.ulost[dir] == 0
	c.ulost[dir] = 0
	runStart := !c.seenDir[dir] || other != c.lastOther[dir]
	c.lastOther[dir], c.seenDir[dir] = other, true
	if lostCount != 0 {
		lostBytes.Add(uint64(lostCount &^ structs.LostUnknown))
		if lostCount&structs.LostUnknown != 0 {
			lostUnknown.Add(1)
		}
	}

	switch c.state {
	case stateUnknown:
		if lost > 0 {
			c.dropPre()
			c.preLost = true
		}
		if c.preLost {
			if !runStart || !cleanRun {
				return
			}
			c.preLost = false
		}
		c.classify(dir, data, attr)
	case stateHTTP2:
		c.onHTTP2(dir, data, lost > 0)
	case stateHTTP1:
		reqCnt, respCnt := own, other // both directions' counters at this chunk
		if dir != c.reqDir {
			reqCnt, respCnt = other, own
		}
		c.onHTTP1(dir, data, lost, runStart && cleanRun, reqCnt, respCnt)
	}
}

// onClose finishes the connection; lost* are the bytes of each direction that
// never reached us after the last delivered chunk.
func (c *conn) onClose(lostRead, lostWrite uint32) {
	if c.state == stateHTTP1 {
		c.h1Lose(dirRecv, lostSize(addLost(lostRead, c.ulost[dirRecv])))
		if c.state == stateHTTP1 {
			c.h1Lose(dirSend, lostSize(addLost(lostWrite, c.ulost[dirSend])))
		}
	}
	c.finish()
}

// finish emits whatever is complete and frees the connection's buffers.
func (c *conn) finish() {
	if c.state == stateTLS && c.seenDir[dirRecv] {
		// Handshake bytes but never any plaintext: the TLS library of this
		// process is not hooked (or its fd could not be resolved).
		tlsWithoutPlaintext.Add(1)
	}
	switch c.state {
	case stateHTTP1:
		c.h1Finish()
	case stateHTTP2:
		c.produceHTTP2()
	}
	c.resetCapture()
	c.state = stateIgnore
}

// wipe drops everything buffered for the connection, without emitting it
// (memory pressure). Only the connection's identity is kept: HTTP/1 and
// unclassified connections resume at the next clean message start, exactly as
// after lost bytes. HTTP/2 can't rebuild its HPACK state, so it is ignored from
// here on.
func (c *conn) wipe() {
	switch {
	case c.state == stateUnknown:
		c.dropPre()
		c.preLost = true
	case c.state == stateHTTP1:
		epoch := c.h1.reqEpoch + 1 // nothing queued before the wipe may be paired
		c.h1.reset(c)
		c.h1.reqEpoch = epoch
	case c.state == stateHTTP2:
		c.ignore()
	default: // TLS handshake or ignored: nothing buffered
		return
	}
	memWipes.Add(1)
}

// ---------------------------------------------------------------------------
// Protocol detection

type wireKind uint8

const (
	wireNeedMore wireKind = iota
	wireHTTP1Request
	wireHTTP2Preface
	wireTLS
	wireOther
)

const h2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

func classifyBytes(b []byte) wireKind {
	if len(b) == 0 {
		return wireNeedMore
	}
	if b[0] == 0x16 { // TLS handshake record
		if len(b) < 2 {
			return wireNeedMore
		}
		if b[1] == 0x03 {
			return wireTLS
		}
		return wireOther
	}
	if len(b) < len(h2Preface) && bytes.HasPrefix([]byte(h2Preface), b) {
		return wireNeedMore
	}
	if bytes.HasPrefix(b, []byte(h2Preface)) {
		return wireHTTP2Preface
	}
	switch requestLineStart(b) {
	case 1:
		return wireHTTP1Request
	case 0:
		return wireNeedMore
	}
	return wireOther
}

// requestLineStart reports whether b starts with "TOKEN " where TOKEN is an
// upper-case method of 3..16 letters: 1 yes, 0 need more bytes, -1 no.
func requestLineStart(b []byte) int {
	for i := 0; i < len(b) && i <= 16; i++ {
		ch := b[i]
		if ch == ' ' {
			if i >= 3 {
				return 1
			}
			return -1
		}
		if ch < 'A' || ch > 'Z' {
			return -1
		}
	}
	if len(b) <= 16 {
		return 0
	}
	return -1
}

// remotePort is the peer's port in host byte order (the kernel keeps it as the
// network sent it, big-endian).
func (c *conn) remotePort() uint16 { return c.id.Port>>8 | c.id.Port<<8 }

// ignoredPort reports whether the server side of the connection listens on an
// ignored port. reqDir tells which side is the server: requests read by the
// traced process mean it accepted the connection on its local port.
func (c *conn) ignoredPort(reqDir uint8) bool {
	if reqDir == dirRecv {
		return c.lport != 0 && ignoredServerPort(c.lport)
	}
	return ignoredServerPort(c.remotePort())
}

func (c *conn) classify(dir uint8, data []byte, attr *structs.SocketDataEventAttr) {
	if len(c.pre[dir])+len(data) > maxClassifyBytes {
		c.ignore()
		return
	}
	if c.pre[dir] == nil {
		c.pre[dir] = getBuf()
	}
	c.pre[dir] = append(c.pre[dir], data...)
	c.addHeld(len(data))

	switch classifyBytes(c.pre[dir]) {
	case wireNeedMore:
		return
	case wireTLS:
		c.dropPre()
		c.state = stateTLS
	case wireHTTP1Request:
		if c.ignoredPort(dir) {
			c.ignore()
			return
		}
		first := c.pre[dir]
		c.pre[dir] = nil
		c.addHeld(-len(first))
		c.dropPre()
		c.state, c.reqDir = stateHTTP1, dir
		c.h1.fr[0].synced, c.h1.fr[1].synced = true, true
		reqOrd, respOrd := attr.ReadEventsCount, attr.WriteEventsCount
		if dir == dirSend {
			reqOrd, respOrd = respOrd, reqOrd
		}
		c.h1.lastReqOrd = reqOrd
		c.h1Feed(dir, first, reqOrd, respOrd)
		putBuf(first)
	case wireHTTP2Preface:
		if c.ignoredPort(dir) {
			c.ignore()
			return
		}
		c.state, c.reqDir = stateHTTP2, dir
		c.h2 = fastparser.NewHTTP2Conn(bodyCap())
		req, resp := c.pre[dir], c.pre[1-dir]
		c.pre[0], c.pre[1] = nil, nil
		c.addHeld(-len(req) - len(resp))
		okReq := c.h2.Feed(true, req) == nil
		okResp := c.h2.Feed(false, resp) == nil
		putBuf(req)
		putBuf(resp)
		if !okReq || !okResp {
			http2ConnFailed.Add(1)
			c.ignore()
			return
		}
		c.produceHTTP2()
	case wireOther:
		// A server may write first (HTTP/2 SETTINGS right after the TLS
		// handshake); wait for the peer's first bytes before giving up.
		if dir == dirSend && len(c.pre[dirRecv]) == 0 {
			return
		}
		c.ignore()
	}
}
