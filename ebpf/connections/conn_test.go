package connections

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/structs"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/fastparser"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// sim plays the kernel side of one socket: it chunks syscalls the way
// process_syscall_data does, bumps the per-direction counters for every chunk
// (delivered or not) and hands the records to a Shard in order.
type sim struct {
	t       *testing.T
	sh      *Shard
	id      structs.ConnID
	rc, wc  uint32
	lost    [2]uint32 // undelivered bytes per direction, as conn_info_t keeps them
	lostRun uint32    // undelivered bytes of the current run
	runDir  int       // direction of the current run, -1 none
	ssl     bool
	chunk   int
	lose    func(dir uint8) bool // chunk is counted but not delivered
}

type pair struct {
	req, resp string
	reqDir    uint8
}

type capture struct {
	pairs   []pair
	streams []*fastparser.HTTP2Stream
	ignored int
}

func newCapture(t *testing.T) *capture {
	c := &capture{}
	oldH1, oldH2, oldIgn := emitHTTP1, emitHTTP2, ignoreInKernel
	emitHTTP1 = func(cn *conn, req, resp []byte) {
		c.pairs = append(c.pairs, pair{string(req), string(resp), cn.reqDir})
	}
	emitHTTP2 = func(_ *conn, s *fastparser.HTTP2Stream) { c.streams = append(c.streams, s) }
	ignoreInKernel = func(structs.ConnID) { c.ignored++ }
	t.Cleanup(func() { emitHTTP1, emitHTTP2, ignoreInKernel = oldH1, oldH2, oldIgn })
	return c
}

var nextFd uint32 = 100

func newSim(t *testing.T, sh *Shard) *sim {
	nextFd++
	return &sim{
		t: t, sh: sh, chunk: 30720, runDir: -1,
		id: structs.ConnID{Id: 42 << 32, Fd: nextFd, Conn_start_ns: uint64(nextFd), Port: 443, Ip: 0x0100000a},
	}
}

// newShard starts at the current wipe epoch, so wipes from earlier tests don't apply.
func newShard() *Shard { return &Shard{conns: map[structs.ConnID]*conn{}, epoch: wipeEpoch.Load()} }

func (s *sim) header(buf []byte, kind uint32) {
	binary.LittleEndian.PutUint64(buf[0:], s.id.Id)
	binary.LittleEndian.PutUint32(buf[8:], s.id.Fd)
	binary.LittleEndian.PutUint32(buf[12:], kind)
	binary.LittleEndian.PutUint64(buf[16:], s.id.Conn_start_ns)
	binary.LittleEndian.PutUint16(buf[24:], s.id.Port)
	binary.LittleEndian.PutUint32(buf[28:], s.id.Ip)
}

func (s *sim) open() {
	b := make([]byte, 48)
	s.header(b, structs.EventOpen)
	binary.LittleEndian.PutUint32(b[32:], 0x0c80000a)
	binary.LittleEndian.PutUint16(b[36:], 443)
	s.sh.HandleRecord(b, time.Now())
}

func (s *sim) close() {
	b := make([]byte, 56)
	s.header(b, structs.EventClose)
	binary.LittleEndian.PutUint32(b[40:], s.rc)
	binary.LittleEndian.PutUint32(b[44:], s.wc)
	binary.LittleEndian.PutUint32(b[48:], s.lost[dirRecv])
	binary.LittleEndian.PutUint32(b[52:], s.lost[dirSend])
	s.sh.HandleRecord(b, time.Now())
}

// syscall emits one read (dir=dirRecv) or write (dirSend) of data.
func (s *sim) syscall(dir uint8, data string) {
	if s.runDir != int(dir) {
		s.runDir, s.lostRun = int(dir), 0
	}
	for off := 0; off < len(data); off += s.chunk {
		end := min(off+s.chunk, len(data))
		if dir == dirSend {
			s.wc++
		} else {
			s.rc++
		}
		if s.lose != nil && s.lose(dir) {
			s.lost[dir] += uint32(end - off)
			s.lostRun += uint32(end - off)
			continue
		}
		b := make([]byte, structs.MsgPayloadOffset+end-off)
		s.header(b, structs.EventData)
		n := int32(end - off)
		if dir == dirRecv {
			n = -n
		}
		binary.LittleEndian.PutUint32(b[32:], uint32(n))
		binary.LittleEndian.PutUint32(b[36:], s.rc)
		binary.LittleEndian.PutUint32(b[40:], s.wc)
		if s.ssl {
			b[44] = 1
		}
		binary.LittleEndian.PutUint32(b[48:], s.lost[dir])
		binary.LittleEndian.PutUint32(b[52:], s.lostRun)
		s.lost[dir], s.lostRun = 0, 0
		copy(b[structs.MsgPayloadOffset:], data[off:end])
		s.sh.HandleRecord(b, time.Now())
	}
}

func (s *sim) read(data string)  { s.syscall(dirRecv, data) }
func (s *sim) write(data string) { s.syscall(dirSend, data) }

// flipSSL mimics set_conn_as_ssl: counters restart, later events carry ssl=1.
func (s *sim) flipSSL() {
	s.ssl, s.rc, s.wc, s.lost, s.lostRun, s.runDir = true, 0, 0, [2]uint32{}, 0, -1
}

func req(id int, body string) string {
	if body == "" {
		return fmt.Sprintf("GET /item/%d HTTP/1.1\r\nHost: h\r\nX-Request-Id: %d\r\n\r\n", id, id)
	}
	return fmt.Sprintf("POST /item/%d HTTP/1.1\r\nHost: h\r\nX-Request-Id: %d\r\nContent-Length: %d\r\n\r\n%s", id, id, len(body), body)
}

func resp(id int, body string) string {
	return fmt.Sprintf("HTTP/1.1 200 R%d\r\nX-Request-Id: %d\r\nContent-Length: %d\r\n\r\n%s", id, id, len(body), body)
}

// idOf reads the exchange id from the start line ("/item/<id> " in requests,
// "R<id>\r" in responses), so even a short prefix carries it.
func idOf(msg string) string {
	for _, mark := range []string{"/item/", " 200 R"} {
		if i := strings.Index(msg, mark); i >= 0 && i < 16 {
			rest := msg[i+len(mark):]
			if j := strings.IndexAny(rest, " \r"); j > 0 {
				return rest[:j]
			}
		}
	}
	return ""
}

func TestKeepAlivePairsInOrder(t *testing.T) {
	cp := newCapture(t)
	s := newSim(t, newShard())
	s.open()
	for i := 1; i <= 3; i++ {
		s.read(req(i, ""))
		s.write(resp(i, strings.Repeat("x", 100)))
	}
	s.close()
	if len(cp.pairs) != 3 {
		t.Fatalf("pairs = %d, want 3", len(cp.pairs))
	}
	for i, p := range cp.pairs {
		if p.req != req(i+1, "") || p.resp != resp(i+1, strings.Repeat("x", 100)) {
			t.Fatalf("pair %d wrong: %q / %q", i, p.req, p.resp)
		}
		if p.reqDir != dirRecv {
			t.Fatalf("server capture must be inbound")
		}
	}
}

func TestMultiChunkAndMultiSyscallMessages(t *testing.T) {
	cp := newCapture(t)
	s := newSim(t, newShard())
	s.chunk = 7
	body := strings.Repeat("abcdefghij", 50)
	r := req(1, body)
	s.read(r[:20])
	s.read(r[20:]) // second read syscall, same message
	w := resp(1, body)
	s.write(w[:30])
	s.write(w[30:])
	s.read(req(2, ""))
	if len(cp.pairs) != 1 || cp.pairs[0].req != r || cp.pairs[0].resp != w {
		t.Fatalf("got %+v", cp.pairs)
	}
}

func TestLostWholeResponseOrphansRequest(t *testing.T) {
	cp := newCapture(t)
	s := newSim(t, newShard())
	s.read(req(1, ""))
	s.lose = func(dir uint8) bool { return dir == dirSend }
	s.write(resp(1, "a"))
	s.lose = nil
	s.read(req(2, ""))
	s.write(resp(2, "b"))
	s.close()
	if len(cp.pairs) != 1 || idOf(cp.pairs[0].req) != "2" || idOf(cp.pairs[0].resp) != "2" {
		t.Fatalf("got %+v", cp.pairs)
	}
}

func TestLostWholeRequestOrphansResponse(t *testing.T) {
	cp := newCapture(t)
	s := newSim(t, newShard())
	s.read(req(1, ""))
	s.write(resp(1, "a"))
	s.lose = func(dir uint8) bool { return dir == dirRecv }
	s.read(req(2, ""))
	s.lose = nil
	s.write(resp(2, "b"))
	s.read(req(3, ""))
	s.write(resp(3, "c"))
	s.close()
	if len(cp.pairs) != 2 || idOf(cp.pairs[0].resp) != "1" || idOf(cp.pairs[1].resp) != "3" {
		t.Fatalf("got %+v", cp.pairs)
	}
}

func TestLostHeadChunkDropsMessage(t *testing.T) {
	cp := newCapture(t)
	s := newSim(t, newShard())
	s.chunk = 16
	s.read(req(1, ""))
	s.write(resp(1, "a"))
	first := true
	s.lose = func(dir uint8) bool {
		if dir == dirRecv && first {
			first = false
			return true
		}
		return false
	}
	s.read(req(2, "some body bytes"))
	s.lose = nil
	s.write(resp(2, "b"))
	s.read(req(3, ""))
	s.write(resp(3, "c"))
	s.close()
	ids := []string{}
	for _, p := range cp.pairs {
		ids = append(ids, idOf(p.req)+"/"+idOf(p.resp))
	}
	if strings.Join(ids, ",") != "1/1,3/3" {
		t.Fatalf("pairs = %v", ids)
	}
}

func TestLostMiddleChunkKeepsCleanPrefix(t *testing.T) {
	cp := newCapture(t)
	s := newSim(t, newShard())
	s.chunk = 10
	s.read(req(1, ""))
	w := resp(1, strings.Repeat("y", 200))
	n := 0
	s.lose = func(dir uint8) bool { n++; return dir == dirSend && n == 8 }
	s.write(w)
	s.lose = nil
	s.read(req(2, ""))
	if len(cp.pairs) != 1 {
		t.Fatalf("pairs = %d", len(cp.pairs))
	}
	got := cp.pairs[0].resp
	if !strings.HasPrefix(w, got) || len(got) >= len(w) || !strings.HasPrefix(got, "HTTP/1.1 200") {
		t.Fatalf("response must be a clean prefix: %q", got)
	}
}

func TestLostTailBeforeCloseIsDetected(t *testing.T) {
	cp := newCapture(t)
	s := newSim(t, newShard())
	s.chunk = 10
	s.read(req(1, ""))
	w := resp(1, strings.Repeat("z", 100))
	total := (len(w) + 9) / 10
	n := 0
	s.lose = func(dir uint8) bool { n++; return n == total } // the last chunk
	s.write(w)
	s.close()
	if len(cp.pairs) != 1 || cp.pairs[0].resp == w || !strings.HasPrefix(w, cp.pairs[0].resp) {
		t.Fatalf("got %+v", cp.pairs)
	}
	if c := s.sh.conns[s.id.Key()]; c != nil {
		t.Fatal("closed connection still tracked")
	}
}

func TestExpectContinueMergesBody(t *testing.T) {
	cp := newCapture(t)
	s := newSim(t, newShard())
	head := "POST /up HTTP/1.1\r\nHost: h\r\nX-Request-Id: 7\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n"
	s.read(head)
	s.write("HTTP/1.1 100 Continue\r\n\r\n")
	s.read("hello")
	s.write(resp(7, "done"))
	s.close()
	if len(cp.pairs) != 1 || cp.pairs[0].req != head+"hello" || cp.pairs[0].resp != resp(7, "done") {
		t.Fatalf("got %+v", cp.pairs)
	}
}

func TestInformationalPrefixStripped(t *testing.T) {
	cp := newCapture(t)
	s := newSim(t, newShard())
	s.read(req(1, ""))
	s.write("HTTP/1.1 103 Early Hints\r\nLink: </a.css>\r\n\r\n" + resp(1, "ok"))
	s.close()
	if len(cp.pairs) != 1 || cp.pairs[0].resp != resp(1, "ok") {
		t.Fatalf("got %+v", cp.pairs)
	}
}

func TestSwitchingProtocolsStopsHTTP1(t *testing.T) {
	cp := newCapture(t)
	s := newSim(t, newShard())
	s.read("GET /ws HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	s.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n")
	s.read("GET looks like http but is a ws frame payload")
	s.write("HTTP/1.1 also a frame")
	s.read("\x81\x05hello")
	s.close()
	if len(cp.pairs) != 1 || !strings.HasPrefix(cp.pairs[0].resp, "HTTP/1.1 101") {
		t.Fatalf("got %+v", cp.pairs)
	}
}

func TestTLSHandshakeThenPlaintext(t *testing.T) {
	cp := newCapture(t)
	s := newSim(t, newShard())
	s.open()
	s.read("\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03client hello")
	s.write("\x16\x03\x03\x00\x7aserver hello")
	s.read("\x14\x03\x03\x00\x01\x01finished")
	s.flipSSL()
	s.read(req(1, ""))
	s.write(resp(1, "secret"))
	s.read(req(2, ""))
	s.write(resp(2, "secret2"))
	s.close()
	if len(cp.pairs) != 2 || idOf(cp.pairs[1].resp) != "2" {
		t.Fatalf("got %+v", cp.pairs)
	}
	if cp.ignored != 0 {
		t.Fatal("TLS connection must not be dropped from the kernel")
	}
}

func TestNonHTTPIgnoredInKernel(t *testing.T) {
	cp := newCapture(t)
	s := newSim(t, newShard())
	s.read("\x00\x00\x00\x2a\x00\x01binary-protocol")
	s.write("\x00\x00\x00\x10reply")
	if cp.ignored != 1 || len(cp.pairs) != 0 {
		t.Fatalf("ignored=%d pairs=%d", cp.ignored, len(cp.pairs))
	}
	if held := s.sh.conns[s.id.Key()].held; held != 0 {
		t.Fatalf("ignored connection still holds %d bytes", held)
	}
}

func TestClientSideCaptureIsOutbound(t *testing.T) {
	cp := newCapture(t)
	s := newSim(t, newShard())
	s.write(req(1, ""))
	s.read(resp(1, "x"))
	s.close()
	if len(cp.pairs) != 1 || cp.pairs[0].reqDir != dirSend || idOf(cp.pairs[0].resp) != "1" {
		t.Fatalf("got %+v", cp.pairs)
	}
}

func TestPairEmittedOnResponseCompletion(t *testing.T) {
	cp := newCapture(t)
	sh := newShard()
	s := newSim(t, sh)
	s.read(req(1, ""))
	s.write(resp(1, "x"))
	if len(cp.pairs) != 1 {
		t.Fatal("a framed response is complete; the pair must not wait for the next request")
	}
	sh.Sweep(time.Now().Add(inactivityThreshold + time.Second))
	if len(sh.conns) != 0 {
		t.Fatalf("idle connection not removed")
	}
}

func TestCloseDelimitedResponseEmittedAtClose(t *testing.T) {
	cp := newCapture(t)
	s := newSim(t, newShard())
	s.read(req(1, ""))
	s.write("HTTP/1.0 200 R1\r\nConnection: close\r\n\r\nall of it")
	s.write(" until close")
	if len(cp.pairs) != 0 {
		t.Fatal("body runs until close")
	}
	s.close()
	if len(cp.pairs) != 1 || !strings.HasSuffix(cp.pairs[0].resp, "all of it until close") {
		t.Fatalf("got %+v", cp.pairs)
	}
}

// A pipelining client: requests split across reads at arbitrary byte
// offsets, responses written between them. Pairing follows request order.
func TestPipelinedRequestsPairInOrder(t *testing.T) {
	cp := newCapture(t)
	s := newSim(t, newShard())
	all := ""
	for i := 1; i <= 6; i++ {
		all += req(i, strings.Repeat("p", i*7))
	}
	cut1, cut2 := len(all)/3+5, 2*len(all)/3+3
	s.read(all[:cut1])
	s.write(resp(1, "a") + resp(2, "b"))
	s.read(all[cut1:cut2])
	s.write(resp(3, "c"))
	s.write(resp(4, "d"))
	s.read(all[cut2:])
	s.write(resp(5, "e") + resp(6, "f"))
	s.close()
	if len(cp.pairs) != 6 {
		t.Fatalf("pairs = %d, want 6", len(cp.pairs))
	}
	for i, p := range cp.pairs {
		want := fmt.Sprint(i + 1)
		if idOf(p.req) != want || idOf(p.resp) != want || p.req != req(i+1, strings.Repeat("p", (i+1)*7)) {
			t.Fatalf("pair %d: %q / %q", i, idOf(p.req), idOf(p.resp))
		}
	}
}

// Once a client pipelines, losing framing means order can't be rebuilt.
func TestPipelinedLossDropsConnection(t *testing.T) {
	cp := newCapture(t)
	s := newSim(t, newShard())
	s.read(req(1, "") + req(2, ""))
	s.lose = func(dir uint8) bool { return dir == dirSend }
	s.write(resp(1, "a"))
	s.lose = nil
	s.write(resp(2, "b"))
	s.read(req(3, ""))
	s.write(resp(3, "c"))
	for _, p := range cp.pairs {
		if idOf(p.req) != idOf(p.resp) {
			t.Fatalf("crossed %s/%s", idOf(p.req), idOf(p.resp))
		}
	}
	if cp.ignored != 1 {
		t.Fatal("pipelined connection with lost framing must be dropped")
	}
}

func TestMessageCapTruncates(t *testing.T) {
	cp := newCapture(t)
	held0 := heldBytes.Load()
	old := utils.SocketDataEventBytesThreshold
	utils.SocketDataEventBytesThreshold = 1000
	defer func() { utils.SocketDataEventBytesThreshold = old }()
	s := newSim(t, newShard())
	s.chunk = 30000
	s.read(req(1, ""))
	w := resp(1, strings.Repeat("q", 200000))
	s.write(w)
	s.close()
	// The buffer keeps body cap + header room; the producer trims the body to the cap.
	if len(cp.pairs) != 1 || len(cp.pairs[0].resp) != 1000+headerRoom || !strings.HasPrefix(w, cp.pairs[0].resp) {
		t.Fatalf("got %d pairs", len(cp.pairs))
	}
	if heldBytes.Load() != held0 {
		t.Fatalf("held bytes leaked: %d", heldBytes.Load())
	}
}

// Random chunking and random loss over many keep-alive exchanges: whatever is
// emitted must pair the right request with the right response, and every byte
// emitted must be a prefix of the message that was really sent.
func TestRandomLossNeverCrossesOrCorrupts(t *testing.T) {
	cp := newCapture(t)
	held0 := heldBytes.Load()
	rng := rand.New(rand.NewSource(1))
	sh := newShard()
	sent := map[string][2]string{}
	early := map[string]bool{}
	for conn := 0; conn < 200; conn++ {
		s := newSim(t, sh)
		s.chunk = 5 + rng.Intn(60)
		rate := []float64{0, 0.01, 0.05, 0.2}[conn%4]
		s.lose = func(uint8) bool { return rng.Float64() < rate }
		s.open()
		carry := "" // owed body bytes the server reads with the next request
		for i := 0; i < 30; i++ {
			id := conn*1000 + i
			r := req(id, strings.Repeat("r", 1+rng.Intn(120)))
			w := resp(id, strings.Repeat("w", rng.Intn(300)))
			sent[fmt.Sprint(id)] = [2]string{r, w}
			in, owed := carry+r, len(carry)
			carry = ""
			if rng.Intn(10) == 0 {
				// Early answer: the server replies once it has the headers
				// and part of the body; the rest is read later.
				cut := min(owed+strings.Index(r, "\r\n\r\n")+4+rng.Intn(5), len(in)-1)
				in, carry = in[:cut], in[cut:]
				early[fmt.Sprint(id)] = true
			}
			for len(in) > 0 { // several read syscalls
				k := 1 + rng.Intn(len(in))
				s.read(in[:k])
				in = in[k:]
			}
			for len(w) > 0 {
				k := 1 + rng.Intn(len(w))
				s.write(w[:k])
				w = w[k:]
			}
		}
		if rng.Intn(2) == 0 {
			s.close()
		}
	}
	sh.Sweep(time.Now().Add(inactivityThreshold + time.Second))

	full, unverifiable, lossless := 0, 0, 0
	for _, p := range cp.pairs {
		id, rid := idOf(p.req), idOf(p.resp)
		if id == "" || rid == "" {
			// Cut inside a start line (the parser rejects these too). Still
			// both halves must be prefixes of one real exchange.
			unverifiable++
			known := id + rid
			if w, ok := sent[known]; known != "" && (!ok || !strings.HasPrefix(w[0], p.req) || !strings.HasPrefix(w[1], p.resp)) {
				t.Fatalf("short pair does not belong to exchange %s: %q / %q", known, p.req, p.resp)
			}
			continue
		}
		if id != rid {
			t.Fatalf("crossed pair: req %q resp %q", id, rid)
		}
		want := sent[id]
		if !strings.HasPrefix(want[0], p.req) || !strings.HasPrefix(want[1], p.resp) {
			t.Fatalf("pair %s is not a clean prefix of what was sent:\nREQ  %q\nWANT %q\nRESP %q\nWANT %q", id, p.req, want[0], p.resp, want[1])
		}
		if p.req == want[0] && p.resp == want[1] {
			full++
		}
		var n int
		fmt.Sscan(id, &n)
		if (n/1000)%4 == 0 {
			lossless++
			if !early[id] && (p.req != want[0] || p.resp != want[1]) {
				t.Fatalf("lossless exchange %s emitted incomplete", id)
			}
		}
	}
	// Every exchange on a lossless connection (every 4th) must be emitted,
	// complete unless the server answered early.
	if lossless != 50*30 {
		t.Fatalf("lossless connections: %d of %d pairs captured", lossless, 50*30)
	}
	if heldBytes.Load() != held0 {
		t.Fatalf("held bytes leaked: %d", heldBytes.Load()-held0)
	}
	t.Logf("pairs=%d complete=%d unverifiable=%d of %d sent", len(cp.pairs), full, unverifiable, len(sent))
}

// ---------------------------------------------------------------------------
// HTTP/2

func h2Frames(t *testing.T, client bool, streams ...uint32) []byte {
	var buf bytes.Buffer
	if client {
		buf.WriteString(h2Preface)
	}
	fr := http2.NewFramer(&buf, nil)
	fr.WriteSettings()
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	for _, id := range streams {
		hb.Reset()
		if client {
			enc.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
			enc.WriteField(hpack.HeaderField{Name: ":path", Value: fmt.Sprintf("/s/%d", id)})
			enc.WriteField(hpack.HeaderField{Name: ":authority", Value: "h"})
		} else {
			enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
		}
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: hb.Bytes(), EndHeaders: true, EndStream: client})
		if !client {
			fr.WriteData(id, true, []byte(fmt.Sprintf("body-%d", id)))
		}
	}
	return buf.Bytes()
}

func TestHTTP2StreamsServerSettingsFirst(t *testing.T) {
	cp := newCapture(t)
	s := newSim(t, newShard())
	s.chunk = 13
	resp := h2Frames(t, false, 1, 3)
	settings := resp[:9] // server SETTINGS goes out before the client preface is read
	s.write(string(settings))
	s.read(string(h2Frames(t, true, 1, 3)))
	s.write(string(resp[9:]))
	if len(cp.streams) != 2 {
		t.Fatalf("streams = %d", len(cp.streams))
	}
	for _, st := range cp.streams {
		if string(st.RespBody) != fmt.Sprintf("body-%d", st.StreamID) || st.Path != fmt.Sprintf("/s/%d", st.StreamID) {
			t.Fatalf("stream %d mismatched: %s %q", st.StreamID, st.Path, st.RespBody)
		}
	}
}

func TestHTTP2GapAbandonsConnection(t *testing.T) {
	cp := newCapture(t)
	s := newSim(t, newShard())
	s.chunk = 10
	s.read(string(h2Frames(t, true, 1, 3, 5)))
	n := 0
	s.lose = func(dir uint8) bool { n++; return dir == dirSend && n == 3 }
	s.write(string(h2Frames(t, false, 1, 3, 5)))
	for _, st := range cp.streams {
		if string(st.RespBody) != fmt.Sprintf("body-%d", st.StreamID) {
			t.Fatalf("corrupt stream emitted: %d %q", st.StreamID, st.RespBody)
		}
	}
	if c := s.sh.conns[s.id.Key()]; c.state != stateIgnore || cp.ignored != 1 {
		t.Fatal("connection with a gap must be abandoned")
	}
}

func TestClassify(t *testing.T) {
	cases := map[string]wireKind{
		"GET / HTTP/1.1\r\n": wireHTTP1Request,
		"PROPFIND /x":        wireHTTP1Request,
		"GE":                 wireNeedMore,
		"PRI * HTTP/2.0\r\n": wireNeedMore,
		h2Preface:            wireHTTP2Preface,
		"\x16\x03\x01":       wireTLS,
		"HTTP/1.1 200 OK":    wireOther,
		"\x00\x01":           wireOther,
		"get / HTTP/1.1":     wireOther,
	}
	for in, want := range cases {
		if got := classifyBytes([]byte(in)); got != want {
			t.Errorf("classify(%q) = %d, want %d", in, got, want)
		}
	}
}

// A server that reads and writes one socket from two threads (Go, Envoy,
// Netty) stamps the other direction's counter out of order. HTTP/2 only needs
// each direction to be contiguous.
func TestHTTP2CrossThreadStampsAreNotLoss(t *testing.T) {
	cp := newCapture(t)
	s := newSim(t, newShard())
	send := func(dir uint8, rc, wc uint32, data []byte) {
		b := make([]byte, structs.MsgPayloadOffset+len(data))
		s.header(b, structs.EventData)
		n := int32(len(data))
		if dir == dirRecv {
			n = -n
		}
		binary.LittleEndian.PutUint32(b[32:], uint32(n))
		binary.LittleEndian.PutUint32(b[36:], rc)
		binary.LittleEndian.PutUint32(b[40:], wc)
		copy(b[structs.MsgPayloadOffset:], data)
		s.sh.HandleRecord(b, time.Now())
	}
	reqB, respB := h2Frames(t, true, 1, 3), h2Frames(t, false, 1, 3)
	half := len(reqB) / 2
	send(dirSend, 1, 1, respB[:9])   // writer already saw the reader's increment
	send(dirRecv, 1, 0, reqB[:half]) // reader's stamp of wc is stale
	send(dirRecv, 2, 2, reqB[half:]) // and now ahead
	send(dirSend, 1, 2, respB[9:])   // writer's stamp of rc is behind
	if len(cp.streams) != 2 || cp.ignored != 0 {
		t.Fatalf("streams=%d ignored=%d", len(cp.streams), cp.ignored)
	}
}

// A server that answers before reading the body (301, 401, 413) reads the
// rest of that body together with the next request. The next request must
// still be found.
func TestEarlyResponseOwedBodyIsSkipped(t *testing.T) {
	body := strings.Repeat("B", 5000)
	full := req(1, body)
	head := full[:len(full)-len(body)+100] // headers + first 100 body bytes
	rest := full[len(head):]
	redirect := "HTTP/1.1 301 R1\r\nLocation: https://h/\r\nContent-Length: 0\r\n\r\n"

	t.Run("rest of body and next request in one read", func(t *testing.T) {
		cp := newCapture(t)
		s := newSim(t, newShard())
		s.read(head)
		s.write(redirect)
		s.read(rest + req(2, ""))
		s.write(resp(2, "ok"))
		s.close()
		if len(cp.pairs) != 2 || idOf(cp.pairs[1].req) != "2" || cp.pairs[1].req != req(2, "") {
			t.Fatalf("got %+v", cp.pairs)
		}
	})
	t.Run("several reads, request starts mid-chunk", func(t *testing.T) {
		cp := newCapture(t)
		s := newSim(t, newShard())
		s.chunk = 700
		s.read(head)
		s.write(redirect)
		s.read(rest[:1000])
		s.read(rest[1000:] + req(2, "xyz"))
		s.write(resp(2, "ok"))
		s.read(req(3, ""))
		s.write(resp(3, "ok"))
		s.close()
		if len(cp.pairs) != 3 || cp.pairs[1].req != req(2, "xyz") || idOf(cp.pairs[2].req) != "3" {
			t.Fatalf("got %d pairs", len(cp.pairs))
		}
	})
	t.Run("100-continue client sends the next request instead", func(t *testing.T) {
		cp := newCapture(t)
		s := newSim(t, newShard())
		h := "POST /item/1 HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 5000\r\n\r\n"
		s.read(h)
		s.write("HTTP/1.1 417 R1\r\nContent-Length: 0\r\n\r\n")
		s.read(req(2, ""))
		s.write(resp(2, "ok"))
		s.close()
		if len(cp.pairs) != 2 || cp.pairs[1].req != req(2, "") {
			t.Fatalf("got %+v", cp.pairs)
		}
	})
	t.Run("chunked body", func(t *testing.T) {
		cp := newCapture(t)
		s := newSim(t, newShard())
		h := "POST /item/1 HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n"
		s.read(h)
		s.write("HTTP/1.1 401 R1\r\nContent-Length: 0\r\n\r\n")
		s.read("6\r\nworld!\r\n0\r")
		s.read("\n\r\n" + req(2, ""))
		s.write(resp(2, "ok"))
		s.close()
		if len(cp.pairs) != 2 || cp.pairs[1].req != req(2, "") {
			t.Fatalf("got %+v", cp.pairs)
		}
	})
}

func htons(p uint16) uint16 { return p>>8 | p<<8 }

// Ignored ports are server ports. A client's ephemeral port must never cause
// its connection to be dropped, whatever its byte order looks like.
func TestIgnoredPortsAreServerPorts(t *testing.T) {
	run := func(remote, local uint16, clientSide bool) int {
		cp := newCapture(t)
		s := newSim(t, newShard())
		s.id.Port = remote
		b := make([]byte, 48)
		s.header(b, structs.EventOpen)
		binary.LittleEndian.PutUint16(b[36:], local)
		s.sh.HandleRecord(b, time.Now())
		if clientSide {
			s.write(req(1, ""))
			s.read(resp(1, "x"))
		} else {
			s.read(req(1, ""))
			s.write(resp(1, "x"))
		}
		s.close()
		return len(cp.pairs)
	}
	if n := run(htons(34056)>>8|htons(34056)<<8, 443, false); n != 1 {
		t.Fatalf("client port that byte-swaps to 2181 was dropped (pairs=%d)", n)
	}
	if n := run(htons(2181), 443, false); n != 1 {
		t.Fatalf("inbound connection from client port 2181 to 443 was dropped")
	}
	if n := run(htons(50000), 6379, false); n != 0 {
		t.Fatalf("traffic to local port 6379 should be ignored")
	}
	if n := run(htons(9092), 50000, true); n != 0 {
		t.Fatalf("outbound traffic to remote port 9092 should be ignored")
	}
}

// A memory wipe drops everything buffered without emitting it. Responses to
// requests read before the wipe are never paired; capture resumes at the next
// clean exchange.
func TestMemoryWipeDropsEverythingAndResumes(t *testing.T) {
	cp := newCapture(t)
	sh := newShard()
	s := newSim(t, sh)
	s.open()
	wipeNow := func() {
		wipeEpoch.Add(1)
		sh.Sweep(time.Now())
		if c := sh.conns[s.id.Key()]; c == nil || c.held != 0 {
			t.Fatal("wipe must keep the connection and free its buffers")
		}
	}
	s.read(req(1, ""))
	wipeNow()
	s.write(resp(1, "a")) // its request is gone: orphan
	s.read(req(2, ""))
	s.write(resp(2, "b"))
	r3 := req(3, strings.Repeat("z", 500))
	s.read(r3[:100])
	wipeNow()
	s.read(r3[100:]) // rest of the body, same run: must not resync here
	s.write(resp(3, "c"))
	s.read(req(4, ""))
	s.write(resp(4, "d"))
	s.close()
	if len(cp.pairs) != 2 || idOf(cp.pairs[0].req) != "2" || idOf(cp.pairs[0].resp) != "2" ||
		idOf(cp.pairs[1].req) != "4" || idOf(cp.pairs[1].resp) != "4" {
		t.Fatalf("got %+v", cp.pairs)
	}
}

// A connection opened while ingest was paused (its first bytes lost) is not
// given up: detection waits for the next clean message start.
func TestLostStartDetectsAtNextCleanRun(t *testing.T) {
	cp := newCapture(t)
	s := newSim(t, newShard())
	s.open()
	s.lose = func(uint8) bool { return true }
	s.read(req(1, strings.Repeat("a", 100)))
	s.write(resp(1, "x"))
	r2 := req(2, strings.Repeat("b", 100))
	s.chunk = 40
	s.read(r2[:40]) // paused through the start of request 2
	s.lose = nil
	s.read(r2[40:]) // resumed mid-request: not a message start
	s.write(resp(2, "y"))
	s.read(req(3, ""))
	s.write(resp(3, "z"))
	s.close()
	if cp.ignored != 0 {
		t.Fatal("connection must not be dropped from the kernel")
	}
	if len(cp.pairs) != 1 || idOf(cp.pairs[0].req) != "3" || idOf(cp.pairs[0].resp) != "3" {
		t.Fatalf("got %+v", cp.pairs)
	}
}
