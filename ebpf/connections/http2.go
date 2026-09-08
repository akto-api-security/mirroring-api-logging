package connections

// HTTP/2 (incl. gRPC) tracker path. Selected per-connection by Tracker.protocol
// (kernel classification verdict). Unlike the HTTP/1.1 msg_seq path, HTTP/2 cannot
// pair by direction change — req/resp of one RPC share a stream_id and the whole
// connection is multiplexed + full-duplex. And because HPACK's dynamic table is
// cumulative per direction, bytes must be fed to the parser IN ORDER, gap-free.
//
// This file owns: per-direction byte resequencing (rc/wc order) and driving the
// persistent fastparser.HTTP2Conn. Completed unary streams are produced through the
// same fast encode+produce pipeline the HTTP/1.1 path uses (kafkaUtil.ProduceReqResp).

import (
	"bytes"
	"log/slog"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/structs"
	ebpfutils "github.com/akto-api-security/mirroring-api-logging/ebpf/utils"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/fastparser"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/kafkaUtil"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

// h2MaxPendingChunks bounds out-of-order buffering per direction. Exceeding it
// means a chunk was lost (not just reordered) → the connection's HPACK state can't
// be trusted, so we abandon it.
const h2MaxPendingChunks = 128

// h2Reassembler restores in-order bytes for one direction from rc/wc-ordered
// chunks (per-CPU perf buffers can deliver out of order). next is the next seq to
// emit; pending holds chunks that arrived early. next is lazily seeded to the first
// observed seq (a connection captured post-SSL-handshake starts at rc/wc > 1).
type h2Reassembler struct {
	next    int
	inited  bool
	pending map[int][]byte
}

// add ingests one chunk. It feeds every now-contiguous chunk (in order) via feed,
// and returns false if out-of-order buffering overflowed (a real gap).
func (r *h2Reassembler) add(seq int, data []byte, feed func([]byte)) bool {
	if !r.inited {
		r.next = seq
		r.inited = true
	}
	if seq < r.next {
		return true // already emitted / duplicate
	}
	if r.pending == nil {
		r.pending = make(map[int][]byte)
	}
	r.pending[seq] = data
	for {
		d, ok := r.pending[r.next]
		if !ok {
			break
		}
		feed(d)
		delete(r.pending, r.next)
		r.next++
	}
	return len(r.pending) <= h2MaxPendingChunks
}

// addHTTP2Event routes one data event into the HTTP/2 path. Caller holds conn.mutex.
func (conn *Tracker) addHTTP2Event(attr *structs.SocketDataEventAttr, payload []byte) {
	if conn.h2 == nil {
		conn.h2 = fastparser.NewHTTP2Conn()
	}
	if conn.h2.Failed() {
		// The connection was abandoned earlier (byte gap / HPACK desync). Everything
		// still arriving on it is unrecoverable, but count it: this is the blast
		// radius of the original single lost chunk, and it used to vanish silently.
		utils.Pipeline.HTTP2EventsAfterFail.Add(1)
		return
	}

	isEgress := attr.Direction == 0 // kEgress=0, kIngress=1
	isRequest := conn.h2IsRequest(isEgress)

	feed := func(d []byte) {
		if err := conn.h2.Feed(isRequest, d); err != nil {
			utils.Pipeline.HTTP2ConnFailed.Add(1)
			if utils.IsMsgSeqLogsEnabled() {
				slog.Warn("http2: parser failed, abandoning connection",
					"fd", conn.connID.Fd, "err", err)
			}
		}
	}

	var r *h2Reassembler
	var seq int
	if isEgress {
		r = &conn.h2egress
		seq = int(attr.WriteEventsCount)
	} else {
		r = &conn.h2ingress
		seq = int(attr.ReadEventsCount)
	}

	if !r.add(seq, payload, feed) {
		conn.h2.Fail()
		utils.Pipeline.HTTP2ConnFailed.Add(1)
		if utils.IsMsgSeqLogsEnabled() {
			slog.Warn("http2: chunk gap (out-of-order overflow), abandoning connection",
				"fd", conn.connID.Fd, "pending", len(r.pending))
		}
	}
}

// h2IsRequest maps wire direction to request (client→server) vs response using role:
// a server receives requests (ingress); a client sends them (egress). Role unknown →
// assume server-side capture (ingress = request), the common case.
func (conn *Tracker) h2IsRequest(isEgress bool) bool {
	switch conn.role {
	case structs.RoleClient:
		return isEgress
	default: // RoleServer or RoleUnknown
		return !isEgress
	}
}

// TakeCompleteHTTP2 returns completed unary streams and removes them. Acquires
// conn.mutex (caller must NOT hold it), mirroring GetFlushablePairs.
func (conn *Tracker) TakeCompleteHTTP2() []*fastparser.HTTP2Stream {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()
	if conn.h2 == nil {
		return nil
	}
	return conn.h2.TakeComplete()
}

// produceHTTP2Streams maps completed streams onto the fast Request/Response and
// produces them via the shared fast pipeline. Orientation (inbound/outbound,
// source/dest) follows role, exactly like ProcessSinglePair.
func produceHTTP2Streams(connID structs.ConnID, tracker *Tracker, streams []*fastparser.HTTP2Stream) {
	if len(streams) == 0 {
		return
	}
	raddrStr := ebpfutils.FormatAddr(connID.Raddr, connID.Rport)
	laddrStr := ebpfutils.FormatAddr(tracker.laddr, tracker.lport)
	hostName := ""
	if kafkaUtil.PodInformerInstance != nil {
		hostName = kafkaUtil.PodInformerInstance.GetPodNameByProcessId(int32(connID.Id >> 32))
	}

	for _, s := range streams {
		req, resp := s.ToRequestResponse()
		utils.Pipeline.PairsAttempted.Add(1)
		utils.Pipeline.HTTP2StreamsProduced.Add(1)

		// Correctness net for multiplexed pairing, mirroring the HTTP/1 check in
		// kafkaUtil/parser.go. HTTP/2 runs many streams concurrently on one
		// connection and responses may return in any order, so a req/resp pair is
		// only correct if it was matched by stream_id rather than arrival order.
		// When a request carries x-debug-token and the peer echoes it, the token
		// MUST appear in that stream's response body; if it doesn't, this pair
		// intermixed with another stream's.
		//
		// Checked against s.RespBody (the raw body) deliberately -- for gRPC
		// ToRequestResponse() base64-encodes resp.Body, and the token would not
		// survive that encoding as a substring.
		if tok := req.Header("x-debug-token"); len(tok) > 0 {
			if !bytes.Contains(s.RespBody, tok) {
				utils.Pipeline.PairsMismatched.Add(1)
				if utils.IsMsgSeqLogsEnabled() {
					slog.Warn("http2: req/resp intermix — x-debug-token not echoed in this stream's response",
						"fd", connID.Fd, "stream", s.StreamID, "token", string(tok))
				}
			}
		}

		switch tracker.role {
		case structs.RoleClient:
			if disableEgress {
				continue
			}
			// outbound: we are the client → source=local, dest=remote
			kafkaUtil.ProduceReqResp(req, resp, h2Context(laddrStr, raddrStr, utils.DirectionOutbound, connID, hostName))
		default:
			// server / unknown → inbound: remote is the client → source=remote, dest=local
			kafkaUtil.ProduceReqResp(req, resp, h2Context(raddrStr, laddrStr, utils.DirectionInbound, connID, hostName))
		}
	}
}

// h2Context builds the TrafficContext, matching tryReadFromBD's construction.
func h2Context(sourceIP, destIP string, direction int, connID structs.ConnID, hostName string) kafkaUtil.TrafficContext {
	return kafkaUtil.TrafficContext{
		SourceIP:            sourceIP,
		DestIP:              destIP,
		VxlanID:             0,
		IsPending:           false,
		TrafficSource:       "MIRRORING",
		IsComplete:          true,
		Direction:           direction,
		ProcessID:           uint32(connID.Id >> 32),
		SocketFD:            connID.Fd,
		DaemonsetIdentifier: uniqueDaemonsetId,
		HostName:            hostName,
	}
}
