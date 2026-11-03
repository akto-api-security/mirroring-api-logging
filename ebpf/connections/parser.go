package connections

import (
	"encoding/binary"
	"net"
	"strconv"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/structs"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/fastparser"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/kafkaUtil"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

// Emit hooks; tests replace them.
var (
	emitHTTP1 = produceHTTP1
	emitHTTP2 = produceHTTP2Stream
)

func formatAddr(ip uint32, port uint16) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], ip)
	return net.IP(b[:]).String() + ":" + strconv.Itoa(int(port))
}

// trafficContext orients the pair: the side that sent the request is the
// source. Requests read by the traced process are inbound. It is built once
// per connection.
func (c *conn) trafficContext() (*kafkaUtil.TrafficContext, bool) {
	if c.reqDir == dirSend && disableEgress {
		return nil, false
	}
	if c.ctx != nil {
		return c.ctx, true
	}
	remote := formatAddr(c.id.Ip, c.id.Port)
	local := formatAddr(c.laddr, c.lport)
	ctx := &kafkaUtil.TrafficContext{
		SourceIP:            remote,
		DestIP:              local,
		VxlanID:             0,
		IsPending:           false,
		TrafficSource:       "MIRRORING",
		IsComplete:          true,
		Direction:           utils.DirectionInbound,
		ProcessID:           uint32(c.id.Id >> 32),
		SocketFD:            c.id.Fd,
		DaemonsetIdentifier: uniqueDaemonsetId,
		ConnID: &kafkaUtil.TrafficConnID{
			ID:        c.id.Id,
			Fd:        c.id.Fd,
			Timestamp: c.id.Conn_start_ns,
			Ip:        c.id.Ip,
			Port:      c.id.Port,
		},
	}
	if c.reqDir == dirSend {
		ctx.SourceIP, ctx.DestIP = local, remote
		ctx.Direction = utils.DirectionOutbound
	}
	if kafkaUtil.PodInformerInstance != nil {
		ctx.HostName = kafkaUtil.PodInformerInstance.GetPodNameByProcessId(int32(c.id.Id >> 32))
	}
	c.ctx = ctx
	return ctx, true
}

func produceHTTP1(c *conn, req, resp []byte) {
	ctx, ok := c.trafficContext()
	if !ok {
		return
	}
	pairsEmitted.Add(1)
	kafkaUtil.ParseAndProduce(req, resp, *ctx)
}

func produceHTTP2Stream(c *conn, s *fastparser.HTTP2Stream) {
	ctx, ok := c.trafficContext()
	if !ok {
		return
	}
	req, resp := s.ToRequestResponse()
	kafkaUtil.ProduceReqResp(req, resp, *ctx)
}

// ignoreInKernel stops the probes from tracking a connection we will never
// parse. Set by main once the BPF maps are loaded.
var ignoreInKernel = func(structs.ConnID) {}

// SetKernelIgnore installs the hook that deletes a connection from the
// kernel's conn_info_map.
func SetKernelIgnore(f func(structs.ConnID)) {
	if f != nil {
		ignoreInKernel = f
	}
}
