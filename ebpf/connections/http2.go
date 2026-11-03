package connections

// HTTP/2 (incl. gRPC). The connection is multiplexed and full duplex, so
// direction runs mean nothing; the request and response of one exchange share
// a stream id. Bytes are fed in order to a persistent per-connection parser
// (HPACK state is connection-wide) and every stream whose request and response
// have both ended is produced right away.

import (
	"log/slog"

	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

func (c *conn) onHTTP2(dir uint8, data []byte, gap bool) {
	if gap {
		// A missing chunk desyncs frame boundaries and HPACK for good.
		http2ConnFailed.Add(1)
		c.produceHTTP2()
		c.ignore()
		return
	}
	if err := c.h2.Feed(dir == c.reqDir, data); err != nil {
		http2ConnFailed.Add(1)
		if utils.ProcessLogsEnabled() {
			slog.Warn("http2: parse failed, dropping connection", "fd", c.id.Fd, "err", err)
		}
		c.produceHTTP2()
		c.ignore()
		return
	}
	c.produceHTTP2()
}

func (c *conn) produceHTTP2() {
	if c.h2 == nil {
		return
	}
	for _, s := range c.h2.TakeComplete() {
		http2Streams.Add(1)
		emitHTTP2(c, s)
	}
}
