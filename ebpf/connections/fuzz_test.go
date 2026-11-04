package connections

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"
)

func chunkedResp(id int, body string) string {
	out := fmt.Sprintf("HTTP/1.1 200 R%d\r\nTransfer-Encoding: chunked\r\n\r\n", id)
	for len(body) > 0 {
		n := min(7, len(body))
		out += fmt.Sprintf("%x\r\n%s\r\n", n, body[:n])
		body = body[n:]
	}
	return out + "0\r\n\r\n"
}

// Many short connections mixing pipelining, chunked responses, early
// answers, random syscall splits, 10% chunk loss in both directions,
// occasional missed return probes, chunks whose socket can't be named when
// they happen (the hole is reported at the session's next call) and memory
// wipes. No emitted pair may ever join a request with another exchange's
// response.
func TestFuzzNoCrossedPairs(t *testing.T) { fuzzNoCrossedPairs(t, false) }

// The same with chunks that vanish uncounted, which the kernel no longer
// produces: the bytes around such a gap are spliced, so a message's content
// can be wrong, but pairing must still never join two exchanges (two
// different, well-formed request ids). Clients don't pipeline here.
func TestFuzzSilentGapsNeverCrossPairs(t *testing.T) { fuzzNoCrossedPairs(t, true) }

func fuzzNoCrossedPairs(t *testing.T, silent bool) {
	n := int64(20000)
	if testing.Short() {
		n = 2000
	}
	for seed := int64(0); seed < n; seed++ {
		cp := newCapture(t)
		rng := rand.New(rand.NewSource(seed))
		var log []string
		s := newSim(t, newShard())
		s.chunk = 5 + rng.Intn(20)
		s.lose = func(dir uint8) bool {
			l := rng.Float64() < 0.1
			if l {
				log = append(log, fmt.Sprintf("  LOST chunk dir=%d", dir))
			}
			return l
		}
		s.missed = func(dir uint8) bool {
			m := rng.Intn(40) == 0
			if m {
				log = append(log, fmt.Sprintf("  MISSED return dir=%d", dir))
			}
			return m
		}
		gap := func(dir uint8) bool {
			d := rng.Intn(30) == 0
			if d {
				log = append(log, fmt.Sprintf("  GAP dir=%d silent=%v", dir, silent))
			}
			return d
		}
		if silent {
			s.drop = gap
		} else {
			s.owe = gap
		}
		wipeMaybe := func() {
			if rng.Intn(25) == 0 {
				log = append(log, "  WIPE")
				wipeEpoch.Add(1)
				s.sh.Sweep(time.Now())
			}
		}
		carry := ""
		// A pipelined request whose head vanished leaves no trace that the
		// connection pipelines, so silent gaps are only checked without it.
		pipe := rng.Intn(4) == 0 && !silent
		if pipe { // a pipelining client: requests first, then responses
			var all, outs string
			for i := 0; i < 4; i++ {
				all += req(i, strings.Repeat("r", 1+rng.Intn(20)))
				outs += chunkedResp(i, strings.Repeat("w", rng.Intn(30)))
			}
			for k := 0; k < 2; k++ {
				a, b := all[:len(all)/2], outs[:len(outs)/2]
				if k == 1 {
					a, b = all[len(all)/2:], outs[len(outs)/2:]
				}
				for len(a) > 0 {
					n := 1 + rng.Intn(len(a))
					wipeMaybe()
					s.read(a[:n])
					a = a[n:]
				}
				for len(b) > 0 {
					n := 1 + rng.Intn(len(b))
					wipeMaybe()
					s.write(b[:n])
					b = b[n:]
				}
			}
		}
		for i := 0; i < 4 && !pipe; i++ {
			r := req(i, strings.Repeat("r", 1+rng.Intn(20)))
			w := resp(i, strings.Repeat("w", rng.Intn(30)))
			if rng.Intn(3) == 0 {
				w = chunkedResp(i, strings.Repeat("w", rng.Intn(30)))
			}
			in, owed := carry+r, len(carry)
			carry = ""
			if rng.Intn(3) == 0 {
				cut := min(owed+strings.Index(r, "\r\n\r\n")+4+rng.Intn(5), len(in)-1)
				in, carry = in[:cut], in[cut:]
				log = append(log, fmt.Sprintf("R%d early cut=%d of %d", i, cut, len(in)+len(carry)))
			}
			for len(in) > 0 {
				k := 1 + rng.Intn(len(in))
				log = append(log, fmt.Sprintf("read R%d %q", i, in[:k]))
				wipeMaybe()
				s.read(in[:k])
				in = in[k:]
			}
			for len(w) > 0 {
				k := 1 + rng.Intn(len(w))
				log = append(log, fmt.Sprintf("write S%d %q", i, w[:k]))
				wipeMaybe()
				s.write(w[:k])
				w = w[k:]
			}
		}
		s.close()
		for _, p := range cp.pairs {
			a, b := idOf(p.req), idOf(p.resp)
			if silent && (!intactID(p.req, a) || !intactID(p.resp, b)) {
				continue // a message spliced at a gap, not a crossed pair
			}
			if a != "" && b != "" && a != b {
				t.Fatalf("seed %d chunk %d: crossed %s/%s\n%s\nREQ=%q\nRESP=%q", seed, s.chunk, a, b, strings.Join(log, "\n"), p.req, p.resp)
			}
		}
	}
}

// intactID reports whether msg names exchange id the same way in its start
// line and in its X-Request-Id header (a splice at a gap rarely keeps both).
func intactID(msg, id string) bool {
	return len(id) == 1 && id[0] >= '0' && id[0] <= '3' &&
		strings.Contains(msg, "\r\nX-Request-Id: "+id+"\r\n")
}
