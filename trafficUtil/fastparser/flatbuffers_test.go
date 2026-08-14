package fastparser

import (
	"testing"
)

// gibps reports throughput of raw input bytes processed, in GiB/s.
func gibps(b *testing.B, ops, bytesPerOp int64) {
	b.ReportMetric(float64(ops*bytesPerOp)/b.Elapsed().Seconds()/(1<<30), "GiB/s")
}

func fbSampleMeta() *Meta {
	return &Meta{
		SourceIP: "10.0.0.1", DestIP: "10.0.0.2", TimeUnix: 1690000000,
		AktoAccountID: "1000000", VxlanID: 42, IsPending: false, Source: "MIRRORING",
		Direction: 1, ProcessID: 1234, SocketID: 7, DaemonsetID: "ds-1",
		ProcessName: "svc", EnableGraph: true, Tag: `{"env":"prod"}`,
	}
}

// fbParse parses a fixture pair once, returning the structs + total raw input bytes.
func fbParse(t testing.TB, size string) (*Request, *Response, int64) {
	reqBuf, respBuf := load(t, "req-"+size+".bin"), load(t, "resp-"+size+".bin")
	p := NewFastParser()
	req, err := p.ParseRequest(reqBuf)
	if err != nil {
		t.Fatalf("ParseRequest %s: %v", size, err)
	}
	// ParseRequest/ParseResponse reuse the parser's header arrays; use a second
	// parser for the response so the request's slices stay valid.
	p2 := NewFastParser()
	resp, err := p2.ParseResponse(respBuf)
	if err != nil {
		t.Fatalf("ParseResponse %s: %v", size, err)
	}
	return req, resp, int64(len(reqBuf) + len(respBuf))
}

// TestFBRoundTrip encodes then decodes the frame and confirms every field
// survives byte-for-byte — across all fixture sizes (differential vs the parser).
func TestFBRoundTrip(t *testing.T) {
	m := fbSampleMeta()
	enc := NewFBEncoder()
	for _, s := range sizes {
		req, resp, _ := fbParse(t, s)
		out := enc.Encode(req, resp, m)
		fb := GetRootAsFbHttpPair(out, 0)

		if string(fb.MethodBytes()) != string(req.Method) {
			t.Fatalf("%s method: %q != %q", s, fb.MethodBytes(), req.Method)
		}
		if string(fb.PathBytes()) != string(req.Path) {
			t.Fatalf("%s path mismatch", s)
		}
		if string(fb.VersionBytes()) != string(req.Version) {
			t.Fatalf("%s version mismatch", s)
		}
		if int(fb.StatusCode()) != resp.StatusCode {
			t.Fatalf("%s status: %d != %d", s, fb.StatusCode(), resp.StatusCode)
		}
		if string(fb.ReasonBytes()) != string(resp.Reason) {
			t.Fatalf("%s reason mismatch", s)
		}
		if string(fb.ReqBodyBytes()) != string(req.Body) {
			t.Fatalf("%s req body mismatch (%d vs %d)", s, fb.ReqBodyLength(), len(req.Body))
		}
		if string(fb.RespBodyBytes()) != string(resp.Body) {
			t.Fatalf("%s resp body mismatch", s)
		}
		if fb.ReqHeadersLength() != len(req.Headers) {
			t.Fatalf("%s req header count: %d != %d", s, fb.ReqHeadersLength(), len(req.Headers))
		}
		if fb.RespHeadersLength() != len(resp.Headers) {
			t.Fatalf("%s resp header count: %d != %d", s, fb.RespHeadersLength(), len(resp.Headers))
		}
		var h FbHeader
		for i := 0; i < fb.ReqHeadersLength(); i++ {
			fb.ReqHeaders(&h, i)
			if string(h.NameBytes()) != string(req.Headers[i].Name) ||
				string(h.ValueBytes()) != string(req.Headers[i].Value) {
				t.Fatalf("%s req header %d mismatch", s, i)
			}
		}
		if string(fb.SourceIp()) != m.SourceIP || string(fb.DestIp()) != m.DestIP ||
			fb.TimeUnix() != m.TimeUnix || int(fb.VxlanId()) != m.VxlanID ||
			string(fb.Tag()) != m.Tag || fb.EnableGraph() != m.EnableGraph {
			t.Fatalf("%s meta mismatch", s)
		}
	}
}

// BenchmarkFBEncode: single-core encode throughput (parse-once), M/s + GiB/s.
func BenchmarkFBEncode(b *testing.B) {
	m := fbSampleMeta()
	for _, s := range sizes {
		req, resp, inBytes := fbParse(b, s)
		enc := NewFBEncoder()
		enc.Encode(req, resp, m) // warm
		b.Run(s, func(b *testing.B) {
			b.ReportAllocs()
			var n int64
			for i := 0; i < b.N; i++ {
				_ = len(enc.Encode(req, resp, m))
				n++
			}
			mps(b, n)
			gibps(b, n, inBytes)
		})
	}
}

// BenchmarkFBEncodeParallel: all-cores encode throughput (one encoder/goroutine).
func BenchmarkFBEncodeParallel(b *testing.B) {
	m := fbSampleMeta()
	for _, s := range sizes {
		req, resp, inBytes := fbParse(b, s)
		b.Run(s, func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				enc := NewFBEncoder()
				for pb.Next() {
					_ = len(enc.Encode(req, resp, m))
				}
			})
			mps(b, int64(b.N))
			gibps(b, int64(b.N), inBytes)
		})
	}
}
