package fastparser

import "testing"

// gibps reports throughput of raw input bytes processed, in GiB/s.
func gibps(b *testing.B, ops, bytesPerOp int64) {
	b.ReportMetric(float64(ops*bytesPerOp)/b.Elapsed().Seconds()/(1<<30), "GiB/s")
}

// fbParse parses a fixture pair once (name kept for tests copied from PR #151).
func fbParse(t testing.TB, size string) (*Request, *Response, int64) {
	reqBuf, respBuf := load(t, "req-"+size+".bin"), load(t, "resp-"+size+".bin")
	p := NewFastParser()
	req, err := p.ParseRequest(reqBuf)
	if err != nil {
		t.Fatalf("ParseRequest %s: %v", size, err)
	}
	p2 := NewFastParser()
	resp, err := p2.ParseResponse(respBuf)
	if err != nil {
		t.Fatalf("ParseResponse %s: %v", size, err)
	}
	return req, resp, int64(len(reqBuf) + len(respBuf))
}
