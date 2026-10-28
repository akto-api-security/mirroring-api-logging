package kafkaUtil

import (
	"testing"

	trafficpb "github.com/akto-api-security/mirroring-api-logging/trafficUtil/protobuf/traffic_payload"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/fastparser"
)

// parseReq builds a fastparser.Request from a header block. Body is empty; only
// the request line + headers matter for source-IP resolution.
func parseReq(t *testing.T, headers string) *fastparser.Request {
	t.Helper()
	raw := []byte("GET /x HTTP/1.1\r\n" + headers + "\r\n")
	req, err := fastparser.NewFastParser().ParseRequest(raw)
	if err != nil {
		t.Fatalf("ParseRequest failed: %v", err)
	}
	return req
}

func TestGetSourceIpFast(t *testing.T) {
	const fallback = "10.0.0.1"

	tests := []struct {
		name    string
		headers string
		want    string
	}{
		{
			name:    "single x-forwarded-for",
			headers: "X-Forwarded-For: 1.2.3.4\r\n",
			want:    "1.2.3.4",
		},
		{
			name:    "comma list returns first token",
			headers: "X-Forwarded-For: 1.2.3.4, 5.6.7.8, 9.9.9.9\r\n",
			want:    "1.2.3.4",
		},
		{
			name:    "first token trimmed of whitespace",
			headers: "X-Forwarded-For:   1.2.3.4  , 5.6.7.8\r\n",
			want:    "1.2.3.4",
		},
		{
			name:    "priority: x-forwarded-for wins over x-real-ip",
			headers: "X-Real-Ip: 5.6.7.8\r\nX-Forwarded-For: 1.2.3.4\r\n",
			want:    "1.2.3.4",
		},
		{
			name:    "falls through to next header when first is empty",
			headers: "X-Forwarded-For:   \r\nX-Real-Ip: 5.6.7.8\r\n",
			want:    "5.6.7.8",
		},
		{
			name:    "case-insensitive header name",
			headers: "x-ForWarDed-fOr: 1.2.3.4\r\n",
			want:    "1.2.3.4",
		},
		{
			name:    "lower-priority header used when only it is present",
			headers: "True-Client-Ip: 7.7.7.7\r\n",
			want:    "7.7.7.7",
		},
		{
			name:    "no client-ip headers falls back to packetIp",
			headers: "Host: example.com\r\nContent-Length: 0\r\n",
			want:    fallback,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := parseReq(t, tc.headers)
			if got := getSourceIpFast(req, fallback); got != tc.want {
				t.Errorf("getSourceIpFast() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestGetSourceIpParity guards against the zero-copy fast variant and the legacy
// map-based GetSourceIp drifting apart: both must resolve the same IP for the
// same request headers.
func TestGetSourceIpParity(t *testing.T) {
	const fallback = "10.0.0.1"

	cases := []string{
		"X-Forwarded-For: 1.2.3.4, 5.6.7.8\r\n",
		"X-Real-Ip: 5.6.7.8\r\nX-Forwarded-For: 1.2.3.4\r\n",
		"True-Client-Ip: 7.7.7.7\r\n",
		"Host: example.com\r\nContent-Length: 0\r\n", // no client-ip header
	}

	for _, headers := range cases {
		req := parseReq(t, headers)

		// Build the map form GetSourceIp expects from the same parsed headers.
		reqHeaders := map[string]*trafficpb.StringList{}
		for _, h := range req.Headers {
			// GetSourceIp looks up lowercase header names (CLIENT_IP_HEADERS are lowercase).
			name := lower(string(h.Name))
			reqHeaders[name] = &trafficpb.StringList{Values: []string{string(h.Value)}}
		}

		fast := getSourceIpFast(req, fallback)
		legacy := GetSourceIp(reqHeaders, fallback)
		if fast != legacy {
			t.Errorf("parity mismatch for %q: fast=%q legacy=%q", headers, fast, legacy)
		}
	}
}

// benchHeaders is a representative request: a proxy-chained X-Forwarded-For plus
// some noise headers the scan must skip past.
const benchHeaders = "Host: example.com\r\n" +
	"User-Agent: bench/1.0\r\n" +
	"Accept: */*\r\n" +
	"X-Forwarded-For: 1.2.3.4, 5.6.7.8, 9.9.9.9\r\n" +
	"X-Real-Ip: 5.6.7.8\r\n"

// BenchmarkGetSourceIpFast measures the zero-copy resolution only (request parsed
// once up front). Expect a single allocation: the returned result string.
func BenchmarkGetSourceIpFast(b *testing.B) {
	raw := []byte("GET /x HTTP/1.1\r\n" + benchHeaders + "\r\n")
	req, err := fastparser.NewFastParser().ParseRequest(raw)
	if err != nil {
		b.Fatalf("ParseRequest failed: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = getSourceIpFast(req, "10.0.0.1")
	}
}

// BenchmarkGetSourceIp measures the legacy resolution with the header map already
// built (map construction excluded). Even so it pays strings.Split on the match.
func BenchmarkGetSourceIp(b *testing.B) {
	raw := []byte("GET /x HTTP/1.1\r\n" + benchHeaders + "\r\n")
	req, err := fastparser.NewFastParser().ParseRequest(raw)
	if err != nil {
		b.Fatalf("ParseRequest failed: %v", err)
	}
	reqHeaders := map[string]*trafficpb.StringList{}
	for _, h := range req.Headers {
		reqHeaders[lower(string(h.Name))] = &trafficpb.StringList{Values: []string{string(h.Value)}}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = GetSourceIp(reqHeaders, "10.0.0.1")
	}
}

// BenchmarkGetSourceIpLegacyWithMapBuild reflects the true fast-path cost the fast
// variant avoids: building the header map on every pair, then resolving.
func BenchmarkGetSourceIpLegacyWithMapBuild(b *testing.B) {
	raw := []byte("GET /x HTTP/1.1\r\n" + benchHeaders + "\r\n")
	req, err := fastparser.NewFastParser().ParseRequest(raw)
	if err != nil {
		b.Fatalf("ParseRequest failed: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reqHeaders := map[string]*trafficpb.StringList{}
		for _, h := range req.Headers {
			reqHeaders[lower(string(h.Name))] = &trafficpb.StringList{Values: []string{string(h.Value)}}
		}
		_ = GetSourceIp(reqHeaders, "10.0.0.1")
	}
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
