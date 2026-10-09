package kafkaUtil

import (
	"bytes"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"slices"

	"github.com/akto-api-security/gomiddleware/http2parser"
)

// http2Preface is the client connection preface (RFC 9113 §3.4). It is always the first thing
// on the request side of an HTTP/2 connection, so it identifies both the protocol and direction.
var http2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

var http2ParseOpts = http2parser.NewParseOptions(
	http2parser.WithBase64Encoding(true),
	http2parser.WithWaitForEndStream(true),
	http2parser.WithGRPCTrailers(true),
)

// IsHTTP2 reports whether reqBuffer is the start of an HTTP/2 connection.
func IsHTTP2(reqBuffer []byte) bool {
	return bytes.HasPrefix(reqBuffer, http2Preface)
}

// parseHTTP2Traffic decodes the HTTP/2 frames of one connection window and returns the
// completed streams as request/response pairs, so they flow through the HTTP/1 producer path.
func parseHTTP2Traffic(reqBuffer, respBuffer []byte, ctx TrafficContext) *ParsedTraffic {
	streams := make(map[uint32]*http2parser.HTTP2Stream)
	if err := http2parser.ParseHTTP2Frames(reqBuffer[len(http2Preface):], streams, true, http2ParseOpts); err != nil {
		slog.Debug("HTTP/2 request parse error", append(TrafficConnIDLogArgs(ctx.ConnID), "error", err)...)
	}
	if err := http2parser.ParseHTTP2Frames(respBuffer, streams, false, http2ParseOpts); err != nil {
		slog.Debug("HTTP/2 response parse error", append(TrafficConnIDLogArgs(ctx.ConnID), "error", err)...)
	}

	parsed := &ParsedTraffic{}
	for _, id := range slices.Sorted(maps.Keys(streams)) {
		s := streams[id]
		if !s.RequestComplete || !s.ResponseComplete {
			continue
		}
		u, err := url.ParseRequestURI(s.Path)
		if err != nil {
			continue
		}
		host := s.RequestHeaders[":authority"]
		if host == "" {
			host = s.RequestHeaders["host"]
		}
		proto := s.GetProtocolType()
		req := http.Request{Method: s.Method, URL: u, Proto: proto, ProtoMajor: 2, Host: host, Header: toHTTPHeader(s.RequestHeaders)}
		resp := http.Response{StatusCode: s.StatusCode, Status: s.Status, Proto: proto, ProtoMajor: 2, Header: toHTTPHeader(s.ResponseHeaders)}

		reqBody, respBody := string(s.RequestBody), string(s.ResponseBody)
		if !shouldParseBody(req.Method, host, u.Path) {
			reqBody, respBody = "", ""
			req.Header.Set("x-akto-skip-sample-update", "true")
		}

		parsed.Requests = append(parsed.Requests, req)
		parsed.RequestBodies = append(parsed.RequestBodies, reqBody)
		parsed.Responses = append(parsed.Responses, resp)
		parsed.ResponseBodies = append(parsed.ResponseBodies, respBody)
	}

	if len(parsed.Requests) == 0 {
		return nil
	}
	return parsed
}

func toHTTPHeader(m map[string]string) http.Header {
	h := make(http.Header, len(m))
	for k, v := range m {
		h[k] = []string{v}
	}
	return h
}
