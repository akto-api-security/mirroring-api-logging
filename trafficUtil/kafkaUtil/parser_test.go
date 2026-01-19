package kafkaUtil

import (
	"compress/gzip"
	"bytes"
	"testing"
)

func TestParseHTTPTraffic_ValidRequest(t *testing.T) {
	reqBody := `{"cardId":12,"amount":9100.50,"bookingId":4123}`
	req := []byte("POST /credit-cards/charge HTTP/1.1\r\nHost: credit-card.default.svc.cluster.local\r\nContent-Type: application/json\r\nContent-Length: 47\r\n\r\n" + reqBody)

	respBody := `{"status":"success"}`
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n" + respBody)

	result := parseHTTPTraffic(req, resp, true)

	if result == nil {
		t.Fatal("expected non-nil result for valid request")
	}
	if len(result.Requests) != 1 {
		t.Errorf("expected 1 request, got %d", len(result.Requests))
	}
	if len(result.Responses) != 1 {
		t.Errorf("expected 1 response, got %d", len(result.Responses))
	}
	if result.RequestBodies[0] != reqBody {
		t.Errorf("unexpected request body: %s", result.RequestBodies[0])
	}
	if result.ResponseBodies[0] != respBody {
		t.Errorf("unexpected response body: %s", result.ResponseBodies[0])
	}
}

func TestParseHTTPTraffic_BadGzip(t *testing.T) {
	reqBody := `{"cardId":12}`
	req := []byte("POST /credit-cards/charge HTTP/1.1\r\nHost: credit-card.default.svc.cluster.local\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n" + reqBody)

	// Response claims gzip but body is not gzip encoded
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\nnot-gzip-data")

	result := parseHTTPTraffic(req, resp, true)

	if result == nil {
		t.Fatal("should not return nil on gzip failure")
	}
	if len(result.Requests) != 1 {
		t.Errorf("expected 1 request, got %d", len(result.Requests))
	}
	if len(result.Responses) != 1 {
		t.Errorf("expected 1 response, got %d", len(result.Responses))
	}
	if result.ResponseBodies[0] != "" {
		t.Errorf("expected empty body on gzip failure, got: %s", result.ResponseBodies[0])
	}
}

func TestParseHTTPTraffic_TruncatedGzip(t *testing.T) {
	req := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")

	// Create valid gzip but truncate it
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte("hello world this is a longer message"))
	gz.Close()
	truncatedGzip := buf.Bytes()[:10] // Truncate to first 10 bytes

	resp := append([]byte("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n"), truncatedGzip...)

	result := parseHTTPTraffic(req, resp, true)

	if result == nil {
		t.Fatal("should not return nil on truncated gzip")
	}
	if result.ResponseBodies[0] != "" {
		t.Errorf("expected empty body on truncated gzip, got: %s", result.ResponseBodies[0])
	}
}

func TestParseHTTPTraffic_ValidGzip(t *testing.T) {
	req := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")

	// Create valid gzip response
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte(`{"status":"ok"}`))
	gz.Close()

	resp := append([]byte("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Type: application/json\r\n\r\n"), buf.Bytes()...)

	result := parseHTTPTraffic(req, resp, true)

	if result == nil {
		t.Fatal("expected non-nil result for valid gzip")
	}
	if result.ResponseBodies[0] != `{"status":"ok"}` {
		t.Errorf("expected decompressed body, got: %s", result.ResponseBodies[0])
	}
}

func TestParseHTTPTraffic_EmptyRequestBody(t *testing.T) {
	req := []byte("GET /health HTTP/1.1\r\nHost: example.com\r\n\r\n")
	resp := []byte("HTTP/1.1 200 OK\r\n\r\nOK")

	result := parseHTTPTraffic(req, resp, false)

	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.RequestBodies[0] != "" {
		t.Errorf("expected empty request body for GET, got: %s", result.RequestBodies[0])
	}
	if result.ResponseBodies[0] != "OK" {
		t.Errorf("expected 'OK' response body, got: %s", result.ResponseBodies[0])
	}
}

func TestParseHTTPTraffic_MultipleRequests(t *testing.T) {
	req := []byte("GET /first HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\nGET /second HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n")
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirstHTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecond")

	result := parseHTTPTraffic(req, resp, false)

	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Requests) != 2 {
		t.Errorf("expected 2 requests, got %d", len(result.Requests))
	}
	if len(result.Responses) != 2 {
		t.Errorf("expected 2 responses, got %d", len(result.Responses))
	}
}

func TestParseHTTPTraffic_InvalidRequest(t *testing.T) {
	req := []byte("not a valid http request")
	resp := []byte("HTTP/1.1 200 OK\r\n\r\nOK")

	result := parseHTTPTraffic(req, resp, false)

	// Should return nil because request parsing fails completely
	if result != nil {
		t.Error("expected nil result for invalid request")
	}
}

func TestParseHTTPTraffic_NoRequests(t *testing.T) {
	req := []byte("")
	resp := []byte("HTTP/1.1 200 OK\r\n\r\nOK")

	result := parseHTTPTraffic(req, resp, false)

	if result != nil {
		t.Error("expected nil result for empty request buffer")
	}
}
