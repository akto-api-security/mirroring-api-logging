package kafkaUtil

import (
	"fmt"
	"testing"
	bloomfilter "github.com/bits-and-blooms/bloom/v3"
)

// TestShouldParseBodyFirstRequest tests that first request body is parsed
func TestShouldParseBodyFirstRequest(t *testing.T) {
	// Reset Bloom filter for testing
	bloomFilter = bloomfilter.NewWithEstimates(uint(bloomFilterCapacity), bloomFilterFPRate)
	lruCache = NewLRUCache(lruCacheCapacity)

	// First request should always be parsed
	if !shouldParseBody("GET", "example.com", "/api/test") {
		t.Errorf("First request should always parse body")
	}
}

// TestShouldParseBodySkipRecent tests that recent requests skip body parsing
func TestShouldParseBodySkipRecent(t *testing.T) {
	// Reset Bloom filter and LRU for testing
	bloomFilter = bloomfilter.NewWithEstimates(uint(bloomFilterCapacity), bloomFilterFPRate)
	lruCache = NewLRUCache(lruCacheCapacity)

	method, host, path := "POST", "api.example.com", "/v1/submit"

	// First request should parse body
	shouldParse1 := shouldParseBody(method, host, path)
	if !shouldParse1 {
		t.Errorf("First request should parse body")
	}

	// Immediate second request should skip body
	shouldParse2 := shouldParseBody(method, host, path)
	if shouldParse2 {
		t.Errorf("Recent request should skip body, but got shouldParse=%v", shouldParse2)
	}

	// Third request should also skip body
	shouldParse3 := shouldParseBody(method, host, path)
	if shouldParse3 {
		t.Errorf("Recent request should skip body, but got shouldParse=%v", shouldParse3)
	}
}

// TestShouldParseBodyDifferentSignatures tests different signatures are tracked separately
func TestShouldParseBodyDifferentSignatures(t *testing.T) {
	// Reset Bloom filter and LRU for testing
	bloomFilter = bloomfilter.NewWithEstimates(uint(bloomFilterCapacity), bloomFilterFPRate)
	lruCache = NewLRUCache(lruCacheCapacity)

	// First signature
	should1a := shouldParseBody("GET", "example.com", "/api/users")
	if !should1a {
		t.Errorf("First request for signature 1 should parse body")
	}

	// Skip immediate request for signature 1
	should1b := shouldParseBody("GET", "example.com", "/api/users")
	if should1b {
		t.Errorf("Second request for signature 1 should skip body")
	}

	// Different signature - should parse body
	should2a := shouldParseBody("GET", "example.com", "/api/orders")
	if !should2a {
		t.Errorf("First request for signature 2 should parse body")
	}

	// Different method - should parse body
	should3a := shouldParseBody("POST", "example.com", "/api/users")
	if !should3a {
		t.Errorf("First request for signature 3 (different method) should parse body")
	}

	// Different host - should parse body
	should4a := shouldParseBody("GET", "other.com", "/api/users")
	if !should4a {
		t.Errorf("First request for signature 4 (different host) should parse body")
	}
}

// BenchmarkShouldParseBody benchmarks the shouldParseBody function
func BenchmarkShouldParseBody(b *testing.B) {
	// Reset
	bloomFilter = bloomfilter.NewWithEstimates(uint(bloomFilterCapacity), bloomFilterFPRate)
	lruCache = NewLRUCache(lruCacheCapacity)

	// Pre-populate with some data
	for i := 0; i < 1000; i++ {
		path := fmt.Sprintf("/api/test%d", i%10)
		shouldParseBody("GET", "example.com", path)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		path := fmt.Sprintf("/api/test%d", i%10)
		shouldParseBody("GET", "example.com", path)
	}
}
