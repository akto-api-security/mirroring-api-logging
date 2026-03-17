package kafkaUtil

import (
	"fmt"
	"testing"
	bloomfilter "github.com/bits-and-blooms/bloom/v3"
)

// TestLRUCache tests the LRU cache implementation
func TestLRUCache(t *testing.T) {
	cache := NewLRUCache(3)

	// Test Put and Get
	cache.Put("key1", 1)
	bucket, found := cache.Get("key1")
	if !found || bucket != 1 {
		t.Errorf("Expected key1=1, got found=%v, bucket=%d", found, bucket)
	}

	// Test Get non-existent key
	_, found = cache.Get("nonexistent")
	if found {
		t.Errorf("Expected nonexistent key to not be found")
	}

	// Test capacity and eviction
	cache.Put("key2", 2)
	cache.Put("key3", 3)
	cache.Put("key4", 4) // Should evict key1

	_, found = cache.Get("key1")
	if found {
		t.Errorf("Expected key1 to be evicted")
	}

	// Check that key4 is present
	bucket, found = cache.Get("key4")
	if !found || bucket != 4 {
		t.Errorf("Expected key4=4, got found=%v, bucket=%d", found, bucket)
	}
}

// TestBuildSignatureKey tests signature key generation
func TestBuildSignatureKey(t *testing.T) {
	tests := []struct {
		method   string
		host     string
		path     string
		expected string
	}{
		{"GET", "example.com", "/api/users", "GET|example.com|/api/users"},
		{"POST", "api.example.com", "/v1/data", "POST|api.example.com|/v1/data"},
		{"DELETE", "localhost:8080", "/test", "DELETE|localhost:8080|/test"},
	}

	for _, tt := range tests {
		result := buildSignatureKey(tt.method, tt.host, tt.path)
		if result != tt.expected {
			t.Errorf("buildSignatureKey(%s, %s, %s) = %s, want %s",
				tt.method, tt.host, tt.path, result, tt.expected)
		}
	}
}

// TestGetTimeBucket tests time bucket generation
func TestGetTimeBucket(t *testing.T) {
	bucket1 := getTimeBucket()
	if bucket1 < 0 || bucket1 > 255 {
		t.Errorf("getTimeBucket() returned %d, expected 0-255", bucket1)
	}

	// Get bucket again immediately (should be same)
	bucket2 := getTimeBucket()
	if bucket1 != bucket2 {
		t.Errorf("Expected same bucket for immediate calls: %d vs %d", bucket1, bucket2)
	}
}

// TestIsTimeBucketExpired tests time bucket expiration detection
func TestIsTimeBucketExpired(t *testing.T) {
	// Test recent bucket (should not be expired)
	currentBucket := getTimeBucket()
	if isTimeBucketExpired(currentBucket) {
		t.Errorf("Current bucket should not be expired")
	}

	// Test old bucket (should be expired)
	oldBucket := uint8((int(currentBucket) - 5 + 256) % 256)
	if !isTimeBucketExpired(oldBucket) {
		t.Errorf("Old bucket should be expired")
	}
}

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

// TestLRUCacheEviction tests that LRU cache correctly evicts oldest entries
func TestLRUCacheEviction(t *testing.T) {
	cache := NewLRUCache(2)

	// Add 2 entries
	cache.Put("a", 1)
	cache.Put("b", 2)

	// Both should be present
	_, foundA := cache.Get("a")
	_, foundB := cache.Get("b")
	if !foundA || !foundB {
		t.Errorf("Both entries should be present")
	}

	// Add third entry (should evict oldest)
	cache.Put("c", 3)

	// "a" should be evicted (least recently used)
	_, foundA = cache.Get("a")
	if foundA {
		t.Errorf("Entry 'a' should be evicted")
	}

	// "b" and "c" should still be present
	_, foundB = cache.Get("b")
	_, foundC := cache.Get("c")
	if !foundB || !foundC {
		t.Errorf("Entries 'b' and 'c' should be present")
	}
}

// TestLRUCacheUpdate tests that updating an entry moves it to front
func TestLRUCacheUpdate(t *testing.T) {
	cache := NewLRUCache(2)

	cache.Put("a", 1)
	cache.Put("b", 2)

	// Access "a" to move it to front
	cache.Get("a")

	// Add third entry (should evict "b" since "a" was more recently accessed)
	cache.Put("c", 3)

	// "b" should be evicted, not "a"
	_, foundA := cache.Get("a")
	_, foundB := cache.Get("b")
	if !foundA {
		t.Errorf("Entry 'a' should not be evicted")
	}
	if foundB {
		t.Errorf("Entry 'b' should be evicted")
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

// BenchmarkLRUCacheGet benchmarks LRU cache Get operation
func BenchmarkLRUCacheGet(b *testing.B) {
	cache := NewLRUCache(10000)

	// Pre-populate
	for i := 0; i < 1000; i++ {
		key := fmt.Sprintf("key%d", i)
		cache.Put(key, uint8(i%256))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("key%d", i%1000)
		cache.Get(key)
	}
}

// BenchmarkBuildSignatureKey benchmarks signature key building
func BenchmarkBuildSignatureKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		buildSignatureKey("GET", "example.com", "/api/users/123")
	}
}
