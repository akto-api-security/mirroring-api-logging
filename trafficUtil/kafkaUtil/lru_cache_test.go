package kafkaUtil

import (
	"testing"
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

// BenchmarkLRUCacheGet benchmarks LRU cache Get operation
func BenchmarkLRUCacheGet(b *testing.B) {
	cache := NewLRUCache(10000)

	// Pre-populate
	for i := 0; i < 1000; i++ {
		key := "key" + string(rune(i))
		cache.Put(key, uint8(i%256))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := "key" + string(rune(i%1000))
		cache.Get(key)
	}
}

// BenchmarkLRUCachePut benchmarks LRU cache Put operation
func BenchmarkLRUCachePut(b *testing.B) {
	cache := NewLRUCache(10000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := "key" + string(rune(i%1000))
		cache.Put(key, uint8(i%256))
	}
}
