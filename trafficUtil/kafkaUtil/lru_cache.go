package kafkaUtil

import (
	"container/list"
	"sync"
)

// LRUCache is a simple LRU cache for tracking recent request signatures
type LRUCache struct {
	capacity int
	cache    map[string]*list.Element
	list     *list.List
	mu       sync.RWMutex
}

type lruEntry struct {
	key        string
	timeBucket uint8 // 0-255 representing time buckets
}

// NewLRUCache creates a new LRU cache with the given capacity
func NewLRUCache(capacity int) *LRUCache {
	return &LRUCache{
		capacity: capacity,
		cache:    make(map[string]*list.Element),
		list:     list.New(),
	}
}

// Get retrieves a value from the cache and moves it to the front (most recently used)
// Returns the time bucket and a boolean indicating if the key was found
func (c *LRUCache) Get(key string) (uint8, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if elem, found := c.cache[key]; found {
		c.list.MoveToFront(elem)
		return elem.Value.(*lruEntry).timeBucket, true
	}
	return 0, false
}

// Put inserts or updates a key-value pair in the cache
// If the cache is at capacity, the least recently used entry is evicted
func (c *LRUCache) Put(key string, timeBucket uint8) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, found := c.cache[key]; found {
		c.list.MoveToFront(elem)
		elem.Value.(*lruEntry).timeBucket = timeBucket
		return
	}

	if c.list.Len() >= c.capacity {
		// Evict oldest (least recently used)
		oldest := c.list.Back()
		if oldest != nil {
			c.list.Remove(oldest)
			delete(c.cache, oldest.Value.(*lruEntry).key)
		}
	}

	entry := &lruEntry{key: key, timeBucket: timeBucket}
	elem := c.list.PushFront(entry)
	c.cache[key] = elem
}
