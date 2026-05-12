package kafkaUtil

import (
	"container/list"
	"sync"
)

type LRUCache struct {
	capacity int
	cache    map[string]*list.Element
	list     *list.List
	mu       sync.RWMutex
}

type lruEntry struct {
	key        string
	timeBucket uint8
}

func NewLRUCache(capacity int) *LRUCache {
	return &LRUCache{
		capacity: capacity,
		cache:    make(map[string]*list.Element),
		list:     list.New(),
	}
}

func (c *LRUCache) Get(key string) (uint8, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if elem, found := c.cache[key]; found {
		c.list.MoveToFront(elem)
		return elem.Value.(*lruEntry).timeBucket, true
	}
	return 0, false
}

func (c *LRUCache) Put(key string, timeBucket uint8) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, found := c.cache[key]; found {
		c.list.MoveToFront(elem)
		elem.Value.(*lruEntry).timeBucket = timeBucket
		return
	}

	if c.list.Len() >= c.capacity {
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
