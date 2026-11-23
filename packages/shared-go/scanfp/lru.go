package scanfp

import "container/list"

// lruCache 是零依赖进程内 LRU（map + 双向链表）。非并发安全，由 Store.mu 守护。
type lruCache struct {
	capacity int
	ll       *list.List // Front = 最近使用
	items    map[string]*list.Element
}

type lruItem struct {
	key   string
	entry *Entry
}

func newLRUCache(capacity int) *lruCache {
	return &lruCache{
		capacity: capacity,
		ll:       list.New(),
		items:    make(map[string]*list.Element, capacity),
	}
}

func (c *lruCache) get(key string) (*Entry, bool) {
	el, ok := c.items[key]
	if !ok {
		return nil, false
	}
	c.ll.MoveToFront(el)
	return el.Value.(*lruItem).entry, true
}

func (c *lruCache) put(key string, entry *Entry) {
	if el, ok := c.items[key]; ok {
		el.Value.(*lruItem).entry = entry
		c.ll.MoveToFront(el)
		return
	}
	el := c.ll.PushFront(&lruItem{key: key, entry: entry})
	c.items[key] = el
	if c.ll.Len() > c.capacity {
		oldest := c.ll.Back()
		if oldest != nil {
			c.ll.Remove(oldest)
			delete(c.items, oldest.Value.(*lruItem).key)
		}
	}
}
