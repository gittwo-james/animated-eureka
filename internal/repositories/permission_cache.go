package repositories

import (
	"sync"
	"time"
)

type PermissionCache struct {
	items sync.Map
	ttl   time.Duration
}

type cacheItem struct {
	value     interface{}
	expiresAt time.Time
}

func NewPermissionCache() *PermissionCache {
	return &PermissionCache{
		ttl: 5 * time.Minute,
	}
}

func (c *PermissionCache) Get(key string) (interface{}, bool) {
	val, ok := c.items.Load(key)
	if !ok {
		return nil, false
	}
	item := val.(cacheItem)
	if time.Now().After(item.expiresAt) {
		c.items.Delete(key)
		return nil, false
	}
	return item.value, true
}

func (c *PermissionCache) Set(key string, value interface{}) {
	c.items.Store(key, cacheItem{
		value:     value,
		expiresAt: time.Now().Add(c.ttl),
	})
}

func (c *PermissionCache) Invalidate(key string) {
	c.items.Delete(key)
}
