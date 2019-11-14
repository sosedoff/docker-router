package main

import (
	"sync"
	"time"
)

type AccessMap struct {
	sync.RWMutex
	items map[string]time.Time
}

func NewAccessMap() AccessMap {
	return AccessMap{
		RWMutex: sync.RWMutex{},
		items:   map[string]time.Time{},
	}
}

func (m *AccessMap) Get(key string) (time.Time, bool) {
	m.RLock()
	defer m.RUnlock()

	val, exists := m.items[key]
	return val, exists
}

func (m *AccessMap) Update(key string) {
	m.Lock()
	m.items[key] = time.Now()
	m.Unlock()
}

func (m *AccessMap) Remove(key string) {
	m.Lock()
	delete(m.items, key)
	m.Unlock()
}

func (m *AccessMap) Items() map[string]time.Time {
	result := map[string]time.Time{}

	m.RLock()
	defer m.RUnlock()

	for k, v := range m.items {
		result[k] = v
	}
	return result
}
