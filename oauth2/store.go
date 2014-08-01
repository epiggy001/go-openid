package oauth2

import (
	"sync"
	"time"
)

type ClientStore interface {
	Save(c *Client) (string, error)
	Remove(id string) error
	Read(id string) (*Client, error)
}

type TokenStore interface {
	Save(t *Token) (string, error)
	Remove(id string) error
	Read(id string) (*Token, error)
}

type MemoryStore struct {
	store  map[string]interface{}
	locker *sync.RWMutex
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{make(map[string]interface{}), new(sync.RWMutex)}
}

func (m *MemoryStore) Save(id string, data interface{}) {
	m.locker.Lock()
	defer m.locker.Unlock()
	m.store[id] = data
}

func (m *MemoryStore) Remove(id string) {
	m.locker.Lock()
	defer m.locker.Unlock()
	delete(m.store, id)
}

func (m *MemoryStore) Read(id string) interface{} {
	m.locker.RLock()
	defer m.locker.RUnlock()
	data, ok := m.store[id]
	if !ok {
		return nil
	}
	return data
}

type MemoryTokenStore struct {
	store *MemoryStore
}

func NewTokenStore() *MemoryTokenStore {
	return &MemoryTokenStore{NewMemoryStore()}
}

func (m *MemoryTokenStore) Save(t *Token) (string, error) {
	m.store.Save(t.Value, t)
	return t.Value, nil
}

func (m *MemoryTokenStore) Remove(id string) error {
	m.store.Remove(id)
	return nil
}

func (m *MemoryTokenStore) Read(id string) (*Token, error) {
	t, ok := m.store.Read(id).(*Token)
	if !ok {
		return nil, nil
	}
	if t.CreatedAt+t.Life < time.Now().Unix() {
		return nil, nil
	}
	return t, nil
}
