package oauth2

import (
  "sync"
)

type MockStorage struct {
  store  map[string]interface{}
  locker *sync.RWMutex
}

func NewMockStorage() *MockStorage {
  return &MockStorage{make(map[string]interface{}), new(sync.RWMutex)}
}

func (m *MockStorage) Insert(id string, data interface{}) {
  m.locker.Lock()
  defer m.locker.Unlock()
  m.store[id] = data
}

func (m *MockStorage) Remove(id string) {
  m.locker.Lock()
  defer m.locker.Unlock()
  delete(m.store, id)
}

func (m *MockStorage) Read(id string) interface{} {
  m.locker.RLock()
  defer m.locker.RUnlock()
  data, ok := m.store[id]
  if !ok {
    return nil
  }
  return data
}

type MockClientStore struct {
  store *MockStorage
}

func NewMockClientStore() *MockClientStore {
  return &MockClientStore{NewMockStorage()}
}

func (m *MockClientStore) Insert(c *Client) (string, error) {
  m.store.Insert(c.Id, c)
  return c.Id, nil
}

func (m *MockClientStore) Remove(id string) error {
  m.store.Remove(id)
  return nil
}

func (m *MockClientStore) Read(id string) (*Client, error) {
  c, _ := m.store.Read(id).(*Client)
  return c, nil
}