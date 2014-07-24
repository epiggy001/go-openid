package oauth2

import (
  "testing"
)

type mockData struct {
}

func TestNewMemoryStore(t *testing.T) {
  m := NewMemoryStore()
  if m == nil {
    t.Error("Fail to create memory store")
  }
  if m.store == nil {
    t.Error("Fail to create map for memory store")
  }
  if m.locker == nil {
    t.Error("Fail to create locker for memory store")
  }
}

func TestMemoryStoreSaveAndRead(t *testing.T) {
  m := NewMemoryStore()
  data := &mockData{}
  id := "id"
  m.Save(id, data)
  rdata := m.Read(id)
  if data != rdata {
    t.Error("Memory store fail to save and read")
  }
}

func TestMemoryStoreRemove(t *testing.T) {
  m := NewMemoryStore()
  data := &mockData{}
  id := "id"
  m.Save(id, data)
  m.Remove(id)
  if m.Read(id) != nil {
    t.Error("Memory store fail to remove data")
  }
}

func TestNewTokenStore(t *testing.T) {
}
