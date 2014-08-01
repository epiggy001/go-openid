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
	m := NewTokenStore()
	if m == nil || m.store == nil {
		t.Error("Fail to create token store")
	}
}

func TestTokenStoreSaveAndRead(t *testing.T) {
	m := NewTokenStore()
	token := NewToken(kClientId, kScope, kBaseUri, kLife)
	id, err := m.Save(token)
	if err != nil {
		t.Error("Fail to save token")
	}
	rtoken, err := m.Read(id)
	if err != nil {
		t.Error("Fail to read token")
	}
	if rtoken != token {
		t.Error("Read wrong token")
	}
}

func TestTokenStoreRemove(t *testing.T) {
	m := NewTokenStore()
	token := NewToken(kClientId, kScope, kBaseUri, kLife)
	id, _ := m.Save(token)
	err := m.Remove(id)
	if err != nil {
		t.Error("Fail to remove token")
	}
	if rtoken, _ := m.Read(id); rtoken != nil {
		t.Error("Fail to remove token but no error reported")
	}
}
