// Copyright 2013 Clustertech Limited. All rights reserved.
//
// Author: jackeychen (jackeychen@clustertech.com)
package oauth2

import (
  "testing"
)

type MockClientStore struct {
  store *MemoryStore
}

func NewMockClientStore() *MockClientStore {
  return &MockClientStore{NewMemoryStore()}
}

func (m *MockClientStore) Save(c *Client) (string, error) {
  m.store.Save(c.Id, c)
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

func TestGenerateCode(t *testing.T) {

}
