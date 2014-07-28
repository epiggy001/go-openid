package oauth2

import (
  "fmt"
)

type Client struct {
  Id          string
  Secret      string
  BaseUri     string
  Description string
}

func (c *Client) String() string {
  return fmt.Sprintf("client %s for %s", c.Id, c.BaseUri)
}

func NewClient(id, secret, uri, des string) *Client {
  return &Client{id, secret, uri, des}
}

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

