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
