package oauth2

import (
  "fmt"
)

type Client struct {
  Id          string
  Secret      string
  BaseUrl     string
  Description string
}

func (c *Client) String() string {
  return fmt.Sprintf("client %s for %s", c.Id, c.BaseUrl)
}

func NewClient(id, secret, url, des string) *Client {
  return &Client{id, secret, url, des}
}
