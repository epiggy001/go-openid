package oauth2

type ClientStore interface {
  Insert(c *Client) (string, error)
  Remove(id string) error
  Read(id string) (*Client, error)
}

type TokenStore interface {
  Insert(t *Token) (string, error)
  Remove(id string) error
  Read(id string) (*Token, error)
}
