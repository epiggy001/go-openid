package oauth2

type ClientManager interface {
  Insert(c *Client) (string, error)
  Remove(id string) error
  Read(id string) (*Client, error)
}

type TokenManager interface {
  Insert(t *Token) (string, error)
  Remove(id string) error
  Read(id string) (*Token, error)
}

type CodeManager interface {
  Insert(c *Code) (string, error)
  Remove(id string) error
  Read(id string) (*Code, error)
}

type RefreshTokenManager interface {
  Insert(t *RefreshToken) (string, error)
  Remove(id string) error
  Read(id string) (*RefreshToken, error)
}
