package oauth2

import (
  "net/http"
)

const (
  authorizationCode = "authorization_code"
)

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

type managers struct {
  Client       ClientManager
  Code         CodeManager
  Token        TokenManager
  RefreshToken RefreshTokenManager
}

type OauthManager struct {
  CodeLife         int32
  TokenLife        int32
  RefreshTokenLife int32
  AllowGetMethod   bool

  Managers *managers

  ClientAuthFunc func(r *http.Request, c *Client) bool
}

func (m *OauthManager) getClient(r *http.Request) (*Client, error) {
  clientId := r.Form.Get("client_id")
  client, err := m.Managers.Client.Read(clientId)
  if err != nil {
    return nil, NewAuthError(nil, E_INVALID_CLIENT, err.Error())
  }

  if client == nil {
    return nil, NewAuthError(nil, E_INVALID_CLIENT, "Failt to read client")
  }

  if !m.ClientAuthFunc(r, client) {
    return nil, NewAuthError(nil, E_INVALID_CLIENT, "Failt to validate client")
  }

  if (r.Method == "GET" && !m.AllowGetMethod) || (r.Method != "POST") {
    return nil, NewAuthError(nil, E_INVALID_REQUEST, "Invalid request method")
  }
  return client, nil
}

func (m *OauthManager) HandleAuthRequest(w http.ResponseWriter,
  r *http.Request) error {
  err := r.ParseForm()
  if err != nil {
    return NewAuthError(nil, E_INVALID_REQUEST, err.Error())
  }

  _, err = m.getClient(r)
  if err != nil {
    return err
  }

  grantType := r.Form.Get("grant_type")
  if grantType != authorizationCode {
    return NewAuthError(nil, E_INVALID_REQUEST, "Fail to parse request")
  }

  return nil
}
