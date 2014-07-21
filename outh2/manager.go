package oauth2

import (
  "net/http"
  "net/url"
)

const (
  authorizationCode = "authorization_code"
)

type managers struct {
  Client       ClientManager
  Code         CodeManager
  Token        TokenManager
  RefreshToken RefreshTokenManager
}

type OauthManager struct {
  CodeLife         int64
  TokenLife        int64
  RefreshTokenLife int64
  AllowGetMethod   bool

  Managers *managers

  ClientAuthFunc func(r *http.Request, c *Client) bool
}

func (m *OauthManager) getClient(r *http.Request) (*Client, error) {
  clientId := r.Form.Get("client_id")
  client, err := m.Managers.Client.Read(clientId)
  if err != nil {
    return nil, NewAuthError(nil, E_SERVER_ERROR, err.Error())
  }

  if client == nil {
    return nil, NewAuthError(nil, E_UNAUTHORIZED_CLIENT, "Failt to read client")
  }

  if !m.ClientAuthFunc(r, client) {
    return nil, NewAuthError(client, E_UNAUTHORIZED_CLIENT, "Failt to validate client")
  }

  if (r.Method == "GET" && !m.AllowGetMethod) || (r.Method != "POST") {
    return nil, NewAuthError(client, E_INVALID_REQUEST, "Invalid request method")
  }
  return client, nil
}

func validateUri(base, uri string) bool {
  return true
}

func (m *OauthManager) GenerateCode(w http.ResponseWriter,
  r *http.Request) (*Code, error) {
  err := r.ParseForm()
  if err != nil {
    return nil, NewAuthError(nil, E_INVALID_REQUEST, err.Error())
  }

  client, err := m.getClient(r)
  if err != nil {
    return nil, err
  }

  grantType := r.Form.Get("grant_type")
  if grantType != authorizationCode {
    return nil, NewAuthError(client, E_INVALID_REQUEST,
      "Only grant type is supported now")
  }

  redirectUri := r.Form.Get("redirect_uri")
  if redirectUri == "" {
    redirectUri = client.BaseUri
  } else if !validateUri(client.BaseUri, redirectUri) {
    return nil, NewAuthError(client, E_INVALID_REQUEST, "Invalid redirect uri")
  }

  scope := r.Form.Get("scope")
  code := NewCode(client.Id, scope, redirectUri, m.CodeLife)
  return code, nil
}

func (m *OauthManager) RedirectUrlWithCode(code *Code) (*url.URL, error) {
  uri, err := url.Parse(code.RedirectUri)
  if err != nil {
    client, _ := m.Managers.Client.Read(code.ClientId)
    return nil, NewAuthError(client, E_INVALID_REQUEST, "Invalid redirect uri")
  }
  uri.Query().Set("scope", code.Scope)
  uri.Query().Set("code", code.Value)
  return uri, nil
}
