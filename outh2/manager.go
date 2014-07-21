package oauth2

import (
  "net/http"
  "net/url"
  "strconv"
)

const (
  authorizationCode = "authorization_code"
)

type managers struct {
  Client       ClientStore
  Code         TokenStore
  Token        TokenStore
  RefreshToken TokenStore
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
    return nil, NewAuthError(nil, E_UNAUTHORIZED_CLIENT,
      "Failt to read client")
  }

  if !m.ClientAuthFunc(r, client) {
    return nil, NewAuthError(client, E_UNAUTHORIZED_CLIENT,
      "Failt to validate client")
  }
  return client, nil
}

func validateUri(base, uri string) bool {
  return true
}

func (m *OauthManager) GenerateCode(w http.ResponseWriter,
  r *http.Request) (*Token, error) {
  err := r.ParseForm()
  if err != nil {
    return nil, NewAuthError(nil, E_INVALID_REQUEST, err.Error())
  }

  client, err := m.getClient(r)
  if err != nil {
    return nil, err
  }

  if (r.Method == "GET" && !m.AllowGetMethod) || (r.Method != "POST") {
    return nil, NewAuthError(client, E_INVALID_REQUEST,
      "Invalid request method")
  }

  responseType := r.Form.Get("response_type")
  if responseType != "code" {
    return nil, NewAuthError(client, E_UNSUPPORTED_RESPONSE_TYPE,
      "Only code response type is supported now")
  }

  redirectUri := r.Form.Get("redirect_uri")
  if redirectUri == "" {
    redirectUri = client.BaseUri
  } else if !validateUri(client.BaseUri, redirectUri) {
    return nil, NewAuthError(client, E_INVALID_REQUEST, "Invalid redirect uri")
  }

  scope := r.Form.Get("scope")
  code := NewToken(client.Id, scope, redirectUri, m.CodeLife)
  _, err = m.Managers.Code.Insert(code)
  if err != nil {
    return nil, NewAuthError(client, E_SERVER_ERROR, err.Error())
  }
  return code, nil
}

func (m *OauthManager) RedirectUrlWithCode(code *Token) (*url.URL, error) {
  uri, err := url.Parse(code.RedirectUri)
  if err != nil {
    client, _ := m.Managers.Client.Read(code.ClientId)
    return nil, NewAuthError(client, E_INVALID_REQUEST, "Invalid redirect uri")
  }
  uri.Query().Set("scope", code.Scope)
  uri.Query().Set("code", code.Value)
  return uri, nil
}

func (m *OauthManager) GenerateToken(w http.ResponseWriter,
  r *http.Request) (*Token, error) {
  err := r.ParseForm()
  if err != nil {
    return nil, NewAuthError(nil, E_INVALID_REQUEST, err.Error())
  }

  client, err := m.getClient(r)
  if err != nil {
    return nil, err
  }

  if (r.Method == "GET" && !m.AllowGetMethod) || (r.Method != "POST") {
    return nil, NewAuthError(client, E_INVALID_REQUEST,
      "Invalid request method")
  }

  responseType := r.Form.Get("grant_type")
  if responseType != authorizationCode {
    return nil, NewAuthError(client, E_INVALID_REQUEST,
      "Only authorization code grant type is supported now")
  }

  code, err := m.Managers.Code.Read(r.Form.Get("code"))
  if err != nil {
    return nil, NewAuthError(client, E_SERVER_ERROR, err.Error())
  }
  if code == nil {
    return nil, NewAuthError(client, E_INVALID_REQUEST, "Invalid code")
  }

  if code.ClientId != client.Id {
    return nil, NewAuthError(client, E_INVALID_REQUEST, "Client is mismatch")
  }

  redirectUri := r.Form.Get("redirect_uri")
  if redirectUri == "" {
    redirectUri = client.BaseUri
  } else if !validateUri(client.BaseUri, redirectUri) {
    return nil, NewAuthError(client, E_INVALID_REQUEST, "Invalid redirect uri")
  }

  token := NewToken(client.Id, code.Scope, redirectUri, m.TokenLife)
  _, err = m.Managers.Token.Insert(token)
  if err != nil {
    return nil, NewAuthError(client, E_SERVER_ERROR, err.Error())
  }
  return token, nil
}

func (m *OauthManager) RedirectUrlWithToken(token *Token) (*url.URL, error) {
  uri, err := url.Parse(token.RedirectUri)
  if err != nil {
    client, _ := m.Managers.Client.Read(token.ClientId)
    return nil, NewAuthError(client, E_INVALID_REQUEST, "Invalid redirect uri")
  }
  uri.Query().Set("scope", token.Scope)
  uri.Query().Set("access_token", token.Scope)
  uri.Query().Set("expires_in", strconv.FormatInt(token.Life, 10))
  return uri, nil
}
