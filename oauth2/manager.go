package oauth2

import (
  "net/http"
  "net/url"
  "encoding/json"
)

const (
  authorizationCode = "authorization_code"
)

type Storage struct {
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

  Storage *Storage

  ClientAuthFunc func(r *http.Request, c *Client) bool
}

func (m *OauthManager) getClient(r *http.Request) (*Client, error) {
  clientId := r.Form.Get("client_id")
  client, err := m.Storage.Client.Read(clientId)
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
  _, err = m.Storage.Code.Insert(code)
  if err != nil {
    return nil, NewAuthError(client, E_SERVER_ERROR, err.Error())
  }
  return code, nil
}

func (m *OauthManager) RedirectUrlWithCode(code *Token) (*url.URL, error) {
  uri, err := url.Parse(code.RedirectUri)
  if err != nil {
    client, _ := m.Storage.Client.Read(code.ClientId)
    return nil, NewAuthError(client, E_INVALID_REQUEST, "Invalid redirect uri")
  }
  q := uri.Query()
  q.Set("scope", code.Scope)
  q.Set("code", code.Value)
  uri.RawQuery = q.Encode()
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

  code, err := m.Storage.Code.Read(r.Form.Get("code"))
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
  _, err = m.Storage.Token.Insert(token)
  if err != nil {
    return nil, NewAuthError(client, E_SERVER_ERROR, err.Error())
  }
  return token, nil
}

func (m *OauthManager) ResponseWithToken(w http.ResponseWriter,
  token *Token) error {
  s := make(map[string]interface{})
  s["scope"] = token.Scope
  s["access_token"] = token.Value
  s["expires_in"] = token.Life
  o, err := json.Marshal(s)
  if err != nil {
    return err
  }
  w.Header().Set("Content-Type", "application/json;charset=UTF-8")
  w.Header().Set("Cache-Control", "no-store")
  w.Header().Set("Pragma", "no-cache")
  w.Write(o)
  return nil
}
