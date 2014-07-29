package oauth2

import (
  "encoding/json"
  "net/http"
  "net/url"
  "strings"
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

type Manager struct {
  CodeLife         int64
  TokenLife        int64
  RefreshTokenLife int64
  AllowGetMethod   bool

  Storage *Storage

  ClientAuthFunc func(r *http.Request, c *Client) bool
}

func (m *Manager) getClient(r *http.Request) (*Client, error) {
  clientId := r.Form.Get("client_id")
  client, err := m.Storage.Client.Read(clientId)
  if err != nil {
    return nil, NewAuthError(nil, E_SERVER_ERROR, err.Error())
  }

  if client == nil {
    return nil, NewAuthError(nil, E_UNAUTHORIZED_CLIENT,
      "Failed to read client")
  }

  return client, nil
}

func validateUri(base, uri string) bool {
  if base == "" || uri == "" {
    return false
  }

  // parse base url
  baseUri, err := url.Parse(base)
  if err != nil {
    return false
  }

  redirectUri, err := url.Parse(uri)
  if err != nil {
    return false
  }

  // must not have fragment
  if baseUri.Fragment != "" || redirectUri.Fragment != "" {
    return false
  }

  // check if urls match
  if baseUri.Scheme == redirectUri.Scheme && baseUri.Host == redirectUri.Host &&
    len(redirectUri.Path) >= len(baseUri.Path) &&
    strings.HasPrefix(redirectUri.Path, baseUri.Path) {
    return true
  }

  return false
}

func (m *Manager) GenerateCode(r *http.Request) (*Token, error) {
  err := r.ParseForm()
  if err != nil {
    return nil, NewAuthError(nil, E_INVALID_REQUEST, err.Error())
  }

  client, err := m.getClient(r)
  if err != nil {
    return nil, err
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
  return code, nil
}

func (m *Manager) SaveCode(code *Token) error {
  _, err := m.Storage.Code.Save(code)
  if err != nil {
    client, _ := m.Storage.Client.Read(code.ClientId)
    return NewAuthError(client, E_SERVER_ERROR, err.Error())
  }
  return nil
}

func (m *Manager) RedirectUrlWithCode(code *Token) (*url.URL, error) {
  uri, err := url.Parse(code.RedirectUri)
  if err != nil {
    client, _ := m.Storage.Client.Read(code.ClientId)
    return nil, NewAuthError(client, E_INVALID_REQUEST, "Invalid redirect uri")
  }
  q := uri.Query()
  q.Set("state", code.State)
  q.Set("code", code.Value)
  uri.RawQuery = q.Encode()
  return uri, nil
}

func (m *Manager) GenerateToken(r *http.Request) (*Token, *Token, error) {
  err := r.ParseForm()
  if err != nil {
    return nil, nil, NewAuthError(nil, E_INVALID_REQUEST, err.Error())
  }

  client, err := m.getClient(r)
  if err != nil {
    return nil, nil, err
  }

  if !m.ClientAuthFunc(r, client) {
    return nil, nil, NewAuthError(client, E_UNAUTHORIZED_CLIENT,
      "Failed to validate client")
  }

  if r.Method != "POST" && !m.AllowGetMethod {
    return nil, nil, NewAuthError(client, E_INVALID_REQUEST,
      "Invalid request method")
  }

  responseType := r.Form.Get("grant_type")
  if responseType != authorizationCode {
    return nil, nil, NewAuthError(client, E_UNSUPPORTED_GRANT_TYPE,
      "Only authorization code grant type is supported now")
  }

  code, err := m.Storage.Code.Read(r.Form.Get("code"))
  if err != nil {
    return nil, nil, NewAuthError(client, E_SERVER_ERROR, err.Error())
  }
  if code == nil {
    return nil, nil, NewAuthError(client, E_INVALID_GRANT, "Invalid code")
  }

  if code.ClientId != client.Id {
    return nil, nil, NewAuthError(client, E_INVALID_CLIENT, "Client is mismatch")
  }

  redirectUri := r.Form.Get("redirect_uri")
  if redirectUri == "" {
    redirectUri = client.BaseUri
  } else if !validateUri(client.BaseUri, redirectUri) {
    return nil, nil, NewAuthError(client, E_INVALID_REQUEST, "Invalid redirect uri")
  } else if code.RedirectUri != redirectUri {
    return nil, nil, NewAuthError(client, E_INVALID_REQUEST, "Invalid redirect uri")
  }

  token := NewToken(client.Id, code.Scope, redirectUri, m.TokenLife)
  return code, token, nil
}

func (m *Manager) SaveToken(token *Token) error {
  _, err := m.Storage.Token.Save(token)
  if err != nil {
    client, _ := m.Storage.Client.Read(token.ClientId)
    return NewAuthError(client, E_SERVER_ERROR, err.Error())
  }
  return nil
}

func (m *Manager) ResponseWithToken(w http.ResponseWriter,
  token *Token, userData map[string]interface{}) error {
  s := make(map[string]interface{})
  s["scope"] = token.Scope
  s["access_token"] = token.Value
  s["expires_in"] = token.Life
  for k, v := range userData {
    s[k] = v
  }
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

func (m *Manager) ResponseWithError(w http.ResponseWriter, err error) error {
  oerr, ok := err.(*AuthError)
  var errString string
  if ok {
    errString = oerr.ErrorString()
  } else {
    errString = err.Error()
  }
  s := make(map[string]interface{})
  s["error"] = errString
  o, err := json.Marshal(s)
  if err != nil {
    return err
  }
  w.WriteHeader(http.StatusBadRequest)
  w.Header().Set("Content-Type", "application/json;charset=UTF-8")
  w.Header().Set("Cache-Control", "no-store")
  w.Header().Set("Pragma", "no-cache")
  w.Write(o)
  return nil
}
