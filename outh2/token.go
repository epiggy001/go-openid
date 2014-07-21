package oauth2

import (
  "code.google.com/p/go-uuid/uuid"
  "encoding/base64"
  "time"
)

type BasicTokenData struct {
  Value       string
  ClientId    string
  Scope       string
  State       string
  RedirectUri string
  CreatedAt   int64
  Life        int64
  UserData    map[string]interface{}
}

func generateToken() string {
  token := uuid.New()
  return base64.StdEncoding.EncodeToString([]byte(token))
}

func NewBasicTokenData(clientId, scope, uri string,
  life int64) *BasicTokenData {
  return &BasicTokenData{
    Value:       generateToken(),
    ClientId:    clientId,
    Scope:       scope,
    RedirectUri: uri,
    CreatedAt:   time.Now().Unix(),
    Life:        life,
    UserData:    make(map[string]interface{})}
}

func (t *BasicTokenData) IsExpire() bool {
  return time.Now().Unix() > t.CreatedAt+t.Life
}

type Code struct {
  *BasicTokenData
}

type Token struct {
  *BasicTokenData
}

type RefreshToken struct {
  *BasicTokenData
}

func NewCode(clientId, scope, uri string, life int64) *Code {
  return &Code{NewBasicTokenData(clientId, scope, uri, life)}
}

func NewToken(clientId, scope, uri string, life int64) *Token {
  return &Token{NewBasicTokenData(clientId, scope, uri, life)}
}

func NewRefreshToken(clientId, scope, uri string, life int64) *RefreshToken {
  return &RefreshToken{NewBasicTokenData(clientId, scope, uri, life)}
}
