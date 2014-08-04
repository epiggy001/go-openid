package oauth2

import (
	"encoding/base64"
	"time"
	"crypto/rand"
  "io"
)

type Token struct {
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
  token := make([]byte, 16)
  if _, err := io.ReadFull(rand.Reader, token); err != nil {
    panic(err.Error())
  }
	return base64.StdEncoding.EncodeToString(token)
}

func NewToken(clientId, scope, uri string,
	life int64) *Token {
	return &Token{
		Value:       generateToken(),
		ClientId:    clientId,
		Scope:       scope,
		RedirectUri: uri,
		CreatedAt:   time.Now().Unix(),
		Life:        life,
		UserData:    make(map[string]interface{})}
}
