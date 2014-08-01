package oauth2

import (
	"code.google.com/p/go-uuid/uuid"
	"encoding/base64"
	"time"
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
	token := uuid.New()
	return base64.StdEncoding.EncodeToString([]byte(token))
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
