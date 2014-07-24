package oauth2

import (
  "testing"
)

const (
  kScope = "scope"
  kLife  = 10
)

func TestNewToken(t *testing.T) {
  token := NewToken(kClientId, kScope, kBaseUri, kLife)
  if token == nil {
    t.Error("Fail to create error")
  }

  if token.Value == "" {
    t.Error("Fail to generate token value")
  }

  if token.ClientId != kClientId {
    t.Errorf("Wrong client id: should be %s but get %s", kClientId,
      token.ClientId)
  }

  if token.Scope != kScope {
    t.Errorf("Wrong scope: should be %s but get %s", kScope,
      token.Scope)
  }

  if token.RedirectUri != kBaseUri {
    t.Errorf("Wrong redirect uri: should be %s but get %s", kBaseUri,
      token.RedirectUri)
  }

  if token.Life != kLife {
    t.Errorf("Wrong token life: should be %d but get %d", kLife,
      token.Life)
  }

  if token.UserData == nil {
    t.Error("Fail to map for user data")
  }
}
