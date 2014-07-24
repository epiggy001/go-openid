package oauth2

import (
  "testing"
)

const (
  kClientId    = "id"
  kSecret      = "secret"
  kBaseUri     = "http://localhost"
  kDescription = "description"
)

func TestNewClient(t *testing.T) {
  c := NewClient(kClientId, kSecret, kBaseUri, kDescription)
  if c == nil {
    t.Error("Fail to create client")
  }

  if c.Id != kClientId {
    t.Errorf("Wrong id: should be %s but get %s", kClientId, c.Id)
  }

  if c.Secret != kSecret {
    t.Errorf("Wrong secret: should be %s but get %s", kSecret, c.Secret)
  }

  if c.BaseUri != kBaseUri {
    t.Errorf("Wrong uri: should be %s but get %s", kBaseUri, c.BaseUri)
  }

  if c.Description != kDescription {
    t.Errorf("Wrong uri: should be %s but get %s", kDescription, c.Description)
  }
}

func TestClientToString(t *testing.T) {
  c := NewClient(kClientId, kSecret, kBaseUri, kDescription)
  if c.String() != "client "+kClientId+" for "+kBaseUri {
    t.Error("Fail to stringify client")
  }
}
