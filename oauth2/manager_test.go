// Copyright 2013 Clustertech Limited. All rights reserved.
//
// Author: jackeychen (jackeychen@clustertech.com)
package oauth2

import (
  "encoding/json"
  "errors"
  "net/http"
  "net/http/httptest"
  "strings"
  "testing"
)

const (
  kServerUrl   = "http://localhost"
  kRedirectUri = "http://localhost/info"
)

func newMockManager() *Manager {
  clientStore := NewMockClientStore()
  c := NewClient(kClientId, kSecret, kBaseUri, "")

  storage := &Storage{clientStore,
    NewTokenStore(), NewTokenStore(),
    NewTokenStore()}

  m := &Manager{
    CodeLife:       kLife,
    TokenLife:      kLife,
    AllowGetMethod: true,

    Storage: storage,
    ClientAuthFunc: func(r *http.Request, c *Client) bool {
      return c.Id == kClientId && r.URL.Query().Get("secret") == kSecret
    }}

  clientStore.Save(c)
  return m
}

func newMockCodeRequest(query map[string]string) *http.Request {
  r, _ := http.NewRequest("GET", kServerUrl, nil)
  q := r.URL.Query()
  q.Set("client_id", kClientId)
  q.Set("response_type", "code")
  q.Set("redirect_uri", kRedirectUri)
  q.Set("scope", kScope)
  if query != nil {
    for k, v := range query {
      q.Set(k, v)
    }
  }
  r.URL.RawQuery = q.Encode()
  return r
}

func TestGenerateCodeWithFakeClilent(t *testing.T) {
  m := newMockManager()
  q := make(map[string]string)
  q["client_id"] = "fake_id"
  r := newMockCodeRequest(q)
  _, err := m.GenerateCode(r)
  if err == nil {
    t.Error("Fail to validate request with a fake id")
  }

  if err.(*AuthError).Code() != E_UNAUTHORIZED_CLIENT {
    t.Error("Wrong error type for fake id")
  }
}

func TestGenerateCodeWithInvalidResponseType(t *testing.T) {
  m := newMockManager()
  q := make(map[string]string)
  q["response_type"] = "fake_type"
  r := newMockCodeRequest(q)
  _, err := m.GenerateCode(r)
  if err == nil {
    t.Error("Fail to validate request with a invalid response type")
  }

  if err.(*AuthError).Code() != E_UNSUPPORTED_RESPONSE_TYPE {
    t.Error("Wrong error type for invalid response type")
  }
}

func TestGenerateCodeWithInvalidUri(t *testing.T) {
  m := newMockManager()
  q := make(map[string]string)
  q["redirect_uri"] = "http://mockhost/info"
  r := newMockCodeRequest(q)
  _, err := m.GenerateCode(r)
  if err == nil {
    t.Error("Fail to validate request with a invalid uri")
  }

  if err.(*AuthError).Code() != E_INVALID_REQUEST {
    t.Error("Wrong error type for invalid uri")
  }
}

func TestGenerateCode(t *testing.T) {
  m := newMockManager()
  r := newMockCodeRequest(nil)
  code, err := m.GenerateCode(r)
  if err != nil {
    t.Error("Fail to generate token for a valid request")
  }

  if code.Life != kLife {
    t.Errorf("Wrong code life: should be %d but get %d", kLife, code.Life)
  }

  if code.ClientId != kClientId {
    t.Errorf("Wrong client id: should be %s but get %s", kClientId,
      code.ClientId)
  }

  if code.RedirectUri != kRedirectUri {
    t.Errorf("Wrong redirect uri:  should be %s but get %s", kRedirectUri,
      code.RedirectUri)
  }

  if code.Scope != kScope {
    t.Errorf("Wrong scope: should be %d but get %d", kScope, code.Scope)
  }
}

func TestRedirectUrlWithCode(t *testing.T) {
  m := newMockManager()
  r := newMockCodeRequest(nil)
  code, _ := m.GenerateCode(r)
  url, err := m.RedirectUrlWithCode(code)
  if err != nil {
    t.Error("Fail to generate redirect url with a given code")
  }

  if !strings.HasPrefix(url.String(), code.RedirectUri) {
    t.Error("Wrong redirect uri")
  }

  if url.Query().Get("code") != code.Value {
    t.Error("Wrong code value")
  }

  if url.Query().Get("state") != code.State {
    t.Error("Wrong code state")
  }
}

func newMockTokenRequest(query map[string]string) *http.Request {
  r, _ := http.NewRequest("GET", kServerUrl, nil)
  q := r.URL.Query()
  q.Set("client_id", kClientId)
  q.Set("grant_type", authorizationCode)
  q.Set("redirect_uri", kRedirectUri)
  q.Set("secret", kSecret)
  if query != nil {
    for k, v := range query {
      q.Set(k, v)
    }
  }
  r.URL.RawQuery = q.Encode()
  return r
}

func TestGenerateTokenWithFakeClient(t *testing.T) {
  m := newMockManager()
  code := NewToken(kClientId, kScope, kRedirectUri, kLife)
  m.SaveCode(code)
  q := make(map[string]string)
  q["client_id"] = "fake_id"
  r := newMockTokenRequest(q)
  _, _, err := m.GenerateToken(r)
  if err == nil {
    t.Error("Fail to validate request with a fake id")
  }

  if err.(*AuthError).Code() != E_UNAUTHORIZED_CLIENT {
    t.Error("Wrong error type for fake id")
  }

  q = make(map[string]string)
  q["secret"] = "fake_secret"
  r = newMockTokenRequest(q)
  _, _, err = m.GenerateToken(r)
  if err == nil {
    t.Error("Fail to validate request with a wrong secret")
  }

  if err.(*AuthError).Code() != E_UNAUTHORIZED_CLIENT {
    t.Error("Wrong error type for a wrong secret")
  }
}

func TestGenerateTokenWithInvalidGrantType(t *testing.T) {
  m := newMockManager()
  code := NewToken(kClientId, kScope, kRedirectUri, kLife)
  m.SaveCode(code)
  q := make(map[string]string)
  q["grant_type"] = "code"
  r := newMockTokenRequest(q)
  _, _, err := m.GenerateToken(r)
  if err == nil {
    t.Error("Fail to validate request with a invalid grant type")
  }

  if err.(*AuthError).Code() != E_UNSUPPORTED_GRANT_TYPE {
    t.Error("Wrong error type for invalid grant type")
  }
}

func TestGenerateTokenWithInvalidCode(t *testing.T) {
  m := newMockManager()
  code := NewToken(kClientId, kScope, kRedirectUri, kLife)
  m.SaveCode(code)
  q := make(map[string]string)
  q["code"] = "fake_code"
  r := newMockTokenRequest(q)
  _, _, err := m.GenerateToken(r)
  if err == nil {
    t.Error("Fail to validate request with a invalid code")
  }

  if err.(*AuthError).Code() != E_INVALID_GRANT {
    t.Error("Wrong error type for invalid code")
  }

  c := NewClient("second", kSecret, kBaseUri, "")
  m.Storage.Client.Save(c)
  code = NewToken("second", kScope, kRedirectUri, kLife)
  m.SaveCode(code)
  q = make(map[string]string)
  q["code"] = code.Value
  r = newMockTokenRequest(q)
  _, _, err = m.GenerateToken(r)
  if err == nil {
    t.Error("Fail to validate request with mismatch client id and code value")
  }

  if err.(*AuthError).Code() != E_INVALID_CLIENT {
    t.Error("Wrong error type for client id and code value mismatching")
  }
}

func TestTokenGenerateWithInvalidRedirectUri(t *testing.T) {
  m := newMockManager()
  code := NewToken(kClientId, kScope, kRedirectUri, kLife)
  m.SaveCode(code)
  q := make(map[string]string)
  q["code"] = code.Value
  q["redirect_uri"] = "http://mockhost/info"
  r := newMockTokenRequest(q)
  _, _, err := m.GenerateToken(r)
  if err == nil {
    t.Error("Fail to validate request with a invalid uri")
  }

  if err.(*AuthError).Code() != E_INVALID_REQUEST {
    t.Error("Wrong error type for invalid uri")
  }
}

func TestTokenGenerate(t *testing.T) {
  m := newMockManager()
  code := NewToken(kClientId, kScope, kRedirectUri, kLife)
  m.SaveCode(code)
  q := make(map[string]string)
  q["code"] = code.Value
  r := newMockTokenRequest(q)
  c, token, err := m.GenerateToken(r)
  if err != nil {
    t.Error("Fail to generate token")
  }

  if c.Value != code.Value {
    t.Error("Fail to return the code")
  }

  if token.ClientId != kClientId {
    t.Error("Wrong client id")
  }

  if token.Life != kLife {
    t.Error("Wrong token life")
  }

  if token.Scope != kScope {
    t.Error("Wrong scope")
  }

  if token.RedirectUri != kRedirectUri {
    t.Error("Wrong redirect uri")
  }
}

func TestResponseWithToken(t *testing.T) {
  w := httptest.NewRecorder()
  token := NewToken(kClientId, kScope, kRedirectUri, kLife)
  m := newMockManager()
  data := make(map[string]interface{})
  data["c"] = "data"
  err := m.ResponseWithToken(w, token, data)
  if err != nil {
    t.Error("Fail to repsone a token")
  }

  out := make(map[string]interface{})
  err = json.Unmarshal(w.Body.Bytes(), &out)
  if err != nil {
    t.Error("Fail to read response")
  }

  if out["scope"].(string) != kScope {
    t.Error("Response wrong scope value")
  }

  if out["access_token"].(string) != token.Value {
    t.Error("Response wrong token value")
  }

  if out["expires_in"].(float64) != kLife {
    t.Error("Response wrong token life")
  }

  if out["c"].(string) != "data" {
    t.Error("Response wrong customized reponse data")
  }
}

func TestResponseWithError(t *testing.T) {
  w := httptest.NewRecorder()
  m := newMockManager()
  errMsg := "error"
  myError := errors.New(errMsg)
  err := m.ResponseWithError(w, myError)
  if err != nil {
    t.Error("Fail to repsone an error")
  }

  out := make(map[string]interface{})
  err = json.Unmarshal(w.Body.Bytes(), &out)
  if err != nil {
    t.Error("Fail to read error response")
  }

  if out["error"].(string) != errMsg {
    t.Error("Return wrong error msg for simple error")
  }

  myAuthError := NewAuthError(nil, E_ACCESS_DENIED, "")
  w = httptest.NewRecorder()
  err = m.ResponseWithError(w, myAuthError)
  if err != nil {
    t.Error("Fail to repsone an AuthError")
  }

  out = make(map[string]interface{})
  err = json.Unmarshal(w.Body.Bytes(), &out)
  if err != nil {
    t.Error("Fail to read AuthError response")
  }

  if out["error"].(string) != myAuthError.ErrorString() {
    t.Error("Return wrong error msg for AuthError")
  }
}
