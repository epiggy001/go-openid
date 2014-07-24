package oauth2

import (
  "testing"
)

const (
  kErrorDetail = "Error detail"
)

func TestNewAuthError(t *testing.T) {
  c := NewClient(kClientId, kSecret, kBaseUri, kDescription)
  err := NewAuthError(c, E_INVALID_GRANT, kErrorDetail)
  if err == nil {
    t.Error("Fail to create AuthError")
  }

  if err.Code() != E_INVALID_GRANT {
    t.Errorf("Wrong code: should be %d but get %d", E_INVALID_GRANT, err.Code())
  }

  if err.ErrorString() != errMap[E_INVALID_GRANT] {
    t.Errorf("Wrong error string: should be %s but get %s",
      errMap[E_INVALID_GRANT], err.ErrorString())
  }
}

func TestErrorInterface(t *testing.T) {
  err := NewAuthError(nil, E_INVALID_GRANT, kErrorDetail)
  if err.Error() != "Error: "+err.ErrorString()+". Detail info: "+
    kErrorDetail {
    t.Error("Fail to generate error info when client is nil")
  }

  c := NewClient(kClientId, kSecret, kBaseUri, kDescription)
  err = NewAuthError(c, E_INVALID_GRANT, kErrorDetail)
  if err.Error() != c.String()+" has error: "+err.ErrorString()+
    ". Detail info: "+kErrorDetail {
    t.Error("Fail to generate error info when client is not nil")
  }
}
