package oauth2

import (
  "fmt"
)

const (
  E_INVALID_REQUEST int = iota
  E_UNAUTHORIZED_CLIENT
  E_ACCESS_DENIED
  E_UNSUPPORTED_RESPONSE_TYPE
  E_SERVER_ERROR
  E_TEMPORARILY_UNAVAILABLE
  E_INVALID_CLIENT
  E_INVALID_GRANT
  E_INVALID_SCOPE
  E_UNSUPPORTED_GRANT_TYPE
)

var (
  errMap = [...]string{
    "invalid_request",
    "unauthorized_client",
    "access_denied",
    "unsupported_response_type",
    "server_error",
    "temporarily_unavailable",
    "invalid_client",
    "invalid_grant",
    "invalid_scope",
    "unsupported_grant_type",
  }
)

type AuthError struct {
  code   int
  client *Client
  detail string
}

func (ae *AuthError) Code() int {
  return ae.code
}

func (ae *AuthError) ErrorString() string {
  return errMap[ae.code]
}

// Implements the error api
func (ae *AuthError) Error() string {
  if ae.client != nil {
    return fmt.Sprintf("%s has error: %s. Detail info: %s", ae.client,
      ae.ErrorString(), ae.detail)
  }

  return fmt.Sprintf("Error: %s. Detail info: %s", ae.ErrorString(), ae.detail)
}

func NewAuthError(client *Client, code int, detail string) *AuthError {
  return &AuthError{code, client, detail}
}
