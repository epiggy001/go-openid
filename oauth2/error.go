package oauth2

import (
  "fmt"
)

const (
  E_INVALID_REQUEST int = iota + 1
  E_UNAUTHORIZED_CLIENT
  E_ACCESS_DENIED
  E_UNSUPPORTED_RESPONSE_TYPE
  E_INVALID_SCOPE
  E_SERVER_ERROR
  E_TEMPORARILY_UNAVAILABLE
)

type authError struct {
  err    string
  client *Client
  detail string
}

func (ae *authError) ErrorString() string {
  return ae.err
}

// Implements the error api
func (ae *authError) Error() string {
  if ae.client != nil {
    return fmt.Sprintf("%s has error: %s. Detail info: %s", ae.client, ae.err,
      ae.detail)
  }

  return fmt.Sprintf("Error: %s. Detail info: %s", ae.err, ae.detail)
}

func NewAuthError(client *Client, n int, detail string) *authError {
  switch n {
  case E_INVALID_REQUEST:
    return &authError{"invalid_request", client, detail}
  case E_UNAUTHORIZED_CLIENT:
    return &authError{"unauthorized_client", client, detail}
  case E_ACCESS_DENIED:
    return &authError{"access_denied", client, detail}
  case E_UNSUPPORTED_RESPONSE_TYPE:
    return &authError{"unsupported_response_type", client, detail}
  case E_INVALID_SCOPE:
    return &authError{"invalid_scope", client, detail}
  case E_SERVER_ERROR:
    return &authError{"server_error", client, detail}
  case E_TEMPORARILY_UNAVAILABLE:
    return &authError{"temporarily_unavailable", client, detail}
  }

  return &authError{"unknown_error", client, detail}
}
