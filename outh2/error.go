package oauth2

const (
  E_INVALID_REQUEST int = iota + 1
  E_UNAUTHORIZED_CLIENT
  E_ACCESS_DENIED
  E_UNSUPPORTED_RESPONSE_TYPE
  E_INVALID_SCOPE
  E_SERVER_ERROR
  E_TEMPORARILY_UNAVAILABLE
  E_UNSUPPORTED_GRANT_TYPE
  E_INVALID_GRANT
  E_INVALID_CLIENT
)

type authError struct {
  err    string
  client *Client
}

func (ae *authError) ErrorString() string {
  return ae.err
}

// Implements the error api
func (ae *authError) Error() string {
  // TODO: Add client info
  return ae.err
}

func NewAuthError(client *Client, n int) *authError {
  switch n {
  case E_INVALID_REQUEST:
    return &authError{"invalid_request", client}
  case E_UNAUTHORIZED_CLIENT:
    return &authError{"unauthorized_client", client}
  case E_ACCESS_DENIED:
    return &authError{"access_denied", client}
  case E_UNSUPPORTED_RESPONSE_TYPE:
    return &authError{"unsupported_response_type", client}
  case E_INVALID_SCOPE:
    return &authError{"invalid_scope", client}
  case E_SERVER_ERROR:
    return &authError{"server_error", client}
  case E_TEMPORARILY_UNAVAILABLE:
    return &authError{"temporarily_unavailable", client}
  case E_UNSUPPORTED_GRANT_TYPE:
    return &authError{"unsupported_grant_type", client}
  case E_INVALID_GRANT:
    return &authError{"invalid_grant", client}
  case E_INVALID_CLIENT:
    return &authError{"invalid_client", client}
  }

  return &authError{"unknown_error", client}
}
