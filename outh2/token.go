package oauth2

type basicTokenData struct {
  Value       string
  ClientId    string
  Scope       string
  State       string
  RedirectUrl string
  CreatedAt   int32
  Duration    int32
  UserData    map[string]interface{}
}

type Code basicTokenData
type Token basicTokenData
type RefreshToken basicTokenData
