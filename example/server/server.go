package main

// Use code.google.com/p/goauth2/oauth client to test
// Open url in browser:
// http://localhost:14000/app

import (
  "encoding/json"
  "github.com/dgrijalva/jwt-go"
  "net/http"
  "github.com/epiggy001/go-openid/oauth2"
  "time"
)

const (
  myKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtn
SgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0i
cqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhC
PUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsAR
ap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKA
Rdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3
n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAy
MaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9
POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdE
KdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gM
IvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDn
FcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvY
mEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghj
FuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+U
I5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs
2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn
/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNT
OvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86
EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+
hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL0
4aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0Kcnckb
mDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ry
eBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3
CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+
9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq
-----END RSA PRIVATE KEY-----`
)

func main() {
  clientStore := oauth2.NewMockClientStore()
  c := oauth2.NewClient("1234", "aabbccdd",
    "http://localhost:14000/info", "")
  clientStore.Insert(c)
  storage := &oauth2.Storage{clientStore,
    oauth2.NewMockTokenStore(), oauth2.NewMockTokenStore(),
    oauth2.NewMockTokenStore()}

  au := oauth2.OauthManager{
    CodeLife:       120,
    TokenLife:      120,
    AllowGetMethod: true,

    Storage: storage,
    ClientAuthFunc: func(r *http.Request, c *oauth2.Client) bool {
      return true
    }}

  // UserInfo endpoint
  http.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
    r.ParseForm()
    tokenString := r.Form.Get("token")
    token, _ := au.Storage.Token.Read(tokenString)
    if token != nil {
      info := make(map[string]interface{})
      info["username"] = token.UserData["username"]
      o, _ := json.Marshal(info)
      w.Write(o)
    }
  })

  // Authorization code endpoint
  http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
    r.ParseForm()
    username := r.Form.Get("username")
    password := r.Form.Get("password")
    if username != "user" || password != "123456" {
      w.Write([]byte("Fial to login"))
      return
    }
    code, err := au.GenerateCode(r)
    if err != nil {
      w.Write([]byte(err.Error()))
      return
    }
    code.UserData["username"] = username
    au.SaveCode(code)
    url, err := au.RedirectUrlWithCode(code)
    if err != nil {
      w.Write([]byte(err.Error()))
      return
    }
    http.Redirect(w, r, url.String(), http.StatusFound)
  })

  // Access token endpoint
  http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
    code, token, err := au.GenerateToken(r)
    if err != nil {
      w.Write([]byte(err.Error()))
      return
    }

    username := code.UserData["username"]
    token.UserData["username"] = username

    jtoken := jwt.New(jwt.GetSigningMethod("RS256"))
    jtoken.Claims["iss"] = "https://localshot:14001"
    jtoken.Claims["sub"] = username
    jtoken.Claims["aud"] = token.ClientId
    jtoken.Claims["iat"] = time.Now().Unix()
    jtoken.Claims["exp"] = time.Now().Add(time.Minute * 2).Unix()
    // Sign and get the complete encoded token as a string
    tokenString, err := jtoken.SignedString([]byte(myKey))
    au.SaveToken(token)
    s := make(map[string]interface{})
    s["id_token"] = tokenString
    err = au.ResponseWithToken(w, token, s)
    if err != nil {
      w.Write([]byte(err.Error()))
      return
    }
  })

  http.ListenAndServe(":14001", nil)
}
