package main

// Use code.google.com/p/goauth2/oauth client to test
// Open url in browser:
// http://localhost:14000/app

import (
	"code.google.com/p/goauth2/oauth"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"io"
	"net/http"
)

const (
	myKey = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41
fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7
mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBp
HssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2
XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3b
ODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy
7wIDAQAB
-----END PUBLIC KEY-----`
)

func main() {
	client := &oauth.Config{
		ClientId:     "1234",
		ClientSecret: "aabbccdd",
		RedirectURL:  "http://localhost:14000/info",
		AuthURL:      "http://localhost:14001/authorize",
		TokenURL:     "http://localhost:14001/token",
	}

	ctransport := &oauth.Transport{Config: client}

	// Application home endpoint
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>"))
		w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Login</a>", client.AuthCodeURL(""))))
		w.Write([]byte("</body></html>"))
	})

	// Application destination - CODE
	http.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		code := r.Form.Get("code")

		w.Write([]byte("<html><body>"))

		if code != "" {
			var jr *oauth.Token
			var err error
			jr, err = ctransport.Exchange(code)
			if err != nil {
				jr = nil
				w.Write([]byte(fmt.Sprintf("ERROR: %s<br/>\n", err)))
			}

			if jr != nil {
				tokenString := jr.Extra["id_token"]
				token, err := jwt.Parse(tokenString, func(token *jwt.Token) ([]byte, error) {
					return []byte(myKey), nil
				})
				if err != nil {
					fmt.Println(err)
					return
				}
				// TODO: Add jwt checking
				if token.Valid {
					resp, err := ctransport.Client().Get("http://localhost:14001/userinfo?token=" + jr.AccessToken)
					if err != nil {
						fmt.Println(err)
						return
					}
					io.Copy(w, resp.Body)
					return
				}
			} else {
				w.Write([]byte("No token"))
			}

		} else {
			w.Write([]byte("Nothing to do"))
		}

		w.Write([]byte("</body></html>"))
	})

	http.ListenAndServe(":14000", nil)
}
