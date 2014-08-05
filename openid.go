package openid

import (
	"github.com/epiggy001/go-openid/jwt"
	"github.com/epiggy001/go-openid/oauth2"
	"net/http"
	"time"
)

const (
	codeLife  = 60
	tokenLife = 60

	userKey = "_user_"
)

type Manager struct {
	om         *oauth2.Manager
	iss        string
	privateKey []byte
	alg        jwt.Algorithm
}

type UserToken oauth2.Token

func (t *UserToken) BelongTo() string {
	name, _ := t.UserData[userKey].(string)
	return name
}

func NewClassicManager(clientStore oauth2.ClientStore, iss string,
	key []byte) (*Manager, error) {
	storage := &oauth2.Storage{clientStore,
		oauth2.NewTokenStore(), oauth2.NewTokenStore(),
		oauth2.NewTokenStore()}

	om := &oauth2.Manager{
		CodeLife:       codeLife,
		TokenLife:      tokenLife,
		AllowGetMethod: true,

		Storage: storage,
		ClientAuthFunc: func(r *http.Request, c *oauth2.Client) bool {
			return c != nil
		}}

	alg, err := jwt.NewRsaAlg(key)
	if err != nil {
		return nil, err
	}
	return &Manager{om, iss, key, alg}, nil
}

func (m *Manager) ReadToken(tokenString string) (*UserToken, error) {
	token, err := m.om.Storage.Token.Read(tokenString)
	if err != nil {
		return nil, err
	}
	return (*UserToken)(token), nil
}

func (m *Manager) ReadCode(codeString string) (*oauth2.Token, error) {
	return m.om.Storage.Code.Read(codeString)
}

func (m *Manager) ReadClient(clientId string) (*oauth2.Client, error) {
	return m.om.Storage.Client.Read(clientId)
}

func (m *Manager) HandleCodeRequest(w http.ResponseWriter,
	r *http.Request, user string) error {
	code, err := m.om.GenerateCode(r)
	if err != nil {
		return err
	}
	code.UserData[userKey] = user
	url, err := m.om.RedirectUrlWithCode(code)
	if err != nil {
		return err
	}
	http.Redirect(w, r, url.String(), http.StatusFound)
	return m.om.SaveCode(code)
}

func (m *Manager) HandleTokenRequest(w http.ResponseWriter,
	r *http.Request) error {
	code, token, err := m.om.GenerateToken(r)
	if err != nil {
		return err
	}

	username := code.UserData[userKey]
	token.UserData[userKey] = username

	jtoken := jwt.New(m.alg)
	jtoken.Claims["iss"] = m.iss
	jtoken.Claims["sub"] = username
	jtoken.Claims["aud"] = token.ClientId
	jtoken.Claims["iat"] = time.Now().Unix()
	jtoken.Claims["exp"] = time.Now().Unix() + token.Life
	// Sign and get the complete encoded token as a string
	tokenString, err := jtoken.Sign()
	s := make(map[string]interface{})
	s["id_token"] = tokenString
	err = m.om.ResponseWithToken(w, token, s)
	if err != nil {
		err = m.om.ResponseWithError(w, err)
		return err
	}
	return m.om.SaveToken(token)
}
