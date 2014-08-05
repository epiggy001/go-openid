package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

type Algorithm interface {
	Sign(string) (string, error)
	Name() string
}

type JWT struct {
	Header struct {
		Typ     string `json:"typ"`
		AlgName string `json:"alg"`
	}
	Claims map[string]interface{}
	Alg    Algorithm
}

func New(alg Algorithm) *JWT {
	j := &JWT{}
	j.Header.Typ = "JWT"
	j.Header.AlgName = alg.Name()
	j.Claims = make(map[string]interface{})
	j.Alg = alg
	return j
}

func (j *JWT) Sign() (string, error) {
	parts := make([]string, 3)
	temp, err := json.Marshal(j.Header)
	if err != nil {
		return "", err
	}
	parts[0] = base64.URLEncoding.EncodeToString(temp)

	temp, err = json.Marshal(j.Claims)
	if err != nil {
		return "", err
	}
	parts[1] = base64.URLEncoding.EncodeToString(temp)

	parts[2], err = j.Alg.Sign(strings.Join(parts[:2], "."))
	if err != nil {
		return "", err
	}
	return strings.Join(parts, "."), nil
}
