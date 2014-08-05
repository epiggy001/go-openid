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

func EncodeToString(in []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(in), "=")
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
	parts[0] = EncodeToString(temp)

	temp, err = json.Marshal(j.Claims)
	if err != nil {
		return "", err
	}
	parts[1] = EncodeToString(temp)

	parts[2], err = j.Alg.Sign(strings.Join(parts[:2], "."))
	if err != nil {
		return "", err
	}
	return strings.Join(parts, "."), nil
}
