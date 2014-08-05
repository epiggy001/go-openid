package jwt

import (
	"testing"
)

const kGoldenSignedString = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJqb2UifQ.HS256_SIG"

type mockAlg int

func (alg *mockAlg) Name() string {
	return "HS256"
}

func (alg *mockAlg) Sign(input string) (string, error) {
	return "HS256_SIG", nil
}

func TestNewJWT(t *testing.T) {
	alg := new(mockAlg)
	j := New(alg)
	if j == nil {
		t.Error("Fail to create a jwt")
	}

	if j.Header.Typ != "JWT" {
		t.Error("Fail to set type of header")
	}

	if j.Header.AlgName != "HS256" {
		t.Error("Fail to set alg of header")
	}

	if j.Claims == nil {
		t.Error("Fail to init claims")
	}

	if j.Alg != alg {
		t.Error("Fail to set algorithm")
	}
}

func TestSignJWT(t *testing.T) {
	alg := new(mockAlg)
	j := New(alg)
	j.Claims["iss"] = "joe"
	j.Claims["exp"] = 1300819380
	j.Claims["http://example.com/is_root"] = true
	str, err := j.Sign()
	if err != nil {
		t.Errorf("Fail to sign a jwt: %s", err)
	}
	if str != kGoldenSignedString {
		t.Errorf("Get a wrong signed string")
	}
}
