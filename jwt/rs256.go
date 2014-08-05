// Copyright 2014 Clustertech Limited. All rights reserved.
//
// Author: jackeychen (jackeychen@clustertech.com)
package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

type RsaAlg struct {
	key *rsa.PrivateKey
}

func NewRsaAlg(input []byte) (*RsaAlg, error) {
	block, _ := pem.Decode(input)
	var key *rsa.PrivateKey
	var err error
	var ok bool
	if key, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		temp, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key, ok = temp.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("Fail to parse private key")
		}
	}
	return &RsaAlg{key}, nil
}

func (alg *RsaAlg) Sign(input string) (string, error) {
	hasher := sha256.New()
	hasher.Write([]byte(input))
	signed, err := rsa.SignPKCS1v15(rand.Reader, alg.key, crypto.SHA256, hasher.Sum(nil))
	if err != nil {
		return "", err
	}
	return EncodeToString(signed), nil
}

func (alg *RsaAlg) Name() string {
	return "RS256"
}
