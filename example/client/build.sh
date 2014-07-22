#!/bin/bash
export GOPATH=`pwd`
go get code.google.com/p/goauth2/oauth
go get github.com/dgrijalva/jwt-go
go build
