#!/bin/bash
export GOPATH=`pwd`
go get github.com/epiggy001/go-openid/oauth2
go get github.com/dgrijalva/jwt-go
go build
