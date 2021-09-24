#!/bin/bash 
#go build -buildmode=c-archive -o libsm2crypto.a crypto.go interface.go
go build -buildmode=c-shared -o libsm2crypto.so crypto.go interface.go loginapi.go
