package client

import "errors"

var (
	ErrCertOutofDate   = errors.New("certificate out of date")
	ErrRequestTimeout  = errors.New("request timeout")
	ErrLogoutFailed    = errors.New("logout failed")
	ErrChangePwdFailed = errors.New("change pwd failed")
)
