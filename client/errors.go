package client

import "errors"

var (
	ErrRequestTimeout  = errors.New("request timeout")
	ErrLogoutFailed    = errors.New("logout failed")
	ErrChangePwdFailed = errors.New("change pwd failed")
)
