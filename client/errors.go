package client

import "errors"

var (
	ErrCertOutofDate   = errors.New("certificate out of date")
	ErrRequestFailed   = errors.New("request failed")
	ErrRequestTimeout  = errors.New("request timeout")
	ErrLogoutFailed    = errors.New("logout failed")
	ErrChangePwdFailed = errors.New("change pwd failed")
	ErrDecryptFailed   = errors.New("decrypt failed")
	ErrGetUserConfigFailed = errors.New("get user config failed")
	ErrResolvServerFailed = errors.New("resolv server ip failed")
	ErrExchangeCertFailed = errors.New("excange cert failed")
	ErrLoginFailed = errors.New("login failed")
)
