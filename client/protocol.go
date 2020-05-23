package client

import "encoding/json"

type ServerResponse struct {
	Type   int    `json:"cmd"`
	Status int    `json:"status"` // 1: success.
	Msg    string `json:"msg"`
}

type LoginResponse struct {
	LoginData `json:"data"`
}

type LoginData struct {
	UserId       string   `json:"usrID"`
	IP           string   `json:"client_ip"`
	GWPubkey     string   `json:"gateway_connection_pubkey"`
	EndPoint     string   `json:"gateway_endpoint"`
	ServerNumber uint32   `json:"server_num"`
	ServerList   []string `json:"server"`
	LifeTime     int      `json:"lifetime"` // unit minutes
}

func (p LoginResponse) String() string {
	b, _ := json.Marshal(p)
	return string(b)
}

type AdminLoginResponse struct {
	AdminLoginData `json:"data"`
}

type AdminLoginData struct {
	Url string `json:"url"`
}

func (p AdminLoginResponse) String() string {
	b, _ := json.Marshal(p)
	return string(b)
}
