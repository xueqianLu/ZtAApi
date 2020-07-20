package client

import (
	"encoding/json"
	. "github.com/xueqianLu/ZtAApi/common"
)

type InvalidPacket interface {
	Valid() bool
	Bytes() []byte
}

type AdminLoginReqPacket struct {
	PwdHash string `json:"pwdhash"`
}

func (l AdminLoginReqPacket) Valid() bool {
	return true //l.Type == int(AdminLoginRequest)
}

func (l AdminLoginReqPacket) Bytes() []byte {
	bs := make([]byte, 0)

	return bs
}

type LoginReqPacket struct {
	MachineInfo SystemInfo `json:"system_info"`
	DeviceID    string     `json:"device_id"`
	Pubkey      string     `json:"pubkey"`
	PwdHash     string     `json:"pwdhash"`
}

func (l LoginReqPacket) Valid() bool {
	if (len(l.DeviceID) != 64) || (len(l.Pubkey) != 44) {
		return false
	}
	return true
}

func (l LoginReqPacket) Bytes() []byte {
	bs, err := json.Marshal(l)
	if err != nil {
		return nil
	}

	return bs
}

type ChangePwdPacket struct {
	OldPwdHash string `json:"oldpwdhash"`
	Passwd     string `json:"passwd"`
}

func (c ChangePwdPacket) Valid() bool {
	return true
}

func (c ChangePwdPacket) Bytes() []byte {
	bs, err := json.Marshal(c)
	if err != nil {
		return nil
	}

	return bs
}

type LogoutPacket struct {
	PwdHash string `json:"pwdhash"`
	Pubkey  string `json:"pubkey"`
}

func (p LogoutPacket) Valid() bool {
	return true
}

func (p LogoutPacket) Bytes() []byte {
	bs, err := json.Marshal(p)
	if err != nil {
		return nil
	}

	return bs
}

type ExchangeCertPacket struct {
	Csrdata   string `json:"csrdata"`
	Timestamp int64  `json:"timestamp"`
}

func (p ExchangeCertPacket) Valid() bool {
	return true
}

func (p ExchangeCertPacket) Bytes() []byte {
	bs, err := json.Marshal(p)
	if err != nil {
		return nil
	}

	return bs
}

//server response header
type ServerResponse struct {
	Type   int    `json:"cmd"`
	Status int    `json:"status"` // 1: success.
	Msg    string `json:"msg"`
}

type LoginResponse struct {
	LoginResData `json:"data"`
}

type LoginResData struct {
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
	AdminLoginResData `json:"data"`
}

type AdminLoginResData struct {
	Url string `json:"url"`
}

func (p AdminLoginResponse) String() string {
	b, _ := json.Marshal(p)
	return string(b)
}

type ExchangeCertResponse struct {
	CertResData `json:"data"`
}

type CertResData struct {
	ManagerCert string `json:"ManagerCert"`
	ClientCert  string `json:"ClientCert"`
}

func (p ExchangeCertResponse) String() string {
	b, _ := json.Marshal(p)
	return string(b)
}
