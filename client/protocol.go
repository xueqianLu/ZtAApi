package client

import (
	"encoding/json"
	. "github.com/xueqianLu/ZtAApi/common"
	"github.com/xueqianLu/ZtAApi/conf"
	"strings"
)

type InvalidPacket interface {
	Valid() bool
	Bytes() []byte
}

type AdminLoginReqPacket struct {
	//Type      int    `json:"type"`
	PwdHash     string     `json:"pwdhash"`
	Timestamp   int64      `json:"timestamp"`
	DeviceID    string     `json:"device_id"`
	Username    string     `json:"username"`
	Passwd      string     `json:"passwd"`
	VerifyCode  string     `json:"verify_code"`
	GetUrl      bool       `json:"get_url"`
	MachineInfo SystemInfo `json:"system_info"`
}

func (l AdminLoginReqPacket) Valid() bool {
	return true //l.Type == int(AdminLoginRequest)
}

func (l AdminLoginReqPacket) Bytes() []byte {
	bs, err := json.Marshal(l)
	if err != nil {
		return nil
	}

	return bs
}

type LoginReqPacket struct {
	//Type        int        `json:"type"`
	DeviceID         string     `json:"device_id"`
	Pubkey           string     `json:"pubkey"`
	PwdHash          string     `json:"pwdhash"`
	Timestamp        int64      `json:"timestamp"`
	Username         string     `json:"username"`
	Passwd           string     `json:"passwd"`
	VerifyCode       string     `json:"verify_code"`
	SecondVerifyCode string     `json:"second_verifyCode"`
	MachineInfo      SystemInfo `json:"system_info"`
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
	//Type       int    `json:"type"`
	OldPwdHash string `json:"oldpwdhash"`
	NewPasswd  string `json:"newpasswd"`
	Timestamp  int64  `json:"timestamp"`
	Username   string `json:"username"`
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

type ReGetVerifyCodePacket struct {
	//Type       int    `json:"type"`
	Timestamp   int64      `json:"timestamp"`
	Username    string     `json:"username"`
	Passwd      string     `json:"passwd"`
	MachineInfo SystemInfo `json:"system_info"`
}

func (c ReGetVerifyCodePacket) Valid() bool {
	return true
}

func (c ReGetVerifyCodePacket) Bytes() []byte {
	bs, err := json.Marshal(c)
	if err != nil {
		return nil
	}

	return bs
}

type LogoutPacket struct {
	//Type      int    `json:"type"`
	PwdHash   string `json:"pwdhash"`
	Pubkey    string `json:"pubkey"`
	Timestamp int64  `json:"timestamp"`
	Username  string `json:"username"`
	Passwd    string `json:"passwd"`
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
	Username    string     `json:"username"`
	Passwd      string     `json:"passwd"`
	Csrdata     string     `json:"csrdata"`
	Timestamp   int64      `json:"timestamp"`
	MachineInfo SystemInfo `json:"system_info"`
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

type SliceInfoReqPacket struct {
	//Type       int    `json:"type"`
	SliceOffset int    `json:"slice_offset"`
	Timestamp   int64  `json:"timestamp"`
	Username    string `json:"username"`
	Passwd      string `json:"passwd"`
}

func (c SliceInfoReqPacket) Valid() bool {
	return true
}

func (c SliceInfoReqPacket) Bytes() []byte {
	bs, err := json.Marshal(c)
	if err != nil {
		return nil
	}

	return bs
}

type UserHomeReqPacket struct {
	//Type      int    `json:"type"`
	Timestamp int64  `json:"timestamp"`
	Username  string `json:"username"`
	Passwd    string `json:"passwd"`
}

func (p UserHomeReqPacket) Valid() bool {
	return true
}

func (p UserHomeReqPacket) Bytes() []byte {
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
	SliceCount  int    `json:"slice_count"`
	SliceOffset int    `json:"slice_offset"`
	SliceInfo   string `json:"info"`
	VerifyType  string `json:"verify_type"`
}

func (p LoginResponse) String() string {
	b, _ := json.Marshal(p)
	return string(b)
}

type AdminLoginResponse struct {
	AdminLoginResData `json:"data"`
}

type AdminLoginResData struct {
	Url         string `json:"url"`
	AccountType string `json:"account_type"`
	VerifyType  string `json:"verify_type"`
}

func (p AdminLoginResponse) String() string {
	b, _ := json.Marshal(p)
	return string(b)
}

type SliceInfoResData struct {
	SliceCount  int    `json:"slice_count"`
	SliceOffset int    `json:"slice_offset"`
	SliceInfo   string `json:"info"`
}

type UserInfoResponse struct {
	SliceInfoResData `json:"data"`
}

func (p UserInfoResponse) String() string {
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

func ParseHostsInfo(hosts []conf.HostInfo) map[string]*DomainList {
	hostinfo := make(map[string]*DomainList)
	for _, host := range hosts {
		section := strings.Split(host.Domain, " ")
		ip := host.IP
		domainlist := hostinfo[ip]
		for _, s := range section {
			//log.Println(strings.TrimSpace(ip),"--->", strings.TrimSpace(s))
			domain := strings.TrimSpace(s)
			if domainlist == nil {
				domainlist = NewDomainList(domain)
				hostinfo[ip] = domainlist
			} else {
				domainlist.Add(domain)
			}
		}
	}
	return hostinfo
}

type UserHomeResponse struct {
	UserHomeResData `json:"data"`
}

type UserHomeResData struct {
	Url string `json:"url"`
}

func (p UserHomeResData) String() string {
	b, _ := json.Marshal(p)
	return string(b)
}
