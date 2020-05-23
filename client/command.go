package client

import (
	"bytes"
	"encoding/json"
	"errors"
	. "github.com/xueqianLu/ZtAApi/common"
	"log"
)

const (
	ClientID               = "AZEROTRUSTNETWORKACCESSTOANYONEL"
	LoginRequestMsg   byte = 0x01
	LoginResponMsg    byte = 0x02
	ChangePwdMsg      byte = 0x03
	LogoutRequestMsg  byte = 0x04
	AdminLoginRequest byte = 0x05
)

type Packet struct {
	Ptype   byte // used to set cmdtype.
	Payload []byte
}

func (p Packet) Bytes() []byte {
	bsb := bytes.NewBuffer([]byte{})
	bsb.Write(p.Payload)
	return bsb.Bytes()
}

type AdminLoginReqPacket struct {
	//Type     int    `json:"type"`
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
	Passwd string `json:"passwd"`
}

func (c ChangePwdPacket) Bytes() []byte {
	bs, err := json.Marshal(c)
	if err != nil {
		return nil
	}

	return bs
}

type LogoutPacket struct {
	Pubkey string `json:"pubkey"`
}

func (p LogoutPacket) Bytes() []byte {
	bs, err := json.Marshal(p)
	if err != nil {
		return nil
	}

	return bs
}

type Cmd struct {
	CmdType   byte
	CheckVal  Hash
	UserIndex Hash
	Random    Hash
	EncPacket []byte
	HMAC      Hash
}

func (l *Cmd) GenHMAC(key []byte) {
	s := make([]byte, 1)
	s[0] = l.CmdType

	data := BytesCombine(s, l.CheckVal[:], l.UserIndex[:], l.Random[:], l.EncPacket[:])
	//log.Println("GenHMAC:checkval=", hex.EncodeToString(l.CheckVal[:]))
	//log.Println("GenHMAC:userindex=", hex.EncodeToString(l.UserIndex[:]))
	//log.Println("GenHMAC:random=", hex.EncodeToString(l.Random[:]))
	//log.Println("GenHMAC:encpaket=", hex.EncodeToString(l.EncPacket[:]))

	l.HMAC = *HMAC_SHA256(data, key)
}

func (l *Cmd) Bytes() []byte {
	s := make([]byte, 1)
	s[0] = l.CmdType
	return BytesCombine(s, l.CheckVal[:], l.UserIndex[:], l.Random[:], l.EncPacket, l.HMAC[:])
}

func NewCommand(name, pwd string, packet *Packet) *Cmd {
	cmd := &Cmd{CmdType: packet.Ptype}
	cmd.Random = GenRandomHash()
	cmd.CheckVal.SetBytes(SHA256(BytesXor([]byte(ClientID), cmd.Random[:])))
	cmd.UserIndex.SetBytes(BytesXor(SHA256([]byte(name)), cmd.Random[:]))

	pwdSha := SHA256([]byte(pwd))
	//log.Println("NewCommand, pwd=", pwd, ",pwdsha=", hex.EncodeToString(pwdSha))
	aeskey := BytesXor(pwdSha[0:16], pwdSha[16:])
	cmd.EncPacket = AESEncrypt(packet.Bytes(), aeskey)

	cmd.GenHMAC(aeskey)

	return cmd
}

func NewLoginCmd(name string, passwd string, pubkey string, deviceId string, sysinfo SystemInfo) (*Cmd, error) {
	lp := LoginReqPacket{DeviceID: deviceId, Pubkey: pubkey, MachineInfo: sysinfo}
	if !lp.Valid() {
		return nil, errors.New("invalid param")
	}
	//log.Println("loginReqpacket:", string(lp.Bytes()))

	p := &Packet{LoginRequestMsg, lp.Bytes()}
	cmd := NewCommand(name, passwd, p)

	return cmd, nil
}

func NewAdminLoginCmd(name string, passwd string) (*Cmd, error) {
	lp := AdminLoginReqPacket{}
	if !lp.Valid() {
		return nil, errors.New("invalid param")
	}

	p := &Packet{AdminLoginRequest, lp.Bytes()}
	cmd := NewCommand(name, passwd, p)

	return cmd, nil
}

func NewChangePwdCmd(name string, passwd string, newpwd string) (*Cmd, error) {
	c := ChangePwdPacket{Passwd: newpwd}
	p := &Packet{ChangePwdMsg, c.Bytes()}
	cmd := NewCommand(name, passwd, p)

	return cmd, nil
}

func NewLogoutCmd(name string, passwd string, pubkey string) (*Cmd, error) {
	c := LogoutPacket{Pubkey: pubkey}
	p := &Packet{LogoutRequestMsg, c.Bytes()}
	cmd := NewCommand(name, passwd, p)

	return cmd, nil
}

func GetResponseDec(name string, pwd string, data []byte) ([]byte, error) {
	if len(data) < 96 {
		return nil, errors.New("Invalid response")
	}
	r_userindx := data[:32]
	r_random := data[32:64]
	r_encpac := data[64 : len(data)-32]
	r_hmac := data[len(data)-32:]

	hmac_data := BytesCombine(r_userindx, r_random, r_encpac)

	userNameSha := SHA256([]byte(name))
	userIndex := BytesXor(userNameSha, r_random)
	if bytes.Compare(r_userindx, userIndex) != 0 {
		return nil, errors.New("not match userindex")
	}
	pwdSha := SHA256([]byte(pwd))
	//log.Println("ParseLoginResponse pwd=", pwd, ",pwdsha=", hex.EncodeToString(pwdSha))

	aeskey := BytesXor(pwdSha[0:16], pwdSha[16:])
	//log.Println("ParseLoginResponse aeskey=", hex.EncodeToString(aeskey))

	hmac_hash := HMAC_SHA256(hmac_data, aeskey)
	//log.Println("ParseLoginResponse local hmac=", hex.EncodeToString(hmac_hash[:]))
	//log.Println("ParseLoginResponse local hmac=", hex.EncodeToString(hmac_hash[:]))
	if result := bytes.Compare(hmac_hash[:], r_hmac); result != 0 {
		return nil, errors.New("hmac not match")
	}

	decPac := AESDecrypt(r_encpac, aeskey)
	//log.Println("AESDec loginRes:%s", hex.EncodeToString(decPac))
	//log.Println("AESDec loginRes:%s", string(decPac))

	return decPac, nil
}

func ParseLoginResponse(name string, pwd string, data []byte) (*LoginData, error) {
	if len(data) < 96 {
		return nil, errors.New("response too short")
	}
	r_userindx := data[:32]
	r_random := data[32:64]
	r_encpac := data[64 : len(data)-32]
	r_hmac := data[len(data)-32:]

	hmac_data := BytesCombine(r_userindx, r_random, r_encpac)

	userNameSha := SHA256([]byte(name))
	userIndex := BytesXor(userNameSha, r_random)
	if bytes.Compare(r_userindx, userIndex) != 0 {
		return nil, errors.New("not match userindex")
	}
	pwdSha := SHA256([]byte(pwd))
	//log.Println("ParseLoginResponse pwd=", pwd, ",pwdsha=", hex.EncodeToString(pwdSha))

	aeskey := BytesXor(pwdSha[0:16], pwdSha[16:])
	//log.Println("ParseLoginResponse aeskey=", hex.EncodeToString(aeskey))

	hmac_hash := HMAC_SHA256(hmac_data, aeskey)
	//log.Println("ParseLoginResponse local hmac=", hex.EncodeToString(hmac_hash[:]))
	//log.Println("ParseLoginResponse local hmac=", hex.EncodeToString(hmac_hash[:]))
	if result := bytes.Compare(hmac_hash[:], r_hmac); result != 0 {
		return nil, errors.New("hmac not match")
	}

	decPac := AESDecrypt(r_encpac, aeskey)
	//log.Println("AESDec loginRes:%s", hex.EncodeToString(decPac))
	//log.Println("AESDec loginRes:%s", string(decPac))

	res := &LoginResponse{}
	if err := json.Unmarshal(decPac, &res); err != nil {
		log.Println("decpac unmarshal to loginrespacket failed.")
		return nil, err
	}
	return &res.LoginData, nil
}

func ParseAdminLoginResponse(name string, pwd string, data []byte) (*AdminLoginData, error) {
	if len(data) < 96 {
		return nil, errors.New("response too short")
	}
	r_userindx := data[:32]
	r_random := data[32:64]
	r_encpac := data[64 : len(data)-32]
	r_hmac := data[len(data)-32:]

	hmac_data := BytesCombine(r_userindx, r_random, r_encpac)

	userNameSha := SHA256([]byte(name))
	userIndex := BytesXor(userNameSha, r_random)
	if bytes.Compare(r_userindx, userIndex) != 0 {
		return nil, errors.New("not match userindex")
	}
	pwdSha := SHA256([]byte(pwd))
	//log.Println("ParseAdminLoginResponse pwd=", pwd, ",pwdsha=", hex.EncodeToString(pwdSha))

	aeskey := BytesXor(pwdSha[0:16], pwdSha[16:])
	//log.Println("ParseLoginResponse aeskey=", hex.EncodeToString(aeskey))

	hmac_hash := HMAC_SHA256(hmac_data, aeskey)
	//log.Println("ParseLoginResponse local hmac=", hex.EncodeToString(hmac_hash[:]))
	if result := bytes.Compare(hmac_hash[:], r_hmac); result != 0 {
		return nil, errors.New("hmac not match")
	}

	decPac := AESDecrypt(r_encpac, aeskey)
	//log.Println("AESDec loginRes:%s", hex.EncodeToString(decPac))
	//log.Println("AESDec loginRes:%s", string(decPac))

	res := &AdminLoginResponse{}
	if err := json.Unmarshal(decPac, &res); err != nil {
		log.Println("decpac unmarshal to loginrespacket failed.")
		return nil, err
	}
	return &res.AdminLoginData, nil
}
