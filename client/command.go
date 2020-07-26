package client

import (
	"bytes"
	"encoding/hex"
	"errors"
	"github.com/tjfoc/gmsm/sm2"
	. "github.com/xueqianLu/ZtAApi/common"
	"log"
	"time"
)

const (
	ClientID               = "AZEROTRUSTNETWORKACCESSTOANYONEL"
	NormalCertCmdType byte = 0x01 // 普通用户
	NormalUserCmdType byte = 0x02 // 普通用户

	AdminCertCmdType byte = 0x03 // 管理员用户
	AdminUserCmdType byte = 0x04 // 管理员用户

	LoginRequestMsg   byte = 0x01
	AdminLoginRequest byte = 0x02
	ChangePwdMsg      byte = 0x03
	LogoutRequestMsg  byte = 0x04
)

type Packet struct {
	//Ptype   byte // used to set cmdtype.
	Payload []byte
}

func (p Packet) Bytes() []byte {
	bsb := bytes.NewBuffer([]byte{})
	bsb.Write(p.Payload)
	return bsb.Bytes()
}

type Command interface {
	Type() byte
	Data() []byte
}

type UserCmd struct {
	CheckVal  Hash
	UserIndex Hash
	Random    Hash
	CmdType   byte
	EncLength [2]byte
	EncPacket []byte
	Signature []byte
}

func (u *UserCmd) GenSignature(privk *sm2.PrivateKey) error {
	enclen := len(u.EncPacket)
	u.EncLength[0] = byte(enclen >> 8 & 0xff)
	u.EncLength[1] = byte(enclen & 0xff)

	s := make([]byte, 1)
	s[0] = u.CmdType

	data := BytesCombine(s, u.CheckVal[:], u.UserIndex[:], u.Random[:], u.EncLength[:], u.EncPacket[:])

	signature, err := SM2PrivSign(privk, data)
	if err != nil {
		log.Println("GenSignature failed, err ", err)
		return err
	}
	u.Signature = signature
	return nil
}

func (u *UserCmd) Type() byte {
	return u.CmdType
}

func (u *UserCmd) Data() []byte {
	s := make([]byte, 1)
	s[0] = u.CmdType
	return BytesCombine(s, u.CheckVal[:], u.UserIndex[:], u.Random[:], u.EncLength[:], u.EncPacket, u.Signature[:])
}

func NewUserCommand(admin bool, username string, privk *sm2.PrivateKey, manager_cert *sm2.Certificate, packet *Packet) *UserCmd {
	var err error
	var cmdtype byte
	if admin {
		cmdtype = AdminUserCmdType
	} else {
		cmdtype = NormalUserCmdType
	}
	cmd := &UserCmd{CmdType: cmdtype}
	cmd.Random = GenRandomHash()
	cmd.CheckVal.SetBytes(SHA256(BytesXor([]byte(ClientID), cmd.Random[:])))
	cmd.UserIndex.SetBytes(BytesXor(SHA256([]byte(username)), cmd.Random[:]))

	cmd.EncPacket, err = SM2CertEncrypt(manager_cert, packet.Bytes())
	if err != nil {
		log.Println("manager cert encrypt failed,", err)
		return nil
	}

	if err = cmd.GenSignature(privk); err != nil {
		log.Println("gensignature failed,", err)
		return nil
	}

	log.Printf("NewUserCommand %v\n", cmd)
	return cmd
}

func NewLoginCmd(name string, passwd string, pubkey string, deviceId string, sysinfo SystemInfo,
	privk *sm2.PrivateKey, manager_cert *sm2.Certificate) (*UserCmd, error) {
	pwdhash := SHA256([]byte(passwd))
	lp := LoginReqPacket{Type: int(LoginRequestMsg), DeviceID: deviceId, Pubkey: pubkey, MachineInfo: sysinfo, PwdHash: hex.EncodeToString(pwdhash), Timestamp: time.Now().Unix()}
	log.Println("new logincmd deviceid:", deviceId, "len(deviceid)", len(deviceId))
	log.Println("new logincmd pubkey:", pubkey, "len(pubkey)", len(pubkey))
	if !lp.Valid() {
		return nil, errors.New("invalid param")
	}
	//log.Println("loginReqpacket:", string(lp.Bytes()))

	p := &Packet{lp.Bytes()}
	cmd := NewUserCommand(false, name, privk, manager_cert, p)

	return cmd, nil
}

func NewAdminLoginCmd(name string, passwd string, privk *sm2.PrivateKey, manager_cert *sm2.Certificate) (*UserCmd, error) {
	pwdhash := SHA256([]byte(passwd))
	lp := AdminLoginReqPacket{Type: int(AdminLoginRequest), PwdHash: hex.EncodeToString(pwdhash), Timestamp: time.Now().Unix()}
	if !lp.Valid() {
		return nil, errors.New("invalid param")
	}

	p := &Packet{lp.Bytes()}
	cmd := NewUserCommand(true, name, privk, manager_cert, p)

	return cmd, nil
}

func NewChangePwdCmd(name string, passwd string, newpwd string, privk *sm2.PrivateKey, manager_cert *sm2.Certificate) (*UserCmd, error) {
	oldpwdhash := SHA256([]byte(passwd))
	c := ChangePwdPacket{Type: int(ChangePwdMsg), OldPwdHash: hex.EncodeToString(oldpwdhash), Passwd: newpwd, Timestamp: time.Now().Unix()}
	p := &Packet{c.Bytes()}
	cmd := NewUserCommand(false, name, privk, manager_cert, p)

	return cmd, nil
}

func NewLogoutCmd(name string, passwd string, pubkey string, privk *sm2.PrivateKey, manager_cert *sm2.Certificate) (*UserCmd, error) {
	pwdhash := SHA256([]byte(passwd))
	c := LogoutPacket{Type: int(LogoutRequestMsg), PwdHash: hex.EncodeToString(pwdhash), Pubkey: pubkey, Timestamp: time.Now().Unix()}
	p := &Packet{c.Bytes()}
	cmd := NewUserCommand(false, name, privk, manager_cert, p)

	return cmd, nil
}

type HmacCmd struct {
	CheckVal  Hash
	UserIndex Hash
	Random    Hash
	CmdType   byte
	//EncLength [2]byte
	EncPacket []byte
	HMAC      Hash
}

func (l *HmacCmd) GenHMAC(key []byte) {
	//enclen := len(l.EncPacket)
	//l.EncLength[0] = byte(enclen>>8 & 0xff)
	//l.EncLength[1] = byte(enclen & 0xff)

	s := make([]byte, 1)
	s[0] = l.CmdType

	data := BytesCombine(s, l.CheckVal[:], l.UserIndex[:], l.Random[:], l.EncPacket[:])
	//log.Println("GenHMAC:checkval=", hex.EncodeToString(l.CheckVal[:]))
	//log.Println("GenHMAC:userindex=", hex.EncodeToString(l.UserIndex[:]))
	//log.Println("GenHMAC:random=", hex.EncodeToString(l.Random[:]))
	//log.Println("GenHMAC:encpaket=", hex.EncodeToString(l.EncPacket[:]))

	l.HMAC = *HMAC_SHA256(data, key)
}

func (l *HmacCmd) Type() byte {
	return l.CmdType
}

func (l *HmacCmd) Data() []byte {
	s := make([]byte, 1)
	s[0] = l.CmdType
	return BytesCombine(s, l.CheckVal[:], l.UserIndex[:], l.Random[:], l.EncPacket, l.HMAC[:])
}

func NewHmacCommand(admin bool, name, pwd string, packet *Packet) *HmacCmd {
	var cmdtype byte
	if admin {
		cmdtype = AdminCertCmdType
	} else {
		cmdtype = NormalCertCmdType
	}
	cmd := &HmacCmd{CmdType: cmdtype}

	cmd.Random = GenRandomHash()
	cmd.CheckVal.SetBytes(SHA256(BytesXor([]byte(ClientID), cmd.Random[:])))
	cmd.UserIndex.SetBytes(BytesXor(SHA256([]byte(name)), cmd.Random[:]))

	pwdSha := SM3Hash([]byte(pwd))
	log.Println("NewCommand, pwd=", pwd, ",pwdsha=", hex.EncodeToString(pwdSha[:]))
	smkey := BytesXor(pwdSha[0:16], pwdSha[16:])
	cmd.EncPacket = SM4EncryptCBC(smkey, packet.Bytes())
	if cmd.EncPacket == nil {
		log.Println("SM4Encrypt return nil")
		return nil
	}
	cmd.GenHMAC(smkey)
	log.Printf("New command %v\n", cmd)

	return cmd
}

func NewNormalExchangeCertCmd(name string, passwd string, csr string) (*HmacCmd, error) {
	c := ExchangeCertPacket{Csrdata: csr, Timestamp: time.Now().Unix()}
	p := &Packet{c.Bytes()}
	cmd := NewHmacCommand(false, name, passwd, p)

	return cmd, nil
}

func NewAdminExchangeCertCmd(name string, passwd string, csr string) (*HmacCmd, error) {
	c := ExchangeCertPacket{Csrdata: csr, Timestamp: time.Now().Unix()}
	p := &Packet{c.Bytes()}
	cmd := NewHmacCommand(true, name, passwd, p)

	return cmd, nil
}
