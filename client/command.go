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
	ClientID                     = "AZEROTRUSTNETWORKACCESSTOANYONEL"
	NormalUserExchangeCert  byte = 1 //普通用户交换证书
	NormalUserLogin         byte = 2 //普通用户登录
	NormalUserChangPwd      byte = 3 //普通用户修改密码
	NormalUserLogout        byte = 4 //普通用户退出登录
	NormalUserReqServerList byte = 5 //普通用户获取服务器列表
	NormalUserReqHostList   byte = 6 //普通用户获取服务器列表

	AdminExchangeCertMsg byte = 10 //管理员交换证书
	AdminLoginMsg        byte = 11 //管理员登录
)

type Packet struct {
	Ptype   byte // used to set cmdtype.
	Payload []byte
}

func (p Packet) Type() byte {
	return p.Ptype
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
	CheckVal    Hash
	UserIndex   Hash
	DeviceIndex Hash
	Random      Hash
	CmdType     byte
	EncLength   [2]byte
	EncPacket   []byte
	Signature   []byte
}

func (u *UserCmd) GenSignature(privk *sm2.PrivateKey) error {
	enclen := len(u.EncPacket)
	u.EncLength[0] = byte(enclen >> 8 & 0xff)
	u.EncLength[1] = byte(enclen & 0xff)

	s := make([]byte, 1)
	s[0] = u.CmdType

	data := BytesCombine(s, u.CheckVal[:], u.UserIndex[:], u.DeviceIndex[:], u.Random[:], u.EncLength[:], u.EncPacket[:])

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
	return BytesCombine(s, u.CheckVal[:], u.UserIndex[:], u.DeviceIndex[:], u.Random[:], u.EncLength[:], u.EncPacket, u.Signature[:])
}

func NewUserCommand(username string, deviceid string, privk *sm2.PrivateKey, manager_cert *sm2.Certificate, packet *Packet) *UserCmd {
	var err error
	var cmdtype = packet.Type()
	cmd := &UserCmd{CmdType: cmdtype}
	cmd.Random = GenRandomHash()
	cmd.CheckVal.SetBytes(SHA256(BytesXor([]byte(ClientID), cmd.Random[:])))
	cmd.UserIndex.SetBytes(BytesXor(SHA256([]byte(username)), cmd.Random[:]))
	cmd.DeviceIndex.SetBytes(BytesXor(SHA256([]byte(deviceid)), cmd.Random[:]))

	cmd.EncPacket, err = SM2CertEncrypt(manager_cert, packet.Bytes())
	if err != nil {
		log.Println("manager cert encrypt failed,", err)
		return nil
	}

	{
		data := []byte("12345678901234567890")
		encd, e := SM2CertEncrypt(manager_cert, data)
		if e != nil {
			log.Println("SM2CertEncrypt failed, err=", err)
		} else {
			log.Println("encdata = ", hex.EncodeToString(encd), "data=", string(data))
		}
	}

	if err = cmd.GenSignature(privk); err != nil {
		log.Println("gensignature failed,", err)
		return nil
	}

	log.Printf("NewUserCommand %v\n", cmd)
	return cmd
}

func NewLoginCmd(name string, passwd string, pubkey string, deviceId string,
	privk *sm2.PrivateKey, manager_cert *sm2.Certificate) (*UserCmd, error) {
	pwdhash := SHA256([]byte(passwd))
	lp := LoginReqPacket{DeviceID: deviceId, Pubkey: pubkey, PwdHash: hex.EncodeToString(pwdhash), Timestamp: time.Now().Unix()}
	//log.Println("new logincmd deviceid:", deviceId, "len(deviceid)", len(deviceId))
	//log.Println("new logincmd pubkey:", pubkey, "len(pubkey)", len(pubkey))
	if !lp.Valid() {
		return nil, errors.New("invalid param")
	}
	//log.Println("loginReqpacket:", string(lp.Bytes()))

	p := &Packet{NormalUserLogin, lp.Bytes()}
	cmd := NewUserCommand(name, deviceId, privk, manager_cert, p)

	return cmd, nil
}

func NewAdminLoginCmd(name string, passwd string, deviceId string, privk *sm2.PrivateKey, manager_cert *sm2.Certificate) (*UserCmd, error) {
	pwdhash := SHA256([]byte(passwd))
	lp := AdminLoginReqPacket{DeviceID: deviceId, PwdHash: hex.EncodeToString(pwdhash), Timestamp: time.Now().Unix()}
	if !lp.Valid() {
		return nil, errors.New("invalid param")
	}

	p := &Packet{AdminLoginMsg, lp.Bytes()}
	cmd := NewUserCommand(name, deviceId, privk, manager_cert, p)

	return cmd, nil
}

func NewChangePwdCmd(name string, deviceId string, passwd string, newpwd string, privk *sm2.PrivateKey, manager_cert *sm2.Certificate) (*UserCmd, error) {
	oldpwdhash := SHA256([]byte(passwd))
	c := ChangePwdPacket{OldPwdHash: hex.EncodeToString(oldpwdhash), Passwd: newpwd, Timestamp: time.Now().Unix()}
	p := &Packet{NormalUserChangPwd, c.Bytes()}
	cmd := NewUserCommand(name, deviceId, privk, manager_cert, p)

	return cmd, nil
}

func NewLogoutCmd(name string, deviceId string, passwd string, pubkey string, privk *sm2.PrivateKey, manager_cert *sm2.Certificate) (*UserCmd, error) {
	pwdhash := SHA256([]byte(passwd))
	c := LogoutPacket{PwdHash: hex.EncodeToString(pwdhash), Pubkey: pubkey, Timestamp: time.Now().Unix()}
	p := &Packet{NormalUserLogout, c.Bytes()}
	cmd := NewUserCommand(name, deviceId, privk, manager_cert, p)

	return cmd, nil
}

func NewReqServerListCmd(name string, deviceId string, startOffset int, privk *sm2.PrivateKey, manager_cert *sm2.Certificate) (*UserCmd, error) {
	c := ServerListReqPacket{StartOffset: startOffset, Timestamp: time.Now().Unix()}
	p := &Packet{NormalUserReqServerList, c.Bytes()}
	cmd := NewUserCommand(name, deviceId, privk, manager_cert, p)

	return cmd, nil
}

func NewReqHostListCmd(name string, deviceId string, startOffset int, privk *sm2.PrivateKey, manager_cert *sm2.Certificate) (*UserCmd, error) {
	c := HostsListReqPacket{StartOffset: startOffset, Timestamp: time.Now().Unix()}
	p := &Packet{NormalUserReqHostList, c.Bytes()}
	cmd := NewUserCommand(name, deviceId, privk, manager_cert, p)

	return cmd, nil
}

type HmacCmd struct {
	CheckVal    Hash
	UserIndex   Hash
	DeviceIndex Hash
	Random      Hash
	CmdType     byte
	EncPacket   []byte
	HMAC        Hash
}

func (l *HmacCmd) GenHMAC(key []byte) {

	s := make([]byte, 1)
	s[0] = l.CmdType

	data := BytesCombine(s, l.CheckVal[:], l.UserIndex[:], l.DeviceIndex[:], l.Random[:], l.EncPacket[:])
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
	return BytesCombine(s, l.CheckVal[:], l.UserIndex[:], l.DeviceIndex[:], l.Random[:], l.EncPacket, l.HMAC[:])
}

func NewHmacCommand(name, deviceid, pwd string, packet *Packet) *HmacCmd {
	var cmdtype = packet.Type()
	cmd := &HmacCmd{CmdType: cmdtype}

	cmd.Random = GenRandomHash()
	cmd.CheckVal.SetBytes(SHA256(BytesXor([]byte(ClientID), cmd.Random[:])))
	cmd.UserIndex.SetBytes(BytesXor(SHA256([]byte(name)), cmd.Random[:]))
	cmd.DeviceIndex.SetBytes(BytesXor(SHA256([]byte(deviceid)), cmd.Random[:]))

	pwdSha := SM3Hash([]byte(pwd))
	//log.Println("NewCommand, pwd=", pwd, ",pwdsha=", hex.EncodeToString(pwdSha[:]))
	smkey := BytesXor(pwdSha[0:16], pwdSha[16:])
	cmd.EncPacket = SM4EncryptCBC(smkey, packet.Bytes())
	if cmd.EncPacket == nil {
		log.Println("SM4Encrypt return nil")
		return nil
	}
	cmd.GenHMAC(smkey)
	//log.Printf("New command %v\n", cmd)

	return cmd
}

func NewNormalExchangeCertCmd(name string, passwd string, csr string, sysinfo SystemInfo) (*HmacCmd, error) {
	c := ExchangeCertPacket{Csrdata: csr, Timestamp: time.Now().Unix(), MachineInfo: sysinfo}
	p := &Packet{NormalUserExchangeCert, c.Bytes()}
	cmd := NewHmacCommand(name, sysinfo.DeviceId, passwd, p)

	return cmd, nil
}

func NewAdminExchangeCertCmd(name string, passwd string, csr string, sysinfo SystemInfo) (*HmacCmd, error) {
	c := ExchangeCertPacket{Csrdata: csr, Timestamp: time.Now().Unix(), MachineInfo: sysinfo}
	p := &Packet{AdminExchangeCertMsg, c.Bytes()}
	cmd := NewHmacCommand(name, sysinfo.DeviceId, passwd, p)

	return cmd, nil
}
