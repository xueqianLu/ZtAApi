package client

import (
	"bytes"
	"encoding/hex"
	"errors"
	"github.com/tjfoc/gmsm/sm2"
	. "github.com/ztasecure-lab/gologin/common"
	"github.com/ztasecure-lab/gologin/conf"
	"log"
	"time"
)

const (
	ClientID                    = "AZEROTRUSTNETWORKACCESSTOANYONEL"
	NormalUserExchangeCert byte = 1 //普通用户交换证书
	NormalUserLogin        byte = 2 //普通用户登录
	NormalUserChangPwd     byte = 3 //普通用户修改密码
	NormalUserLogout       byte = 4 //普通用户退出登录
	NormalUserReqSliceInfo byte = 5 //普通用户获取用户配置信息
	NormalUserReqCertSlice byte = 6 // 普通用户获取证书分片信息

	NormalUserReqHome         byte = 7  //普通用户获取home url
	NormalUserRegetVerifyCode byte = 8  //普通用户获取用户配置信息
	NormalUserGetToken        byte = 9  //普通用户获取token
	NormalUserNetworkSwitch   byte = 16 //普通用户切换网络(内网、外网)

	AdminExchangeCertMsg byte = 10                     //管理员交换证书
	AdminLoginMsg        byte = 11                     //管理员登录
	AdminReGetVerifyCode byte = 12                     // 管理员重新获取验证码
	AdminReqCertSliceCmd byte = NormalUserReqCertSlice // 管理员获取证书分片信息
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
		//log.Println("GenSignature failed, err ", err)
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

	if err = cmd.GenSignature(privk); err != nil {
		log.Println("gensignature failed,", err)
		return nil
	}

	//log.Printf("NewUserCommand %v\n", cmd)
	return cmd
}

func NewLoginCmd(local *conf.StorageConfig, pubkey string, deviceId string,
	privk *sm2.PrivateKey, manager_cert *sm2.Certificate, sysinfo SystemInfo,
	verifyCode string, secondVerify string) (*UserCmd, error) {
	pwdhash := SHA256([]byte(local.Password))
	lp := LoginReqPacket{DeviceID: deviceId, Pubkey: pubkey, PwdHash: hex.EncodeToString(pwdhash), Timestamp: time.Now().Unix(),
		Username: local.UserName, Passwd: local.Password, MachineInfo: sysinfo, VerifyCode: verifyCode, SecondVerifyCode: secondVerify,
		IpAddr: local.LocalAddr, MacAddr: local.LocalMac}
	//log.Println("new logincmd deviceid:", deviceId, "len(deviceid)", len(deviceId))
	//log.Println("new logincmd pubkey:", pubkey, "len(pubkey)", len(pubkey))
	if !lp.Valid() {
		return nil, errors.New("invalid param")
	}
	//log.Println("loginReqpacket:", string(lp.Bytes()))

	p := &Packet{NormalUserLogin, lp.Bytes()}
	cmd := NewUserCommand(local.UserName, deviceId, privk, manager_cert, p)

	return cmd, nil
}

func NewLoginCmdWithToken(local *conf.StorageConfig, pubkey string, deviceId string,
	privk *sm2.PrivateKey, manager_cert *sm2.Certificate, sysinfo SystemInfo,
	verifyCode string, secondVerify string, loginToken string) (*UserCmd, error) {
	pwdhash := SHA256([]byte(local.Password))
	lp := LoginReqPacket{DeviceID: deviceId, Pubkey: pubkey, PwdHash: hex.EncodeToString(pwdhash), Timestamp: time.Now().Unix(),
		Username: local.UserName, Passwd: local.Password, MachineInfo: sysinfo, VerifyCode: verifyCode, SecondVerifyCode: secondVerify, LoginToken: loginToken,
		IpAddr: local.LocalAddr, MacAddr: local.LocalMac}
	//log.Println("new logincmd deviceid:", deviceId, "len(deviceid)", len(deviceId))
	//log.Println("new logincmd pubkey:", pubkey, "len(pubkey)", len(pubkey))
	if !lp.Valid() {
		return nil, errors.New("invalid param")
	}
	//log.Println("loginReqpacket:", string(lp.Bytes()))

	p := &Packet{NormalUserLogin, lp.Bytes()}
	cmd := NewUserCommand(local.UserName, deviceId, privk, manager_cert, p)

	return cmd, nil
}

func NewAdminLoginCmd(local *conf.StorageConfig, deviceId string, privk *sm2.PrivateKey,
	manager_cert *sm2.Certificate, sysinfo SystemInfo, verifyCode string, getUrl bool) (*UserCmd, error) {
	pwdhash := SHA256([]byte(local.Password))
	lp := AdminLoginReqPacket{DeviceID: deviceId, PwdHash: hex.EncodeToString(pwdhash), Timestamp: time.Now().Unix(),
		Username: local.UserName, Passwd: local.Password, MachineInfo: sysinfo, VerifyCode: verifyCode, GetUrl: getUrl,
		IpAddr: local.LocalAddr, MacAddr: local.LocalMac}
	if !lp.Valid() {
		return nil, errors.New("invalid param")
	}

	p := &Packet{AdminLoginMsg, lp.Bytes()}
	cmd := NewUserCommand(local.UserName, deviceId, privk, manager_cert, p)

	return cmd, nil
}

func NewAdminRegetVerifyCodeCmd(local *conf.StorageConfig, deviceId string, privk *sm2.PrivateKey,
	manager_cert *sm2.Certificate, sysinfo SystemInfo) (*UserCmd, error) {
	c := ReGetVerifyCodePacket{Timestamp: time.Now().Unix(),
		Username: local.UserName, Passwd: local.Password, MachineInfo: sysinfo,
		IpAddr: local.LocalAddr, MacAddr: local.LocalMac}
	p := &Packet{AdminReGetVerifyCode, c.Bytes()}
	cmd := NewUserCommand(local.UserName, deviceId, privk, manager_cert, p)

	return cmd, nil
}

func NewChangePwdCmd(local *conf.StorageConfig, deviceId string, newpwd string, privk *sm2.PrivateKey, manager_cert *sm2.Certificate) (*UserCmd, error) {
	oldpwdhash := SHA256([]byte(local.Password))
	c := ChangePwdPacket{OldPwdHash: hex.EncodeToString(oldpwdhash), NewPasswd: newpwd, Timestamp: time.Now().Unix(),
		Username: local.LocalAddr, Passwd: local.Password, IpAddr: local.LocalAddr, MacAddr: local.LocalMac}
	p := &Packet{NormalUserChangPwd, c.Bytes()}
	cmd := NewUserCommand(local.UserName, deviceId, privk, manager_cert, p)

	return cmd, nil
}

func NewRegetVerifyCodeCmd(local *conf.StorageConfig, deviceId string, privk *sm2.PrivateKey,
	manager_cert *sm2.Certificate, sysinfo SystemInfo) (*UserCmd, error) {
	c := ReGetVerifyCodePacket{Timestamp: time.Now().Unix(),
		Username: local.UserName, Passwd: local.Password, MachineInfo: sysinfo, IpAddr: local.LocalAddr, MacAddr: local.LocalMac}
	p := &Packet{NormalUserRegetVerifyCode, c.Bytes()}
	cmd := NewUserCommand(local.UserName, deviceId, privk, manager_cert, p)

	return cmd, nil
}

func NewLogoutCmd(local *conf.StorageConfig, deviceId string, pubkey string, privk *sm2.PrivateKey, manager_cert *sm2.Certificate) (*UserCmd, error) {
	pwdhash := SHA256([]byte(local.Password))
	c := LogoutPacket{PwdHash: hex.EncodeToString(pwdhash), Pubkey: pubkey, Timestamp: time.Now().Unix(),
		Username: local.UserName, Passwd: local.Password, IpAddr: local.LocalAddr, MacAddr: local.LocalMac}
	p := &Packet{NormalUserLogout, c.Bytes()}
	cmd := NewUserCommand(local.UserName, deviceId, privk, manager_cert, p)

	return cmd, nil
}

func NewReqUserInfoCmd(local *conf.StorageConfig, deviceId string, startOffset int, privk *sm2.PrivateKey, manager_cert *sm2.Certificate) (*UserCmd, error) {
	c := SliceInfoReqPacket{SliceOffset: startOffset, Timestamp: time.Now().Unix(), Username: local.UserName, Passwd: local.Password}
	p := &Packet{NormalUserReqSliceInfo, c.Bytes()}
	cmd := NewUserCommand(local.UserName, deviceId, privk, manager_cert, p)

	return cmd, nil
}

func NewReqUserHomeCmd(local *conf.StorageConfig, deviceId string, privk *sm2.PrivateKey, manager_cert *sm2.Certificate) (*UserCmd, error) {
	c := UserHomeReqPacket{Timestamp: time.Now().Unix(), Username: local.UserName, Passwd: local.Password,
		IpAddr: local.LocalAddr, MacAddr: local.LocalMac}
	p := &Packet{NormalUserReqHome, c.Bytes()}
	cmd := NewUserCommand(local.UserName, deviceId, privk, manager_cert, p)

	return cmd, nil
}

func NewReqUserTokenCmd(local *conf.StorageConfig, deviceId string, privk *sm2.PrivateKey, manager_cert *sm2.Certificate) (*UserCmd, error) {
	c := UserTokenReqPacket{Timestamp: time.Now().Unix(), Username: local.UserName, Passwd: local.Password,
		IpAddr: local.LocalAddr, MacAddr: local.LocalMac}
	p := &Packet{NormalUserGetToken, c.Bytes()}
	cmd := NewUserCommand(local.UserName, deviceId, privk, manager_cert, p)

	return cmd, nil
}

func NewReqSwitchNetworkCmd(local *conf.StorageConfig, deviceId string, mode int, privk *sm2.PrivateKey, pub string, manager_cert *sm2.Certificate) (*UserCmd, error) {
	c := SwitchNetReqPacket{Timestamp: time.Now().Unix(), Username: local.UserName, Passwd: local.Password, NetworkMode: mode, Pubkey: pub,
		IpAddr: local.LocalAddr, MacAddr: local.LocalMac}
	p := &Packet{NormalUserNetworkSwitch, c.Bytes()}
	cmd := NewUserCommand(local.UserName, deviceId, privk, manager_cert, p)

	return cmd, nil
}

type HmacCmd struct {
	CheckVal    Hash
	UserIndex   Hash
	DeviceIndex Hash
	Random      Hash
	Key         Hash
	CmdType     byte
	EncPacket   []byte
	HMAC        Hash
	Key2        []byte // used to make hmac and decrypt/encrypt packet.
}

func (l *HmacCmd) GenHMAC(key []byte) {

	s := make([]byte, 1)
	s[0] = l.CmdType

	data := BytesCombine(s, l.CheckVal[:], l.UserIndex[:], l.DeviceIndex[:], l.Random[:], l.Key[:], l.EncPacket[:])
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
	return BytesCombine(s, l.CheckVal[:], l.UserIndex[:], l.DeviceIndex[:], l.Random[:], l.Key[:], l.EncPacket, l.HMAC[:])
}

func NewHmacCommand(name, deviceid, pwd string, packet *Packet) *HmacCmd {
	var cmdtype = packet.Type()
	cmd := &HmacCmd{CmdType: cmdtype}

	cmd.Random = GenRandomHash()
	cmd.CheckVal.SetBytes(SHA256(BytesXor([]byte(ClientID), cmd.Random[:])))
	cmd.UserIndex.SetBytes(BytesXor(SHA256([]byte(name)), cmd.Random[:]))
	cmd.DeviceIndex.SetBytes(BytesXor(SHA256([]byte(deviceid)), cmd.Random[:]))

	var key1 = GenRandomHash()
	//log.Println("in hmc command, key1 = ", hex.EncodeToString(key1[:]))
	var key = BytesXor(key1[:], cmd.Random[:])
	copy(cmd.Key[:], key)

	cmd.Key2 = DevideKey(key1)
	//log.Println("after device key = ", hex.EncodeToString(cmd.Key2))

	cmd.EncPacket = SM4EncryptCBC(cmd.Key2, packet.Bytes())
	if cmd.EncPacket == nil {
		//log.Println("SM4Encrypt return nil")
		return nil
	}

	cmd.GenHMAC(cmd.Key2)
	//log.Printf("New command %v\n", cmd)

	return cmd
}

func NewNormalExchangeCertCmd(local *conf.StorageConfig, csr string, sysinfo SystemInfo) (*HmacCmd, error) {
	c := ExchangeCertPacket{Csrdata: csr, Timestamp: time.Now().Unix(), MachineInfo: sysinfo,
		Username: local.UserName, Passwd: local.Password, IpAddr: local.LocalAddr, MacAddr: local.LocalMac}
	p := &Packet{NormalUserExchangeCert, c.Bytes()}
	cmd := NewHmacCommand(local.UserName, sysinfo.DeviceId, local.Password, p)

	return cmd, nil
}

func NewNormalReqCertSliceCmd(name string, passwd string, startOffset int, sysinfo SystemInfo) (*HmacCmd, error) {
	c := SliceInfoReqPacket{SliceOffset: startOffset, Timestamp: time.Now().Unix()}
	p := &Packet{NormalUserReqCertSlice, c.Bytes()}
	cmd := NewHmacCommand(name, sysinfo.DeviceId, passwd, p)

	return cmd, nil
}

func NewAdminExchangeCertCmd(local *conf.StorageConfig, csr string, sysinfo SystemInfo) (*HmacCmd, error) {
	c := ExchangeCertPacket{Csrdata: csr, Timestamp: time.Now().Unix(), MachineInfo: sysinfo,
		Username: local.UserName, Passwd: local.Password, IpAddr: local.LocalAddr, MacAddr: local.LocalMac}
	p := &Packet{AdminExchangeCertMsg, c.Bytes()}
	cmd := NewHmacCommand(local.UserName, sysinfo.DeviceId, local.Password, p)

	return cmd, nil
}

func NewAdminReqCertSliceCmd(name string, passwd string, startOffset int, sysinfo SystemInfo) (*HmacCmd, error) {
	c := SliceInfoReqPacket{SliceOffset: startOffset, Timestamp: time.Now().Unix()}
	p := &Packet{AdminReqCertSliceCmd, c.Bytes()}
	cmd := NewHmacCommand(name, sysinfo.DeviceId, passwd, p)

	return cmd, nil
}
