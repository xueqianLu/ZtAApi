package client

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/xueqianLu/ZtAApi/common"
	"github.com/xueqianLu/ZtAApi/conf"
	"log"
	"net"
	"strconv"
	"time"
)

const (
	ServerHost     = "127.0.0.1"
	ServerPort     = 36680
	RequestTimeout = 10 * time.Second
	MaxReadBuffer  = 1600
)

var (
	LocalConfig = &conf.StorageConfig{}
	gloginData  = &LoginData{}
)

func SetOrGeneratePrivateKey(priv string) string {

	if LocalConfig.PrivateKey != "" {
		// already have privatekey.
		return LocalConfig.PrivateKey
	}

	if len(priv) != 0 {
		privk, err := conf.NewPrivateKeyFromString(priv)
		if err == nil {
			// set privatekey with param.
			LocalConfig.PrivateKey = priv
			LocalConfig.PublicKey = privk.Public().String()
		}
	}

	if LocalConfig.PrivateKey == "" {
		// generate privatekey
		privk, _ := conf.NewPrivateKey()
		LocalConfig.PrivateKey = privk.String()
		LocalConfig.PublicKey = privk.Public().String()
	}
	return LocalConfig.PrivateKey
}

func SetUserInfo(username, password string) {
	LocalConfig.UserName = username
	LocalConfig.Password = password
}

func SetServerInfo(serveraddr string) {
	LocalConfig.ServerAddr = serveraddr
	log.Println("set server addr ", serveraddr)
}

func requestToServer(cmd *Cmd) ([]byte, error) {
	serverAddr := LocalConfig.ServerAddr + ":" + strconv.Itoa(ServerPort)
	log.Println("request to server", serverAddr)
	conn, err := net.Dial("udp", serverAddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	//log.Println("write to server ", hex.EncodeToString(cmd.Bytes()))
	if _, err = conn.Write(cmd.Bytes()); err != nil {
		return nil, err
	}
	tm := time.NewTimer(RequestTimeout)
	defer tm.Stop()

	ch := make(chan error, 1)
	msg := make([]byte, MaxReadBuffer)
	readLen := 0
	go func() {
		//log.Println("wait to read msg")
		readLen, err = conn.Read(msg)
		log.Println("read msg from server len", readLen, "msg", hex.EncodeToString(msg))
		ch <- err
	}()

	select {
	case <-tm.C:
		// request timeout
		return nil, ErrRequestTimeout
	case err, _ := <-ch:
		if err != nil {
			return nil, err
		} else {
			return msg[:readLen], nil
		}
	}
}

func GetUsername() string {
	return LocalConfig.UserName
}

func GetZtALoginInfo() string {
	data, _ := json.Marshal(gloginData)
	return string(data)
}

func ClientLogin(sysinfostr string) error {
	var err error

	var res, decPac []byte
	local := LocalConfig

	var sysinfo = &common.SystemInfo{}
	err = json.Unmarshal([]byte(sysinfostr), &sysinfo)
	if err != nil {
		log.Println("ClientLogin parse sysinfo failed, sysinfo:", sysinfostr)
		return err
	}

	cmd, _ := NewLoginCmd(local.UserName, local.Password, local.PublicKey, sysinfo.DeviceId, *sysinfo)
	res, err = requestToServer(cmd)
	if err != nil {
		return err
	}
	// den
	decPac, err = GetResponseDec(local.UserName, local.Password, res)
	if err != nil {
		return err
	}

	head := &ServerResponse{}
	if err = json.Unmarshal(decPac, &head); err != nil {
		log.Println("decpac unmarshal to server response failed.")
		return err
	}
	//log.Printf("decode login response status = %d\n", head.Status)
	if head.Status != 1 {
		err = errors.New(head.Msg)
		return err
	}
	// parse res
	var info *LoginData
	info, err = ParseLoginResponse(local.UserName, local.Password, res)
	if err != nil {
		return err
	}
	gloginData = info // save logininfo
	return nil
}

func ClientLogout(force bool) error {
	var res, decPac []byte
	var err error
	//log.Println("client logout, force =", force)

	// stop lifetime keeper routine.
	//log.Println("client logout, force =", force)
	if !force {
		log.Println("client logout, force =", force)
		local := LocalConfig
		cmd, _ := NewLogoutCmd(local.UserName, local.Password, local.PublicKey)
		res, err = requestToServer(cmd)
		log.Println("send to server logout cmd:", hex.EncodeToString(cmd.Bytes()))
		if err != nil {
			return err
		}
		// den
		decPac, err = GetResponseDec(local.UserName, local.Password, res)
		if err != nil {
			return err
		}

		head := &ServerResponse{}
		if err = json.Unmarshal(decPac, &head); err != nil {
			log.Println("decpac unmarshal to server response failed.")
			return err
		}
		if head.Status != 1 {
			err = errors.New(head.Msg)
			return err
		}
	}

	return nil
}

func ClientChangePwd(newpwd string) error {
	local := LocalConfig
	cmd, _ := NewChangePwdCmd(local.UserName, local.Password, newpwd)
	res, err := requestToServer(cmd)
	if err != nil {
		return err
	}
	// den
	decPac, err := GetResponseDec(local.UserName, local.Password, res)
	if err != nil {
		return err
	}

	head := &ServerResponse{}
	if err = json.Unmarshal(decPac, &head); err != nil {
		log.Println("decpac unmarshal to server response failed.")
		return err
	}
	if head.Status != 1 {
		err = errors.New(head.Msg)
		return err
	}
	return nil
}
