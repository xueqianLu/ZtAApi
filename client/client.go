package client

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/xueqianLu/ZtAApi/common"
	"github.com/xueqianLu/ZtAApi/conf"
	"io"
	"io/ioutil"
	"log"
	"net"
	"path/filepath"
	"strconv"
	"time"
)

const (
	ServerHost     = "127.0.0.1"
	ServerPort     = 36680
	RequestTimeout = 10 * time.Second
	MaxReadBuffer  = 60000
)

func SetLogger(writer io.Writer) {
	common.Setlog(writer)
	log.Println("after ztaapi set logger")
}

func SetUserInfo(local *conf.StorageConfig, username, password string) {
	log.Println("SetUserInfo:", username)
	local.UserName = username
	local.Password = password
}

func SetServerInfo(local *conf.StorageConfig, serveraddr string) {
	local.ServerAddr = serveraddr
	log.Println("set server addr ", serveraddr)
}

func GetServerInfo(local *conf.StorageConfig) string {
	return local.ServerAddr + ":" + strconv.Itoa(ServerPort)
}

func checkAndGetUserConfig(local *conf.StorageConfig) error {
	var err error
	var userConfigPath string

	defer func() {
		if local.User != nil {
			conf.ClientUserConfigSave(local.User)
		}
	}()

	if local.User == nil {
		if userConfigPath,err = conf.GetUserConfigPath(local); err == nil {
			local.User,err = conf.GetUserLocalConfig(userConfigPath, local.UserName)
		} else {
			log.Println("checkAndGetUserConfig", "get user config path failed", err)
		}
	} else if local.UserName != local.User.UserName {
		conf.ClientUserConfigSave(local.User)
		userConfigPath,err = conf.GetUserConfigPath(local)
		local.User, err = conf.GetUserLocalConfig(userConfigPath, local.UserName)
	}

	return err
}

func requestToServer(local *conf.StorageConfig, cmd Command) ([]byte, error) {

	serverAddr := local.ServerAddr + ":" + strconv.Itoa(ServerPort)
	log.Println("request to server", serverAddr)
	conn, err := net.Dial("udp", serverAddr)
	if err != nil {
		log.Println("net.Dial failed, err", err)
		return nil, err
	}
	defer conn.Close()
	log.Println("write to server ", hex.EncodeToString(cmd.Data()))
	if _, err = conn.Write(cmd.Data()); err != nil {
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

func GetUsername(local *conf.StorageConfig) string {
	return local.UserName
}

func GetZtALoginInfo(lg *LoginResData) string {
	data, _ := json.Marshal(lg)
	return string(data)
}

func needExchangeCert(conf *conf.StorageConfig) bool {
	if conf.User.ManagerCert != nil && conf.User.Sm2Priv != nil {
		return false
	}
	return true
}

func prepareCsrAndPrivk(conf *conf.StorageConfig) ([]byte, error) {
	// 生成私钥
	conf.User.Sm2Priv, _ = common.SM2GenerateKey()
	conf.User.SM2PrivkFile = filepath.Join(conf.User.ConfPath, "./smprivk.pem")
	_, err := common.WriteEncSm2Privatekey(conf.User.SM2PrivkFile, conf.User.Sm2Priv, nil)
	if err != nil {
		log.Println("Write privateKey to pem failed","path=",conf.User.SM2PrivkFile,"err=", err)
		return nil, err
	}
	selfcsrfile := filepath.Join(conf.User.ConfPath, "./scsr.pem")
	csr, err := common.SM2CreateCertificateRequest(selfcsrfile, conf.UserName, conf.User.Sm2Priv)
	if err != nil {
		log.Println("create certificate request failed","path = ",selfcsrfile,"err = ", err)
		return nil, err
	}
	return csr, nil
}

func clientExchangeCert(local *conf.StorageConfig, sysinfo common.SystemInfo) error {
	var err error
	var res, decPac []byte
	var csr []byte

	csr, err = prepareCsrAndPrivk(local)
	if err != nil {
		return err
	}
	cmd, e := NewNormalExchangeCertCmd(local.UserName, local.Password, string(csr), sysinfo)
	if e != nil {
		log.Println("NewLoginCmd failed", "err", e.Error())
		return e
	}
	res, err = requestToServer(local, cmd)
	if err != nil {
		return err
	}
	// den
	decPac, err = GetDecryptResponseWithHmac(local.UserName, local.Password, res)
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

	// Todo: 存储证书加密

	// parse res
	var info = &ExchangeCertResponse{}
	if err = json.Unmarshal(decPac, &info); err != nil {
		log.Println("decpac unmarshal to LoginResponse failed.")
		return err
	}
	manager_certdata := []byte(info.ManagerCert)
	local.User.ManagerCert, err = common.SM2ReadCertificateFromMem(manager_certdata)
	if err != nil {
		log.Println("Parse to certificate failed, err ", err)
		return err
	}
	local.User.ManagerCertFile = filepath.Join(local.User.ConfPath, "manager.pem")
	err = ioutil.WriteFile(local.User.ManagerCertFile, manager_certdata, 0755)
	if err != nil {
		log.Println("Write certificate to file failed, err ", err)
	}

	return nil
}

func ClientLogin(local *conf.StorageConfig, sysinfostr string) (*LoginResData, error) {
	var err error
	var res, decPac []byte

	err = checkAndGetUserConfig(local)
	if err != nil {
		return nil, err
	}

	var sysinfo = &common.SystemInfo{}
	err = json.Unmarshal([]byte(sysinfostr), &sysinfo)
	if err != nil {
		log.Println("ClientLogin parse sysinfo failed, sysinfo:", sysinfostr)
		return nil, err
	}
	log.Println("client login sysinfostr", sysinfostr)
	log.Println("client login sysinfo", sysinfo)

	log.Println("goto check exchange cert")
	if needExchangeCert(local) {
		log.Println("need exchange cert.")
		err = clientExchangeCert(local, *sysinfo)
		if err != nil {
			log.Println("exchange cert failed, err ", err)
			return nil, err
		}
		log.Println("exchange cert success, goto login")
	}

	cmd, e := NewLoginCmd(local.UserName, local.Password, local.User.PublicKey, sysinfo.DeviceId, local.User.Sm2Priv, local.User.ManagerCert)
	if cmd == nil {
		log.Println("new login cmd is null")
	}
	if e != nil {
		log.Println("NewLoginCmd failed", "err", e.Error())
		return nil, e
	}
	res, err = requestToServer(local, cmd)
	if err != nil {
		return nil, err
	}
	// den
	decPac, err = GetDecryptResponseWithSign(local.UserName, res, local.User.Sm2Priv, local.User.ManagerCert)
	if err != nil {
		return nil, err
	}

	head := &ServerResponse{}
	if err = json.Unmarshal(decPac, &head); err != nil {
		log.Println("decpac unmarshal to server response failed.")
		return nil, err
	}
	if head.Status != 1 {
		err = errors.New(head.Msg)
		return nil, err
	}
	// parse res
	var info = &LoginResponse{}
	if err = json.Unmarshal(decPac, &info); err != nil {
		log.Println("decpac unmarshal to LoginResponse failed.")
		return nil, err
	}
	local.User.DeviceId = sysinfo.DeviceId

	return &info.LoginResData, nil
}

func ClientLogout(local *conf.StorageConfig, force bool) error {
	var res, decPac []byte
	var err error

	// stop lifetime keeper routine.
	if !force {
		if local.User == nil {
			return nil
		}

		err = checkAndGetUserConfig(local)
		if err != nil {
			return err
		}

		log.Println("client logout, force =", force)
		cmd, _ := NewLogoutCmd(local.UserName, local.User.DeviceId, local.Password, local.User.PublicKey, local.User.Sm2Priv, local.User.ManagerCert)
		res, err = requestToServer(local, cmd)
		log.Println("send to server logout cmd:", hex.EncodeToString(cmd.Data()))
		if err != nil {
			return err
		}
		// den
		decPac, err = GetDecryptResponseWithSign(local.UserName, res, local.User.Sm2Priv, local.User.ManagerCert)
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
	local.User = nil

	return nil
}

func ClientChangePwd(local *conf.StorageConfig, newpwd string) error {

	err := checkAndGetUserConfig(local)
	if err != nil {
		return err
	}

	cmd, _ := NewChangePwdCmd(local.UserName, local.User.DeviceId, local.Password, newpwd, local.User.Sm2Priv, local.User.ManagerCert)
	res, err := requestToServer(local, cmd)
	if err != nil {
		return err
	}
	// den
	decPac, err := GetDecryptResponseWithSign(local.UserName, res, local.User.Sm2Priv, local.User.ManagerCert)
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

func adminExchangeCert(local *conf.StorageConfig, sysinfo common.SystemInfo) error {
	var err error
	var res, decPac []byte
	var csr []byte

	csr, err = prepareCsrAndPrivk(local)
	if err != nil {
		return err
	}
	cmd, e := NewAdminExchangeCertCmd(local.UserName, local.Password, string(csr), sysinfo)
	if e != nil {
		log.Println("NewLoginCmd failed", "err", e.Error())
		return e
	}
	res, err = requestToServer(local, cmd)
	if err != nil {
		return err
	}
	// den
	decPac, err = GetDecryptResponseWithHmac(local.UserName, local.Password, res)
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
	var info = &ExchangeCertResponse{}
	if err = json.Unmarshal(decPac, &info); err != nil {
		log.Println("decpac unmarshal to LoginResponse failed.")
		return err
	}
	manager_certdata := []byte(info.ManagerCert)
	local.User.ManagerCert, err = common.SM2ReadCertificateFromMem(manager_certdata)
	if err != nil {
		log.Println("Parse to certificate failed, err ", err)
		return err
	}
	local.User.ManagerCertFile = filepath.Join(local.User.ConfPath, "manager.pem")
	err = ioutil.WriteFile(local.User.ManagerCertFile, manager_certdata, 0755)
	if err != nil {
		log.Println("Write certificate to file failed, err ", err)
	}

	return nil
}

func AdminLogin(local *conf.StorageConfig, sysinfostr string) (*AdminLoginResData, error) {
	var err error
	var res, decPac []byte

	err = checkAndGetUserConfig(local)
	if err != nil {
		return nil, err
	}

	var sysinfo = &common.SystemInfo{}
	err = json.Unmarshal([]byte(sysinfostr), &sysinfo)
	if err != nil {
		log.Println("ClientLogin parse sysinfo failed, sysinfo:", sysinfostr)
		return nil, err
	}
	log.Println("Admin login sysinfostr", sysinfostr)
	log.Println("Admin login sysinfo", sysinfo)


	if needExchangeCert(local) {
		log.Println("need exchange cert.")
		err = adminExchangeCert(local,*sysinfo)
		if err != nil {
			log.Println("exchange cert failed, err ", err)
			return nil, err
		}
		log.Println("exchange cert success, goto login")
	}

	cmd, _ := NewAdminLoginCmd(local.UserName, local.Password, sysinfo.DeviceId, local.User.Sm2Priv, local.User.ManagerCert)
	res, err = requestToServer(local, cmd)
	if err != nil {
		return nil, err
	}
	// den
	decPac, err = GetDecryptResponseWithSign(local.UserName, res, local.User.Sm2Priv, local.User.ManagerCert)
	if err != nil {
		return nil, err
	}

	head := &ServerResponse{}
	if err = json.Unmarshal(decPac, &head); err != nil {
		log.Println("decpac unmarshal to server response failed.")
		return nil, err
	}
	//log.Printf("decode login response status = %d\n", head.Status)
	if head.Status != 1 {
		err = errors.New(head.Msg)
		return nil, err
	}

	var info = &AdminLoginResponse{}
	if err = json.Unmarshal(decPac, &info); err != nil {
		//log.Println("decpac unmarshal to LoginResponse failed.")
		return nil, err
	}

	return &info.AdminLoginResData, nil
}
