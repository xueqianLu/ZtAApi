package client

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/tjfoc/gmsm/sm2"
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
	MaxReadBuffer  = 1600
)

var (
//LocalConfig = &conf.StorageConfig{}
//gloginData  = &LoginResData{}
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

func GerServerInfo(local *conf.StorageConfig) string {
	return local.ServerAddr + ":" + strconv.Itoa(ServerPort)
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

func NeedExchangeCert(conf *conf.StorageConfig) bool {
	if conf.ManagerCert != nil && conf.Sm2Priv != nil {
		return false
	}
	return true
}

func prepareCsrAndPrivk(conf *conf.StorageConfig) ([]byte, error) {
	// 生成私钥
	conf.Sm2Priv, _ = common.SM2GenerateKey()
	conf.SM2PrivkFile = filepath.Join(conf.ConfPath, "./smprivk.pem")
	_, err := sm2.WritePrivateKeytoPem(conf.SM2PrivkFile, conf.Sm2Priv, nil)
	if err != nil {
		log.Println("Write privateKey to pem failed, err", err)
	}
	csr, err := common.SM2CreateCertificateRequest(conf.UserName, conf.Sm2Priv)
	if err != nil {
		log.Println("create certificate request failed, err ", err)
		return nil, err
	}
	return csr, nil
}

func ClientExchangeCert(local *conf.StorageConfig) error {
	var err error
	var res, decPac []byte
	var csr []byte

	csr, err = prepareCsrAndPrivk(local)
	if err != nil {
		return err
	}
	cmd, e := NewExchangeCertCmd(local.UserName, local.Password, string(csr))
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
	local.ManagerCert, err = common.SM2ReadCertificateFromMem(manager_certdata)
	if err != nil {
		log.Println("Parse to certificate failed, err ", err)
		return err
	}
	local.ManagerCertFile = filepath.Join(local.ConfPath, "manager.pem")
	err = ioutil.WriteFile(local.ManagerCertFile, manager_certdata, 0755)
	if err != nil {
		log.Println("Write certificate to file failed, err ", err)
	}

	return nil
}

func ClientLogin(local *conf.StorageConfig, sysinfostr string) (*LoginResData, error) {
	var err error
	var res, decPac []byte
	log.Println("goto check exchange cert")
	if NeedExchangeCert(local) {
		log.Println("need exchange cert.")
		err = ClientExchangeCert(local)
		if err != nil {
			log.Println("exchange cert failed, err ", err)
			return nil, err
		}
		log.Println("exchange cert success, goto login")
	}

	var sysinfo = &common.SystemInfo{}
	err = json.Unmarshal([]byte(sysinfostr), &sysinfo)
	if err != nil {
		log.Println("ClientLogin parse sysinfo failed, sysinfo:", sysinfostr)
		return nil, err
	}
	log.Println("client login sysinfostr", sysinfostr)
	log.Println("client login sysinfo", sysinfo)

	cmd, e := NewLoginCmd(local.UserName, local.Password, local.PublicKey, sysinfo.DeviceId, *sysinfo, local.Sm2Priv, local.ManagerCert)
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
	decPac, err = GetDecryptResponseWithSign(local.UserName, res, local.Sm2Priv, local.ManagerCert)
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
	// parse res
	var info = &LoginResponse{}
	if err = json.Unmarshal(decPac, &info); err != nil {
		log.Println("decpac unmarshal to LoginResponse failed.")
		return nil, err
	}

	return &info.LoginResData, nil
}

func ClientLogout(local *conf.StorageConfig, force bool) error {
	var res, decPac []byte
	var err error
	// stop lifetime keeper routine.
	if !force {
		log.Println("client logout, force =", force)
		cmd, _ := NewLogoutCmd(local.UserName, local.Password, local.PublicKey, local.Sm2Priv, local.ManagerCert)
		res, err = requestToServer(local, cmd)
		log.Println("send to server logout cmd:", hex.EncodeToString(cmd.Data()))
		if err != nil {
			return err
		}
		// den
		decPac, err = GetDecryptResponseWithSign(local.UserName, res, local.Sm2Priv, local.ManagerCert)
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

func ClientChangePwd(local *conf.StorageConfig, newpwd string) error {
	cmd, _ := NewChangePwdCmd(local.UserName, local.Password, newpwd, local.Sm2Priv, local.ManagerCert)
	res, err := requestToServer(local, cmd)
	if err != nil {
		return err
	}
	// den
	decPac, err := GetDecryptResponseWithSign(local.UserName, res, local.Sm2Priv, local.ManagerCert)
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

func AdminLogin(local *conf.StorageConfig) (*AdminLoginResData, error) {
	var err error

	var res, decPac []byte
	cmd, _ := NewAdminLoginCmd(local.UserName, local.Password, local.Sm2Priv, local.ManagerCert)
	res, err = requestToServer(local, cmd)
	if err != nil {
		return nil, err
	}
	// den
	decPac, err = GetDecryptResponseWithSign(local.UserName, res, local.Sm2Priv, local.ManagerCert)
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
