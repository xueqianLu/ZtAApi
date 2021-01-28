package client

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/xueqianLu/ZtAApi/common"
	"github.com/xueqianLu/ZtAApi/conf"
	"io"
	"log"
	"net"
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

	if local.User != nil && local.UserName == local.User.UserName {
		local.User.ServerAddr = local.ServerAddr
		return nil
	} else {
		if local.User != nil {
			conf.ClientUserConfigSave(local.User)
		}
		userConfigPath, err = conf.GetUserConfigPath(local)
		local.User, err = conf.GetUserLocalConfig(userConfigPath, local.UserName, local.ServerAddr)
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
	//log.Println("write to server ", hex.EncodeToString(cmd.Data()))
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
		//log.Println("read msg from server len", readLen, "msg", hex.EncodeToString(msg))
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
	managerCert := conf.User.GetManagerCert(conf.User.ServerAddr)
	if conf.User.Sm2Priv != nil && managerCert != nil {
		return false
	}
	return true
}

func clientExchangeCert(local *conf.StorageConfig, sysinfo common.SystemInfo) error {
	var err error
	var res, decPac []byte
	var csr []byte

	csr = local.User.GetScsrData()
	if csr == nil {
		return errors.New("have no scsr data")
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
	decPac, err = GetDecryptResponseWithHmac(local.UserName, cmd.Key2, res)
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
		msg, _ := common.Base64Decode(head.Msg)
		err = errors.New(string(msg))
		return err
	}

	// parse res
	var info = &ExchangeCertResponse{}
	if err = json.Unmarshal(decPac, &info); err != nil {
		log.Println("decpac unmarshal to LoginResponse failed.")
		return err
	}
	return local.User.SaveManagerCert([]byte(info.ManagerCert))
}

func ClientLogin(local *conf.StorageConfig, sysinfostr string) (*conf.AllConfigInfo, error) {
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
	//log.Println("client login sysinfostr", sysinfostr)
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
	managerCert := local.User.GetManagerCert(local.ServerAddr)

	cmd, e := NewLoginCmd(local.UserName, local.Password, local.PublicKey, sysinfo.DeviceId,
		local.User.Sm2Priv, managerCert, *sysinfo)
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
	decPac, err = GetDecryptResponseWithSign(local.UserName, res, local.User.Sm2Priv, managerCert)
	if err != nil {
		return nil, err
	}

	head := &ServerResponse{}
	if err = json.Unmarshal(decPac, &head); err != nil {
		log.Println("decpac unmarshal to server response failed.")
		return nil, err
	}
	if head.Status != 1 {
		msg, _ := common.Base64Decode(head.Msg)
		err = errors.New(string(msg))
		return nil, err
	}
	// parse res
	var login = &LoginResponse{}
	if err = json.Unmarshal(decPac, &login); err != nil {
		log.Println("decpac unmarshal to LoginResponse failed.")
		return nil, err
	}

	if login.VerifyType != "" {
		// 如果用户需要登录验证，则停止获取后续信息，输入验证码后重新登录.
		allConfigInfo := &conf.AllConfigInfo{}
		allConfigInfo.VerifyType = login.VerifyType
		return allConfigInfo, nil
	}

	local.User.DeviceId = sysinfo.DeviceId
	var userConfig string
	userConfig += login.SliceInfo
	var reqSliceOffset = login.SliceOffset + 1
	for i := reqSliceOffset; i < login.SliceCount; i++ {
		if configSlice, e := ClientReqSliceInfo(local, i); e != nil {
			return nil, errors.New(fmt.Sprintf("request userconfig failed, e:%s", e.Error()))
		} else {
			userConfig += configSlice.SliceInfo
		}
	}

	allConfigInfo := &conf.AllConfigInfo{}
	if decodedConfig, ne := common.Base64Decode(userConfig); ne != nil {
		return nil, errors.New(fmt.Sprintf("decode userconfig failed, e:%s", ne.Error()))
	} else {
		log.Println("after decode base64:", decodedConfig)
		if err = json.Unmarshal(decodedConfig, &allConfigInfo); err != nil {
			log.Println("user login, unmarshal to allConfigInfo failed.")
			return nil, err
		}
	}
	return allConfigInfo, nil
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
		managerCert := local.User.GetManagerCert(local.ServerAddr)
		cmd, _ := NewLogoutCmd(local.UserName, local.User.DeviceId, local.Password, local.PublicKey, local.User.Sm2Priv, managerCert)
		res, err = requestToServer(local, cmd)
		log.Println("send to server logout cmd:", hex.EncodeToString(cmd.Data()))
		if err != nil {
			return err
		}
		// den
		decPac, err = GetDecryptResponseWithSign(local.UserName, res, local.User.Sm2Priv, managerCert)
		if err != nil {
			return err
		}

		head := &ServerResponse{}
		if err = json.Unmarshal(decPac, &head); err != nil {
			log.Println("decpac unmarshal to server response failed.")
			return err
		}
		if head.Status != 1 {
			msg, _ := common.Base64Decode(head.Msg)
			err = errors.New(string(msg))
			return err
		}
	}
	if local.User != nil {
		conf.ClientUserConfigSave(local.User)
	}
	local.User = nil

	return nil
}

func ClientChangePwd(local *conf.StorageConfig, newpwd string) error {

	err := checkAndGetUserConfig(local)
	if err != nil {
		return err
	}
	managerCert := local.User.GetManagerCert(local.ServerAddr)
	cmd, _ := NewChangePwdCmd(local.UserName, local.User.DeviceId, local.Password, newpwd, local.User.Sm2Priv, managerCert)
	res, err := requestToServer(local, cmd)
	if err != nil {
		return err
	}
	// den
	decPac, err := GetDecryptResponseWithSign(local.UserName, res, local.User.Sm2Priv, managerCert)
	if err != nil {
		return err
	}

	head := &ServerResponse{}
	if err = json.Unmarshal(decPac, &head); err != nil {
		log.Println("decpac unmarshal to server response failed.")
		return err
	}
	if head.Status != 1 {
		msg, _ := common.Base64Decode(head.Msg)
		err = errors.New(string(msg))
		return err
	}
	return nil
}

func ClientReqHome(local *conf.StorageConfig) (*UserHomeResData, error) {

	err := checkAndGetUserConfig(local)
	if err != nil {
		return nil, err
	}
	managerCert := local.User.GetManagerCert(local.ServerAddr)
	cmd, _ := NewReqUserHomeCmd(local.UserName, local.Password, local.User.DeviceId, local.User.Sm2Priv, managerCert)
	res, err := requestToServer(local, cmd)
	if err != nil {
		return nil, err
	}
	// den
	decPac, err := GetDecryptResponseWithSign(local.UserName, res, local.User.Sm2Priv, managerCert)
	if err != nil {
		return nil, err
	}

	head := &ServerResponse{}
	if err = json.Unmarshal(decPac, &head); err != nil {
		log.Println("decpac unmarshal to server response failed.")
		return nil, err
	}
	if head.Status != 1 {
		msg, _ := common.Base64Decode(head.Msg)
		err = errors.New(string(msg))
		return nil, err
	}
	// parse res
	var response = &UserHomeResponse{}
	if err = json.Unmarshal(decPac, &response); err != nil {
		log.Println("decpac unmarshal to LoginResponse failed.")
		return nil, err
	}
	return &response.UserHomeResData, nil
}

func ClientReqSliceInfo(local *conf.StorageConfig, offset int) (*SliceInfoResData, error) {

	err := checkAndGetUserConfig(local)
	if err != nil {
		return nil, err
	}
	managerCert := local.User.GetManagerCert(local.ServerAddr)
	cmd, _ := NewReqUserInfoCmd(local.UserName, local.Password, local.User.DeviceId, offset, local.User.Sm2Priv, managerCert)
	res, err := requestToServer(local, cmd)
	if err != nil {
		return nil, err
	}
	// den
	decPac, err := GetDecryptResponseWithSign(local.UserName, res, local.User.Sm2Priv, managerCert)
	if err != nil {
		return nil, err
	}

	head := &ServerResponse{}
	if err = json.Unmarshal(decPac, &head); err != nil {
		log.Println("decpac unmarshal to server response failed.")
		return nil, err
	}
	if head.Status != 1 {
		msg, _ := common.Base64Decode(head.Msg)
		err = errors.New(string(msg))
		return nil, err
	}
	// parse res
	var slist = &UserInfoResponse{}
	if err = json.Unmarshal(decPac, &slist); err != nil {
		log.Println("decpac unmarshal to LoginResponse failed.")
		return nil, err
	}
	return &slist.SliceInfoResData, nil
}

func adminExchangeCert(local *conf.StorageConfig, sysinfo common.SystemInfo) error {
	var err error
	var res, decPac []byte
	var csr []byte

	csr = local.User.GetScsrData()
	if csr == nil {
		return errors.New("have no scsr data")
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
	decPac, err = GetDecryptResponseWithHmac(local.UserName, cmd.Key2, res)
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
		msg, _ := common.Base64Decode(head.Msg)
		err = errors.New(string(msg))
		return err
	}
	// parse res
	var info = &ExchangeCertResponse{}
	if err = json.Unmarshal(decPac, &info); err != nil {
		log.Println("decpac unmarshal to LoginResponse failed.")
		return err
	}
	return local.User.SaveManagerCert([]byte(info.ManagerCert))
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
		err = adminExchangeCert(local, *sysinfo)
		if err != nil {
			log.Println("exchange cert failed, err ", err)
			return nil, err
		}
		log.Println("exchange cert success, goto login")
	}
	managerCert := local.User.GetManagerCert(local.ServerAddr)
	cmd, _ := NewAdminLoginCmd(local.UserName, local.Password, sysinfo.DeviceId,
		local.User.Sm2Priv, managerCert, *sysinfo)
	res, err = requestToServer(local, cmd)
	if err != nil {
		return nil, err
	}
	// den
	decPac, err = GetDecryptResponseWithSign(local.UserName, res, local.User.Sm2Priv, managerCert)
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
		msg, _ := common.Base64Decode(head.Msg)
		err = errors.New(string(msg))
		return nil, err
	}

	var info = &AdminLoginResponse{}
	if err = json.Unmarshal(decPac, &info); err != nil {
		//log.Println("decpac unmarshal to LoginResponse failed.")
		return nil, err
	}

	return &info.AdminLoginResData, nil
}
