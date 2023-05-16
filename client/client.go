package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ztasecure-lab/gologin/common"
	"github.com/ztasecure-lab/gologin/conf"
	"io"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	ServerHost     = "127.0.0.1"
	ServerPort     = 36680
	MaxReadBuffer  = 60000
	RequestTimeout = time.Second * 3
)

var (
	writeErr    = errors.New("send packet failed")
	readErr     = errors.New("read packet failed")
	readTimeout = ErrRequestTimeout

	// packet pool
	packetPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, MaxReadBuffer)
			return &b
		},
	}
	timeoutRetry = 2
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
	local.ServerAddr = strings.TrimSpace(serveraddr)
	log.Println("set server addr ", serveraddr)
}

func GetServerInfo(local *conf.StorageConfig) string {
	addr, err := getServerIp(local.ServerAddr)
	if err != nil {
		return ""
	}
	addr = addr + ":" + strconv.Itoa(ServerPort)
	return addr
}

func checkAndGetUserConfig(local *conf.StorageConfig) error {
	var err error
	var userConfigPath string

	defer func() {
		if local.User != nil {
			conf.ClientUserConfigSave(local.User)
		}
	}()
	{
		if len(local.LocalAddr) == 0 {
			conn, err := dialServer(local.ServerAddr)
			if err == nil {
				local.LocalAddr = common.GetIpV4Address(conn.LocalAddr().String())
				log.Println("local ip := ", local.LocalAddr)
				local.LocalMac, _ = common.GetNetIfMac(local.LocalAddr)
				log.Println("local mac := ", local.LocalMac)
				conn.Close()
			}
		}
	}

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

func checkIp(server string) bool {
	addr := strings.Trim(server, " ")
	regStr := `^(([1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.)(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){2}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$`
	if match, _ := regexp.MatchString(regStr, addr); match {
		return true
	}
	return false
}

func dialServer(server string) (net.Conn, error) {
	ip, err := getServerIp(server)
	if err != nil {
		return nil, err
	}
	serverAddr := ip + ":" + strconv.Itoa(ServerPort)
	return net.DialTimeout("udp", serverAddr, time.Second)
}

func getServerIp(server string) (string, error) {
	if checkIp(server) {
		return server, nil
	} else {
		ipaddr, err := net.ResolveIPAddr("ip", server)
		if err != nil {
			return "", err
		} else {
			return ipaddr.String(), nil
		}
	}
}

func requestWithTimeout(conn net.Conn, data []byte, timeout time.Duration) ([]byte, error) {
	//log.Println("write to server ", hex.EncodeToString(cmd.Data()))
	conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(data); err != nil {
		log.Printf("write packet failed:%s\n", err)
		return nil, writeErr
	}
	buffer := packetPool.Get().(*[]byte)
	conn.SetReadDeadline(time.Now().Add(timeout))

	rlen, err := conn.Read(*buffer)
	if err != nil {
		packetPool.Put(buffer)
		//log.Printf("read packet failed:%s\n", err)
		netErr, ok := err.(*net.OpError)
		if ok && netErr.Timeout() {
			return nil, readTimeout
		}
		return nil, readErr
	} else {
		response := make([]byte, rlen)
		copy(response, (*buffer)[:rlen])
		packetPool.Put(buffer)
		return response, nil
	}
}

func requestToServer(local *conf.StorageConfig, cmd Command) ([]byte, error) {
	ip, err := getServerIp(local.ServerAddr)
	if err != nil {
		return []byte{}, errors.New(fmt.Sprintf("can't parsed server %s", local.ServerAddr))
	}

	timeout := RequestTimeout
	retry := 1

	serverAddr := ip + ":" + strconv.Itoa(ServerPort)
	log.Println("request to server", serverAddr)

	var response []byte
	var reserr error
	for i := 0; i < retry; i++ {
		//log.Println("send request times ", i)
		conn, err := net.DialTimeout("udp", serverAddr, timeout)
		if err != nil {
			//log.Println("net.Dial failed, err", err)
			return nil, err
		}

		response, reserr = requestWithTimeout(conn, cmd.Data(), timeout)
		conn.Close()

		if reserr == readTimeout {
			log.Println("request sever timeout")
			continue
		} else {
			break
		}
	}
	return response, reserr
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

	if conf.User.Sm2Priv != nil && managerCert != nil && conf.User.GetLastLoginStatus(conf.User.ServerAddr) {
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

	for retry := 0; retry < timeoutRetry; retry++ {
		cmd, e := NewNormalExchangeCertCmd(local, string(csr), sysinfo)
		if e != nil {
			log.Println("NewLoginCmd failed", "err", e.Error())
			return e
		}
		res, err = requestToServer(local, cmd)
		if err == readTimeout {
			continue
		}
		if err != nil {
			return err
		}
		// den
		decPac, err = GetDecryptResponseWithHmac(local.UserName, cmd.Key2, res)
		if err == common.ErrSM2Decrypt {
			continue
		}
		if err != nil {
			return err
		}
		break
	}

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

	var certData string
	certData += info.SliceInfo
	var reqSliceOffset = info.SliceOffset + 1
	for i := reqSliceOffset; i < info.SliceCount; i++ {
		if certSlice, e := ClientReqCertSlice(local, i); e != nil {
			log.Println("request cert slice failed, e:", e.Error())
			return e
		} else {
			certData += certSlice.SliceInfo
		}
	}
	var certs = &CertResData{}
	if len(certData) > 0 {
		if decodeCerts, ne := common.Base64Decode(certData); ne != nil {
			return errors.New(fmt.Sprintf("decode cert data failed, e:%s", ne.Error()))
		} else {
			//log.Println("after decode base64:", decodeCerts)
			if err = json.Unmarshal(decodeCerts, &certs); err != nil {
				log.Println("exchange certs, unmarshal to certResData failed, ", err.Error())
				return err
			}
		}
	}

	return local.User.SaveManagerCert([]byte(certs.ManagerCert))
}

func updateServerHistory(local *conf.StorageConfig) {
	var history = make([]string, 0)
	var p = make(map[string]int)
	if len(local.ServerAddr) == 0 {
		return
	}
	history = append(history, local.ServerAddr)
	p[local.ServerAddr] = 1
	for _, h := range local.ServerHistory {
		if _, exist := p[h]; !exist {
			history = append(history, h)
			p[h] = 1
		}
	}
	local.ServerHistory = history
}

func ClientLogin(local *conf.StorageConfig, sysinfostr string, verifyCode string, secondVerify string) (*conf.AllConfigInfo, int, error) {
	var err error
	var res, decPac []byte

	err = checkAndGetUserConfig(local)
	if err != nil {
		return nil, 1000, err
	}

	defer func() {
		if err != nil && err == ErrRequestTimeout {
			local.User.SetLoginStatus(local.User.ServerAddr, false)
		} else {
			local.User.SetLoginStatus(local.User.ServerAddr, true)
		}
	}()
	var sysinfo = &common.SystemInfo{}
	err = json.Unmarshal([]byte(sysinfostr), &sysinfo)
	if err != nil {
		log.Println("ClientLogin parse sysinfo failed, sysinfo:", sysinfostr)
		return nil, 1001, err
	}
	local.Sysinfo = sysinfo
	//log.Println("client login sysinfostr", sysinfostr)
	//log.Println("client login sysinfo", sysinfo)

	//log.Println("goto check exchange cert")
	if needExchangeCert(local) {
		log.Println("need exchange cert.")
		err = clientExchangeCert(local, *sysinfo)
		if err != nil {
			log.Println("exchange cert failed, err ", err)
			return nil, 1002, err
		}
		log.Println("exchange cert success, goto login")
	}

	for retry := 0; retry < timeoutRetry; retry++ {
		managerCert := local.User.GetManagerCert(local.ServerAddr)

		local.User.DeviceId = sysinfo.DeviceId
		cmd, e := NewLoginCmd(local, local.PublicKey, sysinfo.DeviceId,
			local.User.Sm2Priv, managerCert, *sysinfo, verifyCode, secondVerify)
		if cmd == nil || e != nil {
			log.Println("NewLoginCmd failed", "err", e.Error())
			return nil, 1003, e
		}

		res, err = requestToServer(local, cmd)
		if err == readTimeout {
			continue
		}
		if err != nil {
			log.Println("request to server err:", err)
			return nil, 1004, err
		}
		// den
		decPac, err = GetDecryptResponseWithSign(local.UserName, res, local.User.Sm2Priv, managerCert)
		if err == common.ErrSM2Decrypt {
			continue
		}
		if err != nil {
			return nil, 1005, err
		}
		break
	}
	if err != nil {
		return nil, 1008, err
	}
	head := &ServerResponse{}
	if err = json.Unmarshal(decPac, &head); err != nil {
		log.Println("decpac unmarshal to server response failed.")
		return nil, 1006, err
	}
	// parse res
	var login = &LoginResponse{}
	if err = json.Unmarshal(decPac, &login); err != nil {
		log.Println("decpac unmarshal to LoginResponse failed.")
		return nil, 1007, err
	}

	//if head.Status != 1 {
	//	msg, _ := common.Base64Decode(head.Msg)
	//	err = errors.New(string(msg))
	//	return nil, head.Status, err
	//}

	var userConfig string
	userConfig += login.SliceInfo
	var reqSliceOffset = login.SliceOffset + 1
	for i := reqSliceOffset; i < login.SliceCount; i++ {
		if configSlice, e := ClientReqSliceInfo(local, i); e != nil {
			log.Println("request userconfig failed, e:", e.Error())
			return nil, 1009, e
		} else {
			userConfig += configSlice.SliceInfo
		}
	}
	allConfigInfo := &conf.AllConfigInfo{}
	allConfigInfo.VerifyType = login.VerifyType

	if len(userConfig) > 0 {
		updateServerHistory(local) // add server to history.
		if decodedConfig, ne := common.Base64Decode(userConfig); ne != nil {
			return nil, 1010, errors.New(fmt.Sprintf("decode userconfig failed, e:%s", ne.Error()))
		} else {
			log.Println("after decode base64:", decodedConfig)
			if err = json.Unmarshal(decodedConfig, &allConfigInfo); err != nil {
				log.Println("user login, unmarshal to allConfigInfo failed.")
				return nil, 1011, err
			}
		}
	}
	if head.Status != 1 {
		msg, _ := common.Base64Decode(head.Msg)
		err = errors.New(string(msg))
	}

	return allConfigInfo, head.Status, err
}

func ClientLoginWithToken(local *conf.StorageConfig, sysinfostr string, verifyCode string, secondVerify string, token string) (*conf.AllConfigInfo, int, error) {
	var err error
	var res, decPac []byte

	err = checkAndGetUserConfig(local)
	if err != nil {
		return nil, 1000, err
	}

	var sysinfo = &common.SystemInfo{}
	err = json.Unmarshal([]byte(sysinfostr), &sysinfo)
	if err != nil {
		log.Println("ClientLogin parse sysinfo failed, sysinfo:", sysinfostr)
		return nil, 1001, err
	}
	local.Sysinfo = sysinfo
	//log.Println("client login sysinfostr", sysinfostr)
	//log.Println("client login sysinfo", sysinfo)

	//log.Println("goto check exchange cert")
	if needExchangeCert(local) {
		log.Println("need exchange cert.")
		err = clientExchangeCert(local, *sysinfo)
		if err != nil {
			log.Println("exchange cert failed, err ", err)
			return nil, 1002, err
		}
		log.Println("exchange cert success, goto login")
	}

	for retry := 0; retry < timeoutRetry; retry++ {
		managerCert := local.User.GetManagerCert(local.ServerAddr)

		local.User.DeviceId = sysinfo.DeviceId

		cmd, e := NewLoginCmdWithToken(local, local.PublicKey, sysinfo.DeviceId,
			local.User.Sm2Priv, managerCert, *sysinfo, verifyCode, secondVerify, token)
		if cmd == nil || e != nil {
			log.Println("NewLoginCmd failed", "err", e.Error())
			return nil, 1003, e
		}

		res, err = requestToServer(local, cmd)
		if err == readTimeout {
			continue
		}
		if err != nil {
			log.Println("request to server err:", err)
			return nil, 1004, err
		}
		// den
		decPac, err = GetDecryptResponseWithSign(local.UserName, res, local.User.Sm2Priv, managerCert)
		if err == common.ErrSM2Decrypt {
			continue
		}
		if err != nil {
			return nil, 1005, err
		}
		break
	}
	if err != nil {
		return nil, 1008, err
	}
	head := &ServerResponse{}
	if err = json.Unmarshal(decPac, &head); err != nil {
		log.Println("decpac unmarshal to server response failed.")
		return nil, 1006, err
	}
	// parse res
	var login = &LoginResponse{}
	if err = json.Unmarshal(decPac, &login); err != nil {
		log.Println("decpac unmarshal to LoginResponse failed.")
		return nil, 1007, err
	}

	//if head.Status != 1 {
	//	msg, _ := common.Base64Decode(head.Msg)
	//	err = errors.New(string(msg))
	//	return nil, head.Status, err
	//}

	var userConfig string
	userConfig += login.SliceInfo
	var reqSliceOffset = login.SliceOffset + 1
	for i := reqSliceOffset; i < login.SliceCount; i++ {
		if configSlice, e := ClientReqSliceInfo(local, i); e != nil {
			log.Println("request userconfig failed, e:", e.Error())
			return nil, 1009, e
		} else {
			userConfig += configSlice.SliceInfo
		}
	}
	allConfigInfo := &conf.AllConfigInfo{}
	allConfigInfo.VerifyType = login.VerifyType

	if len(userConfig) > 0 {
		updateServerHistory(local) // add server to history.
		if decodedConfig, ne := common.Base64Decode(userConfig); ne != nil {
			return nil, 1010, errors.New(fmt.Sprintf("decode userconfig failed, e:%s", ne.Error()))
		} else {
			log.Println("after decode base64:", decodedConfig)
			if err = json.Unmarshal(decodedConfig, &allConfigInfo); err != nil {
				log.Println("user login, unmarshal to allConfigInfo failed.")
				return nil, 1011, err
			}
		}
	}
	if head.Status != 1 {
		msg, _ := common.Base64Decode(head.Msg)
		err = errors.New(string(msg))
	}

	return allConfigInfo, head.Status, err
}

func ClientLogout(local *conf.StorageConfig, force bool) error {
	//var res, decPac []byte
	var err error

	// stop lifetime keeper routine.
	if true {
		if local.User == nil {
			return nil
		}

		err = checkAndGetUserConfig(local)
		if err != nil {
			return err
		}

		log.Println("client logout, force =", force)
		for retry := 0; retry < timeoutRetry; retry++ {
			managerCert := local.User.GetManagerCert(local.ServerAddr)
			cmd, _ := NewLogoutCmd(local, local.User.DeviceId, local.PublicKey, local.User.Sm2Priv, managerCert)
			_, err = requestToServer(local, cmd)
			if err == readTimeout {
				// if request timeout , resend.
				continue
			}
			//if err != nil {
			//	return err
			//}
			// den
			//decPac, err = GetDecryptResponseWithSign(local.UserName, res, local.User.Sm2Priv, managerCert)
			//if err != nil {
			//	return err
			//}
		}
		//head := &ServerResponse{}
		//if err = json.Unmarshal(decPac, &head); err != nil {
		//	log.Println("decpac unmarshal to server response failed.")
		//	return err
		//}
		//if head.Status != 1 {
		//	msg, _ := common.Base64Decode(head.Msg)
		//	err = errors.New(string(msg))
		//	return err
		//}
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
	var res, decPac []byte
	for retry := 0; retry < timeoutRetry; retry++ {
		managerCert := local.User.GetManagerCert(local.ServerAddr)
		cmd, _ := NewChangePwdCmd(local, local.User.DeviceId, newpwd, local.User.Sm2Priv, managerCert)
		res, err = requestToServer(local, cmd)
		if err == readTimeout {
			continue
		}
		if err != nil {
			return err
		}
		// den
		decPac, err = GetDecryptResponseWithSign(local.UserName, res, local.User.Sm2Priv, managerCert)
		if err == common.ErrSM2Decrypt {
			continue
		}
		if err != nil {
			return err
		}
		break
	}
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
	var res, decPac []byte
	for retry := 0; retry < timeoutRetry; retry++ {
		managerCert := local.User.GetManagerCert(local.ServerAddr)
		cmd, _ := NewReqUserHomeCmd(local, local.User.DeviceId, local.User.Sm2Priv, managerCert)
		res, err = requestToServer(local, cmd)
		if err == readTimeout {
			continue
		}
		if err != nil {
			return nil, err
		}
		// den
		decPac, err = GetDecryptResponseWithSign(local.UserName, res, local.User.Sm2Priv, managerCert)
		if err == common.ErrSM2Decrypt {
			continue
		}
		if err != nil {
			return nil, err
		}
		break
	}
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

func ClientReqToken(local *conf.StorageConfig) (*UserTokenResData, error) {

	err := checkAndGetUserConfig(local)
	if err != nil {
		return nil, err
	}
	var res, decPac []byte
	for retry := 0; retry < timeoutRetry; retry++ {
		managerCert := local.User.GetManagerCert(local.ServerAddr)
		cmd, _ := NewReqUserTokenCmd(local, local.User.DeviceId, local.User.Sm2Priv, managerCert)
		res, err = requestToServer(local, cmd)
		if err == readTimeout {
			continue
		}
		if err != nil {
			return nil, err
		}
		// den
		decPac, err = GetDecryptResponseWithSign(local.UserName, res, local.User.Sm2Priv, managerCert)
		if err == common.ErrSM2Decrypt {
			continue
		}
		if err != nil {
			return nil, err
		}
		break
	}
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
	var response = &UserTokenResponse{}
	if err = json.Unmarshal(decPac, &response); err != nil {
		log.Println("decpac unmarshal to LoginResponse failed.")
		return nil, err
	}
	return &response.UserTokenResData, nil
}

func ClientReqSwitchNetwork(local *conf.StorageConfig, mode int) (*SwitchNetworkResData, error) {

	err := checkAndGetUserConfig(local)
	if err != nil {
		return nil, err
	}
	var res, decPac []byte
	for retry := 0; retry < timeoutRetry; retry++ {
		managerCert := local.User.GetManagerCert(local.ServerAddr)
		cmd, _ := NewReqSwitchNetworkCmd(local, local.User.DeviceId, mode, local.User.Sm2Priv, local.PublicKey, managerCert)
		res, err = requestToServer(local, cmd)
		if err == ErrRequestTimeout {
			continue
		}
		if err != nil {
			return nil, err
		}
		// den
		decPac, err = GetDecryptResponseWithSign(local.UserName, res, local.User.Sm2Priv, managerCert)
		if err == common.ErrSM2Decrypt {
			continue
		}
		if err != nil {
			return nil, err
		}
		break
	}
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
	var response = &SwitchNetworkResponse{}
	if err = json.Unmarshal(decPac, &response); err != nil {
		log.Println("decpac unmarshal to LoginResponse failed.")
		return nil, err
	}
	return &response.SwitchNetworkResData, nil
}

func ClientReqCertSlice(local *conf.StorageConfig, offset int) (*SliceInfoResData, error) {
	var err error
	var res, decPac []byte
	var csr []byte

	csr = local.User.GetScsrData()
	if csr == nil {
		return nil, errors.New("have no scsr data")
	}

	for retry := 0; retry < timeoutRetry; retry++ {
		cmd, e := NewNormalReqCertSliceCmd(local.UserName, local.Password, offset, *local.Sysinfo)
		if e != nil {
			log.Println("NewReqCertSliceCmd failed", "err", e.Error())
			return nil, e
		}
		res, err = requestToServer(local, cmd)
		if err == readTimeout {
			continue
		}
		if err != nil {
			return nil, err
		}
		// den
		decPac, err = GetDecryptResponseWithHmac(local.UserName, cmd.Key2, res)
		if err == common.ErrSM2Decrypt {
			continue
		}
		if err != nil {
			return nil, err
		}

		break
	}
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

	// parse res
	var info = &ExchangeCertResponse{}
	if err = json.Unmarshal(decPac, &info); err != nil {
		log.Println("decpac unmarshal to LoginResponse failed.")
		return nil, err
	}
	return &info.SliceInfoResData, nil
}

func ClientReqSliceInfo(local *conf.StorageConfig, offset int) (*SliceInfoResData, error) {

	err := checkAndGetUserConfig(local)
	if err != nil {
		return nil, err
	}
	var res, decPac []byte
	for retry := 0; retry < timeoutRetry; retry++ {
		managerCert := local.User.GetManagerCert(local.ServerAddr)
		cmd, _ := NewReqUserInfoCmd(local, local.User.DeviceId, offset, local.User.Sm2Priv, managerCert)
		res, err = requestToServer(local, cmd)
		if err == readTimeout {
			continue
		}
		if err != nil {
			return nil, err
		}
		// den
		decPac, err = GetDecryptResponseWithSign(local.UserName, res, local.User.Sm2Priv, managerCert)
		if err == common.ErrSM2Decrypt {
			continue
		}
		if err != nil {
			return nil, err
		}
		break
	}
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

func ClientRegetVerifyCode(local *conf.StorageConfig) error {

	err := checkAndGetUserConfig(local)
	if err != nil {
		return err
	}
	var res, decPac []byte
	for retry := 0; retry < timeoutRetry; retry++ {
		managerCert := local.User.GetManagerCert(local.ServerAddr)
		cmd, _ := NewRegetVerifyCodeCmd(local, local.User.DeviceId, local.User.Sm2Priv, managerCert, *local.Sysinfo)
		res, err = requestToServer(local, cmd)
		if err == readTimeout {
			continue
		}
		if err != nil {
			return err
		}
		// den
		decPac, err = GetDecryptResponseWithSign(local.UserName, res, local.User.Sm2Priv, managerCert)
		if err == common.ErrSM2Decrypt {
			continue
		}
		if err != nil {
			return err
		}
		break
	}
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

func adminExchangeCert(local *conf.StorageConfig, sysinfo common.SystemInfo) error {
	var err error
	var res, decPac []byte
	var csr []byte

	csr = local.User.GetScsrData()
	if csr == nil {
		return errors.New("have no scsr data")
	}

	for retry := 0; retry < timeoutRetry; retry++ {
		cmd, e := NewAdminExchangeCertCmd(local, string(csr), sysinfo)
		if e != nil {
			log.Println("NewLoginCmd failed", "err", e.Error())
			return e
		}
		res, err = requestToServer(local, cmd)
		if err == readTimeout {
			continue
		}
		if err != nil {
			return err
		}
		// den
		decPac, err = GetDecryptResponseWithHmac(local.UserName, cmd.Key2, res)
		if err == common.ErrSM2Decrypt {
			continue
		}
		if err != nil {
			return err
		}
		break
	}
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

	var certData string
	certData += info.SliceInfo
	var reqSliceOffset = info.SliceOffset + 1
	for i := reqSliceOffset; i < info.SliceCount; i++ {
		if certSlice, e := AdminReqCertSlice(local, i); e != nil {
			return errors.New(fmt.Sprintf("request userconfig failed, e:%s", e.Error()))
		} else {
			certData += certSlice.SliceInfo
		}
	}
	var certs = &CertResData{}
	if len(certData) > 0 {
		if decodeCerts, ne := common.Base64Decode(certData); ne != nil {
			return errors.New(fmt.Sprintf("decode cert data failed, e:%s", ne.Error()))
		} else {
			log.Println("after decode base64:", decodeCerts)
			if err = json.Unmarshal(decodeCerts, &certs); err != nil {
				log.Println("exchange certs, unmarshal to certResData failed, ", err.Error())
				return err
			}
		}
	}

	return local.User.SaveManagerCert([]byte(certs.ManagerCert))
}

func AdminLogin(local *conf.StorageConfig, sysinfostr string, verifyCode string) (*AdminLoginResData, error) {
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
	local.Sysinfo = sysinfo

	if needExchangeCert(local) {
		log.Println("need exchange cert.")
		err = adminExchangeCert(local, *sysinfo)
		if err != nil {
			log.Println("exchange cert failed, err ", err)
			return nil, err
		}
		log.Println("exchange cert success, goto login")
	}
	for retry := 0; retry < timeoutRetry; retry++ {
		managerCert := local.User.GetManagerCert(local.ServerAddr)
		cmd, _ := NewAdminLoginCmd(local, sysinfo.DeviceId,
			local.User.Sm2Priv, managerCert, *sysinfo, verifyCode, false)
		res, err = requestToServer(local, cmd)
		if err == readTimeout {
			continue
		}
		if err != nil {
			return nil, err
		}
		// den
		decPac, err = GetDecryptResponseWithSign(local.UserName, res, local.User.Sm2Priv, managerCert)
		if err == common.ErrSM2Decrypt {
			continue
		}
		if err != nil {
			return nil, err
		}
		break
	}
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

func AdminHomeUrl(local *conf.StorageConfig, sysinfostr string) (*AdminLoginResData, error) {
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
		return nil, errors.New("need exchange cert first")
	}
	for retry := 0; retry < timeoutRetry; retry++ {
		managerCert := local.User.GetManagerCert(local.ServerAddr)
		cmd, _ := NewAdminLoginCmd(local, sysinfo.DeviceId,
			local.User.Sm2Priv, managerCert, *sysinfo, "", true)
		res, err = requestToServer(local, cmd)
		if err == readTimeout {
			continue
		}
		if err != nil {
			return nil, err
		}
		// den
		decPac, err = GetDecryptResponseWithSign(local.UserName, res, local.User.Sm2Priv, managerCert)
		if err == common.ErrSM2Decrypt {
			continue
		}
		if err != nil {
			return nil, err
		}
		break
	}
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

func AdminRegetVerifyCode(local *conf.StorageConfig) error {

	err := checkAndGetUserConfig(local)
	if err != nil {
		return err
	}
	var res, decPac []byte
	for retry := 0; retry < timeoutRetry; retry++ {
		managerCert := local.User.GetManagerCert(local.ServerAddr)
		cmd, _ := NewAdminRegetVerifyCodeCmd(local, local.User.DeviceId, local.User.Sm2Priv, managerCert, *local.Sysinfo)
		res, err = requestToServer(local, cmd)
		if err == readTimeout {
			continue
		}
		if err != nil {
			return err
		}
		// den
		decPac, err = GetDecryptResponseWithSign(local.UserName, res, local.User.Sm2Priv, managerCert)
		if err == common.ErrSM2Decrypt {
			continue
		}
		if err != nil {
			return err
		}
		break
	}
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

func AdminReqCertSlice(local *conf.StorageConfig, offset int) (*SliceInfoResData, error) {
	var err error
	var res, decPac []byte
	var csr []byte

	csr = local.User.GetScsrData()
	if csr == nil {
		return nil, errors.New("have no scsr data")
	}
	for retry := 0; retry < timeoutRetry; retry++ {
		cmd, e := NewAdminReqCertSliceCmd(local.UserName, local.Password, offset, *local.Sysinfo)
		if e != nil {
			log.Println("NewAdminReqCertSliceCmd failed", "err", e.Error())
			return nil, e
		}
		res, err = requestToServer(local, cmd)
		if err == readTimeout {
			continue
		}
		if err != nil {
			return nil, err
		}
		// den
		decPac, err = GetDecryptResponseWithHmac(local.UserName, cmd.Key2, res)
		if err == common.ErrSM2Decrypt {
			continue
		}
		if err != nil {
			return nil, err
		}
		break
	}
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

	// parse res
	var info = &ExchangeCertResponse{}
	if err = json.Unmarshal(decPac, &info); err != nil {
		log.Println("decpac unmarshal to LoginResponse failed.")
		return nil, err
	}
	return &info.SliceInfoResData, nil
}
