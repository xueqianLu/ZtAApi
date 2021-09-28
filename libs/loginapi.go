package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/xueqianLu/ZtAApi/client"
	"github.com/xueqianLu/ZtAApi/common"
	"github.com/xueqianLu/ZtAApi/conf"
	"io/ioutil"
	"log"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

const (
	ServerHost     = "127.0.0.1"
	ServerPort     = 36680
	RequestTimeout = 10 * time.Second
	MaxReadBuffer  = 60000
)

var (
	configPath      = "config"
	managerCertPath = "manager.pem"
	csrPath         = "client.csr"
	sm2privPath     = "priv.key"
	certsInfo       = "certs.json"
	userkeyPath     = "user.json"

	userConfigs = sync.Map{} //make(map[string]*userInfo)

	globaConfig = &Config{}

	configMux = sync.Mutex{}
)

type userkey struct {
	Name string `json:"name"`
	Priv string `json:"priv"`
}

type Alluserkey struct {
	Alluser []userkey `json:"data"`
}

type CertInfo struct {
	Server        string   `json:"server"`
	Path          string   `json:"path"`
	ExchangedUser []string `json:"exchanged-user"`
	Cert          *sm2.Certificate
}

type Config struct {
	CertsInfo sync.Map //map[string]*CertInfo
	Sm2Priv   *sm2.PrivateKey
	Sm2Public *sm2.PublicKey
	csr       []byte
	userPriv  sync.Map
	sysinfo   *common.SystemInfo
	//reExchange  bool
}

type userInfo struct {
	username    string
	password    string
	server      string
	privk       *conf.Key
	managerCert map[string]*sm2.Certificate
	Sm2Priv     *sm2.PrivateKey
	Sm2Public   *sm2.PublicKey
	csr         []byte
	sysinfo     *common.SystemInfo
}

func GetManagerCertPath(server string) string {
	return filepath.Join(configPath, fmt.Sprintf("%s-%s", server, managerCertPath))
}
func GetCSRPath() string {
	return filepath.Join(configPath, csrPath)
}
func GetSMPrivPath() string {
	return filepath.Join(configPath, sm2privPath)
}
func GetUserKeyPath() string {
	return filepath.Join(configPath, userkeyPath)
}
func GetCertsInfoPath() string {
	return filepath.Join(configPath, certsInfo)
}

func loadCertsInfo(config *Config) error {
	file := GetCertsInfoPath()
	var infos []CertInfo
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, &infos)
	if err != nil {
		LError.Println("unmarshal cert info failed, err:", err)
		return err
	}
	for _, info := range infos {
		if certdata, err := ioutil.ReadFile(info.Path); err != nil {
			log.Println("read manager cert ", info.Path, " failed, err ", err.Error())
		} else {
			if info.Cert, err = common.SM2ReadCertificateFromMem(certdata); err != nil {
				log.Println("ReadCert from data failed, err ", err)
			}
		}
		if info.Cert != nil {
			ninfo := &CertInfo{
				Server:        info.Server,
				Path:          info.Path,
				ExchangedUser: info.ExchangedUser,
				Cert:          info.Cert,
			}
			config.CertsInfo.Store(info.Server, ninfo)
		}
	}
	return nil
}

func addCertInfo(server, user string, cert *sm2.Certificate) {

	config := globaConfig
	if info, exist := config.CertsInfo.Load(server); !exist {
		ninfo := &CertInfo{
			Server:        server,
			Path:          GetManagerCertPath(server),
			ExchangedUser: make([]string, 0),
			Cert:          cert,
		}
		ninfo.ExchangedUser = append(ninfo.ExchangedUser, user)
		config.CertsInfo.Store(server, ninfo)
	} else {
		ninfo := info.(*CertInfo)
		ninfo.ExchangedUser = append(ninfo.ExchangedUser, user)
	}
	saveCertInfo(config)
}

func saveCertInfo(config *Config) error {
	file := GetCertsInfoPath()
	data, err := json.Marshal(config.CertsInfo)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(file, data, 0755)
}

func userHaveCert(config *Config, server, username string) bool {
	if info, exist := config.CertsInfo.Load(server); exist {
		ninfo := info.(*CertInfo)
		for _, name := range ninfo.ExchangedUser {
			if name == username {
				return true
			}
		}
	}
	return false
}

func getCert(config *Config, server string) *sm2.Certificate {
	if info, exist := config.CertsInfo.Load(server); exist {
		ninfo := info.(*CertInfo)
		return ninfo.Cert
	}
	return nil
}

func saveUserkey(config *Config) error {
	var allUser Alluserkey
	allUser.Alluser = make([]userkey, 0)
	config.userPriv.Range(func(key, value interface{}) bool {
		upriv := value.(*conf.Key)

		uk := userkey{Name: key.(string), Priv: common.ToHex(upriv[:])}
		allUser.Alluser = append(allUser.Alluser, uk)
		return true
	})
	data, e := json.Marshal(allUser)
	if e != nil {
		return e
	}
	log.Println("save user key with data ", string(data))
	ioutil.WriteFile(GetUserKeyPath(), data, 0755)
	return nil
}

func loadOrGenerate(config *Config) error {
	var reGenCSR = false
	var reExchange = false

	// load user private key
	{
		var allUser Alluserkey
		data, err := ioutil.ReadFile(GetUserKeyPath())
		if err == nil {
			err = json.Unmarshal(data, &allUser)
			if err == nil {
				for _, d := range allUser.Alluser {
					k := &conf.Key{}
					uk := common.FromHex(d.Priv)
					copy(k[:], uk)
					config.userPriv.Store(d.Name, k)
				}
			}
		}
	}

	// load privkey
	privk, err := common.ReadEncSm2PrivateKey(GetSMPrivPath(), []byte("12345678"))
	if err != nil {
		// generate and save privatekey
		privk, _ = common.SM2GenerateKey()
		config.Sm2Priv = privk
		common.WriteEncSm2Privatekey(GetSMPrivPath(), privk, []byte("12345678"))
		reGenCSR = true
		reExchange = true
	} else {
		config.Sm2Priv = privk
	}
	config.Sm2Public = &config.Sm2Priv.PublicKey

	// load csr
	config.csr, err = ioutil.ReadFile(GetCSRPath())
	if err != nil || reGenCSR {
		csr, err := common.SM2CreateCertificateRequest(GetCSRPath(), "sdp", config.Sm2Priv)
		if err != nil {
			log.Println("create certificate request failed", "path = ", GetCSRPath(), "err = ", err)
			return err
		}
		config.csr = csr
		reExchange = true
	}
	if !reExchange {
		loadCertsInfo(config)
	}

	return nil
}

func checkAndGetUserConfig(user string, password string, server string, ninfo *userInfo, allconfig *Config) error {
	configMux.Lock()
	if globaConfig.Sm2Priv == nil {
		loadOrGenerate(globaConfig)
	}
	configMux.Unlock()

	var err error
	if data, exist := userConfigs.Load(user); !exist {
		ninfo.managerCert = make(map[string]*sm2.Certificate)
		if userHaveCert(allconfig, server, user) {
			ninfo.managerCert[server] = getCert(allconfig, server)
		}
		ninfo.username = user
		ninfo.password = password
		ninfo.server = server
		ninfo.Sm2Priv = globaConfig.Sm2Priv
		ninfo.Sm2Public = &ninfo.Sm2Priv.PublicKey
		ninfo.csr = globaConfig.csr
		userConfigs.Store(user, ninfo)
		if k, ok := globaConfig.userPriv.Load(user); ok {
			fmt.Println("user use exist privatekey")
			ninfo.privk = k.(*conf.Key)
		} else {
			fmt.Println("user create new privatekey")
			ninfo.privk, _ = conf.NewPrivateKey()
			globaConfig.userPriv.Store(user, ninfo.privk)
			saveUserkey(globaConfig)
		}
	} else {
		info := data.(*userInfo)
		ninfo.managerCert = info.managerCert
		ninfo.password = password
		ninfo.server = server
		ninfo.csr = info.csr
		ninfo.privk = info.privk
		ninfo.Sm2Priv = info.Sm2Priv
		ninfo.Sm2Public = info.Sm2Public
		ninfo.username = info.username
	}
	return err
}

func requestWithTimeout(conn net.Conn, data []byte, timeout time.Duration) ([]byte, error) {
	//log.Println("write to server ", hex.EncodeToString(cmd.Data()))
	if _, err := conn.Write(data); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ch := make(chan error, 1)
	msg := make([]byte, MaxReadBuffer)
	readLen := 0
	go func() {
		//log.Println("wait to read msg")
		rlen, err := conn.Read(msg)
		readLen = rlen
		//log.Println("read msg from server len ", rlen, "at time ", time.Now().String()) //, "msg", hex.EncodeToString(msg))
		ch <- err
	}()

	select {
	case <-ctx.Done():
		// request timeout
		log.Println("request context timeout at ", time.Now().String())
		return nil, client.ErrRequestTimeout
	case err, _ := <-ch:
		if err != nil {
			return nil, err
		} else {
			//log.Println("request return with msg", hex.EncodeToString(msg[:readLen]))
			return msg[:readLen], nil
		}
	}
}

func requestToServer(server string, cmd client.Command) ([]byte, error) {
	ip := server

	serverAddr := ip + ":" + strconv.Itoa(ServerPort)
	log.Println("request to server", serverAddr)

	var response []byte
	var reserr error
	for i := 0; i < 1; i++ {
		log.Println("send request times ", i)
		conn, err := net.Dial("udp", serverAddr)
		if err != nil {
			log.Println("net.Dial failed, err", err)
			return nil, err
		}

		response, reserr = requestWithTimeout(conn, cmd.Data(), time.Second*5)
		conn.Close()
		if reserr == client.ErrRequestTimeout {
			continue
		} else {
			break
		}
	}
	return response, reserr

}

func lightLogin(userName string, password string, server string,
	sysinfo string) ([]byte, error) {

	info := &userInfo{}
	var err error
	var res, decPac []byte
	checkAndGetUserConfig(userName, password, server, info, globaConfig)

	if globaConfig.sysinfo == nil {
		var nsysinfo = &common.SystemInfo{}
		err = json.Unmarshal([]byte(sysinfo), &nsysinfo)
		if err != nil {
			LError.Println("ClientLogin parse sysinfo failed, sysinfo:", sysinfo)
			return nil, err
		}
		globaConfig.sysinfo = nsysinfo
	}

	info.sysinfo = globaConfig.sysinfo

	LInfo.Println("check need exchange cert.")
	if _, exist := info.managerCert[server]; !exist {
		LInfo.Printf("goto exchange cert\n")
		if err := clientExchangeCert(info); err != nil {
			LError.Printf(" exchange error :%s\n", err)
		} else {
			LInfo.Println("exchange cert passed")
		}
	}

	if info.managerCert == nil {
		LError.Println("have no manager cert.")
		return nil, errors.New("have no manager cert")
	}

	for i := 0; i < 6; i++ {
		cmd, e := client.NewLoginCmd(info.username, info.password, info.privk.Public().String(), info.sysinfo.DeviceId, info.Sm2Priv, info.managerCert[info.server], *info.sysinfo, "", "")
		if cmd == nil || e != nil {
			LError.Println("NewLoginCmd failed", "err", e.Error())
			return nil, e
		}

		res, err = requestToServer(info.server, cmd)
		if err == client.ErrRequestTimeout {
			continue
		}
		if err != nil {
			LError.Println("request to server err:", err)
			return nil, err
		}
		// den
		decPac, err = client.GetDecryptResponseWithSign(info.username, res, info.Sm2Priv, info.managerCert[info.server])
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
	return decPac, nil
}

func clientExchangeCert(info *userInfo) error {
	var err error
	var res, decPac []byte
	var csr []byte

	csr = info.csr
	if csr == nil {
		return errors.New("have no scsr data")
	}

	for retry := 0; retry < 6; retry++ {
		cmd, e := client.NewNormalExchangeCertCmd(info.username, info.password, string(csr), *info.sysinfo)
		if e != nil {
			log.Println("NewLoginCmd failed", "err", e.Error())
			return e
		}
		res, err = requestToServer(info.server, cmd)
		if err == client.ErrRequestTimeout {
			continue
		}
		if err != nil {
			return err
		}
		// den
		decPac, err = client.GetDecryptResponseWithHmac(info.username, cmd.Key2, res)
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

	head := &client.ServerResponse{}
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
	var resinfo = &client.ExchangeCertResponse{}
	if err = json.Unmarshal(decPac, &resinfo); err != nil {
		log.Println("decpac unmarshal to LoginResponse failed.")
		return err
	}

	var certData string
	certData += resinfo.SliceInfo
	var reqSliceOffset = resinfo.SliceOffset + 1
	for i := reqSliceOffset; i < resinfo.SliceCount; i++ {
		if certSlice, e := ClientReqCertSlice(info, i); e != nil {
			log.Println("request cert slice failed, e:", e.Error())
			return e
		} else {
			certData += certSlice.SliceInfo
		}
	}
	var certs = &client.CertResData{}
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
	err = ioutil.WriteFile(GetManagerCertPath(info.server), []byte(certs.ManagerCert), 0755)
	if err != nil {
		log.Println("Write certificate to file failed, err ", err, "filename", GetManagerCertPath(info.server))
		return err
	}
	cert, _ := common.SM2ReadCertificateFromMem([]byte(certs.ManagerCert))
	addCertInfo(info.server, info.username, cert)
	info.managerCert[info.server] = cert
	return nil
}

func ClientReqCertSlice(info *userInfo, offset int) (*client.SliceInfoResData, error) {
	var err error
	var res, decPac []byte
	var csr []byte

	csr = info.csr
	if csr == nil {
		return nil, errors.New("have no scsr data")
	}

	for retry := 0; retry < 6; retry++ {
		cmd, e := client.NewNormalReqCertSliceCmd(info.username, info.password, offset, *info.sysinfo)
		if e != nil {
			log.Println("NewReqCertSliceCmd failed", "err", e.Error())
			return nil, e
		}
		res, err = requestToServer(info.server, cmd)
		if err == client.ErrRequestTimeout {
			continue
		}
		if err != nil {
			return nil, err
		}
		// den
		decPac, err = client.GetDecryptResponseWithHmac(info.username, cmd.Key2, res)
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
	head := &client.ServerResponse{}
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
	var resinfo = &client.ExchangeCertResponse{}
	if err = json.Unmarshal(decPac, &resinfo); err != nil {
		log.Println("decpac unmarshal to LoginResponse failed.")
		return nil, err
	}
	return &resinfo.SliceInfoResData, nil
}

func ClientReqSliceInfo(info *userInfo, offset int) (*client.SliceInfoResData, error) {

	var res, decPac []byte
	var err error
	for retry := 0; retry < 6; retry++ {
		managerCert := info.managerCert[info.server]
		cmd, _ := client.NewReqUserInfoCmd(info.username, info.password, info.sysinfo.DeviceId, offset, info.Sm2Priv, managerCert)
		res, err = requestToServer(info.server, cmd)
		if err == client.ErrRequestTimeout {
			continue
		}
		if err != nil {
			return nil, err
		}
		// den
		decPac, err = client.GetDecryptResponseWithSign(info.username, res, info.Sm2Priv, managerCert)
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

	head := &client.ServerResponse{}
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
	var slist = &client.UserInfoResponse{}
	if err = json.Unmarshal(decPac, &slist); err != nil {
		log.Println("decpac unmarshal to LoginResponse failed.")
		return nil, err
	}
	return &slist.SliceInfoResData, nil
}
