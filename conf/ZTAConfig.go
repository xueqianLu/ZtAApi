package conf

import (
	"encoding/json"
	"errors"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/xueqianLu/ZtAApi/common"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

const (
	ClientID           = "AZEROTRUSTNETWORKACCESSTOANYONEL"
	ztaLocalConfigFile = "zta.json"
	ztaUserConfigFile  = "user.json"
	managerCertSuffix  = "manager.cert"
	sm2PrivkFile       = "privk.pem"
	scsrFileName       = "scsr.pem"
)

type managerCertInfo struct {
	serveraddr string
	cert       *sm2.Certificate
}

type UserConfig struct {
	UserName   string `json:"username"`   // username
	ServerAddr string `json:"serveraddr"` // server addr
	AutoLogin  bool   `json:"autologin"`  // autologin
	ConfPath   string `json:"-"`
	DeviceId   string `json:"-"` // current device id

	SM2PrivkFile string          `json:"-"` // sm2 privk file path.
	Sm2Priv      *sm2.PrivateKey `json:"-"` // sm2 privk in mem.
	ScsrFile     string          `json:"-"` // sm2 scsr file path
	ScsrData     []byte          `json:"-"`

	ServerList   []string           `json:"serverlist"` // save all manager cert server addr.
	ManagerCerts []*managerCertInfo `json:"-"`          // save all manager cert info.
}

func (c *UserConfig) createPrivk() error {
	if c.Sm2Priv == nil {
		// 生成私钥
		c.Sm2Priv, _ = common.SM2GenerateKey()
		c.SM2PrivkFile = sm2PrivkFile
		fullpath := filepath.Join(c.ConfPath, c.SM2PrivkFile)
		_, err := common.WriteEncSm2Privatekey(fullpath, c.Sm2Priv, nil)
		if err != nil {
			log.Println("Write privateKey to pem failed", "path=", fullpath, "err=", err)
			return err
		}
	}
	return nil
}

func (c *UserConfig) createScsr() error {
	if c.Sm2Priv != nil && len(c.ScsrData) == 0 {
		c.ScsrFile = scsrFileName
		fullpath := filepath.Join(c.ConfPath, c.ScsrFile)
		csr, err := common.SM2CreateCertificateRequest(fullpath, c.UserName, c.Sm2Priv)
		if err != nil {
			log.Println("create certificate request failed", "path = ", fullpath, "err = ", err)
			return err
		}
		c.ScsrData = csr
	}
	return nil
}

func (c *UserConfig) GetSM2Privkey() *sm2.PrivateKey {
	return c.Sm2Priv
}

func (c *UserConfig) GetScsrData() []byte {
	return c.ScsrData
}

func (c *UserConfig) GetManagerCert(server string) *sm2.Certificate {
	for _, info := range c.ManagerCerts {
		if info.serveraddr == server {
			return info.cert
		}
	}
	return nil
}

func getManagerConfigPath(userpath string, server string) (string, error) {
	managerPath := filepath.Join(userpath, server)
	err := os.MkdirAll(managerPath, os.ModeDir|0700)
	if err != nil {
		return "", err
	}
	return managerPath, nil
}

func ManagerCertName(path, server string) (string, error) {
	managerPath, err := getManagerConfigPath(path, server)
	if err != nil {
		return "", err
	} else {
		return filepath.Join(managerPath, managerCertSuffix), nil
	}
}

func (c *UserConfig) SaveManagerCert(certData []byte) error {

	savefileName, err := ManagerCertName(c.ConfPath, c.ServerAddr)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(savefileName, certData, 0755)
	if err != nil {
		log.Println("Write certificate to file failed, err ", err, "filename", savefileName)
		return err
	}
	var managerCert *sm2.Certificate
	managerCert, err = common.SM2ReadCertificateFromMem(certData)
	if err != nil {
		log.Println("Parse to certificate failed, err ", err)
		return err
	} else {
		c.addManagerCert(c.ServerAddr, managerCert)
	}
	return nil
}

func (c *UserConfig) addManagerCert(server string, cert *sm2.Certificate) {
	var have_server bool
	var have_cert bool
	for _, s := range c.ServerList {
		if server == s {
			have_server = true
			break
		}
	}
	if !have_server {
		c.ServerList = append(c.ServerList, server)
	}

	for _, info := range c.ManagerCerts {
		if info.serveraddr == server {
			info.cert = cert
			have_cert = true
		}
	}
	if !have_cert {
		info := &managerCertInfo{
			serveraddr: server,
			cert:       cert,
		}
		c.ManagerCerts = append(c.ManagerCerts, info)
	}
}

type StorageConfig struct {
	RootPath      string      `json:"configpath"`
	UserName      string      `json:"username"`
	Password      string      `json:"-"`             // dec password
	ServerAddr    string      `json:"serveraddr"`    // server addr
	ServerHistory []string    `json:"serverhistory"` // server history
	User          *UserConfig `json:"-"`

	PrivateKey string `json:"private"` // private key
	PublicKey  string `json:"-"`       // public key
}

func GetServerHistory(local *StorageConfig) []string {
	return local.ServerHistory
}

func GetUserConfigPath(stConfig *StorageConfig) (string, error) {
	root := stConfig.RootPath
	if stConfig.UserName == "" {
		return "", errors.New("not set username")
	}
	userconfig_path := filepath.Join(root, stConfig.UserName)
	log.Println("userconfig path ", userconfig_path)
	err := os.MkdirAll(userconfig_path, os.ModeDir|0700)
	if err != nil {
		return "", err
	}
	return userconfig_path, nil
}

// get user local config, if error happen, retry. retry once.
func GetUserLocalConfig(userpath string, username string, serveraddr string) (*UserConfig, error) {
	var c *UserConfig
	var e error
	if c, e = loadUserLocalConfig(userpath, username, serveraddr); e != nil {
		err := os.RemoveAll(userpath)
		if err != nil {
			log.Println("remove path failed", "path=", userpath, "err=", err)
		}

		err = os.MkdirAll(userpath, os.ModeDir|0700)

		if err != nil {
			log.Println("makedir path failed", "path=", userpath, "err=", err)
		}
		c, e = loadUserLocalConfig(userpath, username, serveraddr)
	}
	return c, e
}

func getManagerCert(userpath string, server string) (*managerCertInfo, error) {
	managername, err := ManagerCertName(userpath, server)
	if err != nil {
		return nil, err
	}
	if certdata, err := ioutil.ReadFile(managername); err != nil {
		log.Println("read manager cert ", managername, " failed, err ", err.Error())
		return nil, err
	} else {
		info := &managerCertInfo{
			serveraddr: server,
		}
		if info.cert, err = common.SM2ReadCertificateFromMem(certdata); err != nil {
			log.Println("ReadCert from data failed, err ", err)
			return nil, err
		} else {
			return info, nil
		}
	}
}

func loadUserLocalConfig(userpath string, username string, serveraddr string) (*UserConfig, error) {
	var config UserConfig

	p := userpath
	name := filepath.Join(p, ztaUserConfigFile)
	encdata, err := ioutil.ReadFile(name)

	if err == nil {
		content := common.SM4DecryptCBC(common.LocalEncKey, encdata)
		json.Unmarshal(content, &config)
	}

	// new created
	if config.UserName == "" {
		config.UserName = username
	}

	if config.UserName != username {
		return nil, errors.New("unmatched local config and username")
	}

	config.ConfPath = userpath
	config.ServerAddr = serveraddr

	config.SM2PrivkFile = filepath.Join(userpath, sm2PrivkFile)
	config.ScsrFile = filepath.Join(userpath, scsrFileName)
	if config.ServerList == nil {
		config.ServerList = make([]string, 0)
	}

	if config.ManagerCerts == nil {
		config.ManagerCerts = make([]*managerCertInfo, 0)
	}

	if config.Sm2Priv, err = common.ReadEncSm2PrivateKey(config.SM2PrivkFile, nil); err != nil {
		log.Println("ReadPrivkey from Pem failed, err ", err, "filepath ", config.SM2PrivkFile)
		// 如果读取私钥失败了，重新生成私钥和自描述文件，并且不再加载 manager 证书.
		config.createPrivk()
		config.createScsr()

	} else {
		// get scsr data
		if config.ScsrData, err = ioutil.ReadFile(config.ScsrFile); err != nil {
			config.createScsr()
		}

		// get all server manager cert
		for _, server := range config.ServerList {
			info, err := getManagerCert(userpath, server)
			if err != nil {
				log.Println("read manager cert ", server, " failed, err ", err.Error())
				continue
			} else {
				config.ManagerCerts = append(config.ManagerCerts, info)
			}
		}
	}

	return &config, nil
}

func ClientUserConfigSave(userconf *UserConfig) error {
	if userconf == nil {
		return nil
	}

	filename := filepath.Join(userconf.ConfPath, ztaUserConfigFile)
	log.Println("save user config to ", filename)
	bytes, _ := json.Marshal(userconf)
	encdata := common.SM4EncryptCBC(common.LocalEncKey, bytes)
	err := ioutil.WriteFile(filename+".tmp", encdata, 0600)
	if err != nil {
		return err
	}

	err = os.Rename(filename+".tmp", filename)
	if err != nil {
		os.Remove(filename + ".tmp")
		return err
	}
	return nil
}

func DeleteAllConfig(rootdir string) error {
	dir, err := ioutil.ReadDir(rootdir)
	if err != nil {
		return err
	}
	PthSep := string(os.PathSeparator)
	for _, d := range dir {
		if !d.IsDir() {
			continue
		}
		if d.Name() == "Configurations" {
			continue
		}
		os.RemoveAll(rootdir + PthSep + d.Name())
	}
	return nil
}

// must not return nil
func GetClientLocalConfig(rootdir string) *StorageConfig {
	var config = &StorageConfig{}
	var err error

	root := make([]byte, len(rootdir))
	copy(root, []byte(rootdir))
	log.Println("local config root path = ", string(root))
	name := filepath.Join(string(root), ztaLocalConfigFile)

	encdata, err := ioutil.ReadFile(name)
	if err == nil {
		content := common.SM4DecryptCBC(common.LocalEncKey, encdata)
		json.Unmarshal(content, &config)
	}

	config.RootPath = string(root)
	if config.PrivateKey != "" {
		privk, err := NewPrivateKeyFromString(config.PrivateKey)
		if err == nil {
			config.PublicKey = privk.Public().String()
		} else {
			config.PrivateKey = ""
		}
	}

	if config.PrivateKey == "" {
		privk, _ := NewPrivateKey()
		config.PrivateKey = privk.String()
		config.PublicKey = privk.Public().String()
	}

	//if userConfigPath,err := GetUserConfigPath(config); err == nil {
	//	config.User,err = GetUserLocalConfig(userConfigPath, config.UserName, config.ServerAddr)
	//	if err != nil {
	//		log.Println("GetUserLocalConfig failed, delete dir:", userConfigPath, ",username:", config.UserName, ",err:", err)
	//		os.RemoveAll(userConfigPath)
	//	}
	//}

	return config
}

func ClientLocalConfigSave(local *StorageConfig) error {
	root := local.RootPath
	filename := filepath.Join(root, ztaLocalConfigFile)
	bytes, _ := json.Marshal(local)

	encdata := common.SM4EncryptCBC(common.LocalEncKey, bytes)
	err := ioutil.WriteFile(filename+".tmp", encdata, 0600)
	if err != nil {
		return err
	}
	err = os.Rename(filename+".tmp", filename)
	if err != nil {
		os.Remove(filename + ".tmp")
		return err
	}
	return nil
}
