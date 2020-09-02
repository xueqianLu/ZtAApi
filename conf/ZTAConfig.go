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
)

type UserConfig struct {
	UserName   string `json:"username"`	  // username
	ConfPath   string `json:"confpath"`
	AutoLogin  bool   `json:"autologin"`  // autologin
	PrivateKey string `json:"private"`    // private key
	PublicKey  string `json:"-"`          // public key
	DeviceId   string `json:"-"`		  // current device id

	ServerAddr string `json:"serveraddr"` // server addr

	SM2PrivkFile    string           `json:"privkpath"`   // sm2 privk file path.
	ManagerCertFile string           `json:"managercert"` // manager cert file path.
	Sm2Priv         *sm2.PrivateKey  // sm2 privk in mem.
	ManagerCert     *sm2.Certificate // manager cert in mem.
}

type StorageConfig struct {
	ConfigPath string `json:"configpath"`
	UserName string `json:"username"`
	Password string `json:"-"` // dec password
	ServerAddr string `json:"serveraddr"` // server addr
	User     *UserConfig `json:"-"`
}

func GetUserConfigPath(stConfig *StorageConfig) (string,error) {
	root := stConfig.ConfigPath
	if stConfig.UserName == "" {
		return "",errors.New("not set username")
	}
	userconfig_path := filepath.Join(root,stConfig.UserName)
	log.Println("userconfig path ", userconfig_path)
	err := os.MkdirAll(userconfig_path, os.ModeDir|0700)
	if err != nil {
		return "",err
	}
	return userconfig_path, nil
}

// get user local config, if error happen, retry. retry once.
func GetUserLocalConfig(userpath string, username string) (*UserConfig,error) {
	var c *UserConfig
	var e error
	if c,e = getUserLocalConfig(userpath, username); e != nil {
		err := os.RemoveAll(userpath)
		if err != nil {
			log.Println("remove path failed", "path=",userpath,"err=",err)
		}

		err = os.MkdirAll(userpath, os.ModeDir|0700)

		if err != nil {
			log.Println("makedir path failed", "path=",userpath,"err=",err)
		}
		c,e = getUserLocalConfig(userpath, username)
	}
	return c,e
}

func getUserLocalConfig(userpath string, username string) (*UserConfig,error) {
	var config = &UserConfig{}
	p := userpath
	name := filepath.Join(p, ztaUserConfigFile)
	content, err := ioutil.ReadFile(name)
	if err == nil {
		json.Unmarshal(content, &config)
	}
	if config.ConfPath == "" {
		config.ConfPath = p
	}

	// new created
	if config.UserName == "" {
		config.UserName = username
	}

	if config.UserName != username {
		return nil, errors.New("unmatched local config and username")
	}

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

	if config.SM2PrivkFile != "" && config.ManagerCertFile != "" {
		if config.Sm2Priv, err = sm2.ReadPrivateKeyFromPem(config.SM2PrivkFile, nil); err != nil {
			log.Println("ReadPrivkey from Pem failed, err ", err)
		}
		csrdata, _ := ioutil.ReadFile(config.ManagerCertFile)
		if config.ManagerCert, err = common.SM2ReadCertificateFromMem(csrdata); err != nil {
			log.Println("ReadCert from data failed, err ", err)
		}
	}
	return config, nil
}

// must not return nil
func GetClientLocalConfig(rootdir string) *StorageConfig {
	var config = &StorageConfig{}
	var err error

	root := make([]byte, len(rootdir))
	copy(root,[]byte(rootdir))
	log.Println("local config root path = ", string(root))
	name := filepath.Join(string(root), ztaLocalConfigFile)
	content, err := ioutil.ReadFile(name)
	if err == nil {
		json.Unmarshal(content, &config)
	}

	if config.ConfigPath == "" {
		config.ConfigPath = string(root)
	}

	if userConfigPath,err := GetUserConfigPath(config); err == nil {
		config.User,err = GetUserLocalConfig(userConfigPath, config.UserName)
		if err != nil {
			log.Println("GetUserLocalConfig failed, delete dir:", userConfigPath, ",username:", config.UserName, ",err:", err)
			os.RemoveAll(userConfigPath)
		}
	}

	return config
}

func ClientUserConfigSave(userconf *UserConfig) error {
	p := userconf.ConfPath
	filename := filepath.Join(p, ztaUserConfigFile)
	bytes, _ := json.Marshal(userconf)
	err := ioutil.WriteFile(filename+".tmp", bytes, 0600)
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

func ClientLocalConfigSave(local *StorageConfig) error {
	root := local.ConfigPath
	filename := filepath.Join(root, ztaLocalConfigFile)
	bytes, _ := json.Marshal(local)
	err := ioutil.WriteFile(filename+".tmp", bytes, 0600)
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
