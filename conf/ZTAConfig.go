package conf

import (
	"encoding/json"
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
)

type StorageConfig struct {
	ConfPath string `json:"configpath"`
	UserName string `json:"username"`
	Password string `json:"-"` // dec password
	//EncPassword string `json:"password"`   // aes enc and base64, only used for storage.
	PrivateKey string `json:"private"`    // private key
	PublicKey  string `json:"-"`          // public key
	AutoLogin  bool   `json:"autologin"`  // autologin
	ServerAddr string `json:"serveraddr"` // server addr

	SM2PrivkFile    string           `json:"privkpath"`   // sm2 privk file path.
	ManagerCertFile string           `json:"managercert"` // manager cert file path.
	Sm2Priv         *sm2.PrivateKey  // sm2 privk in mem.
	ManagerCert     *sm2.Certificate // manager cert in mem.
}

// must not return nil
func GetClientLocalConfig(rootdir string) *StorageConfig {
	var config = &StorageConfig{AutoLogin: false}
	var err error

	root := rootdir
	name := filepath.Join(root, ztaLocalConfigFile)
	content, err := ioutil.ReadFile(name)
	if err == nil {
		json.Unmarshal(content, &config)
	}

	if config.ConfPath == "" {
		config.ConfPath = rootdir
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

	return config
}

func ClientLocalConfigSave(rootdir string, local *StorageConfig) error {
	root := rootdir
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
