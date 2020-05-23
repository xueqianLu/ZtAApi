package conf

const (
	ClientID             = "AZEROTRUSTNETWORKACCESSTOANYONEL"
	ztaLocalConfigFile   = "zta.json"
	DefaultInterfaceName = "ztainterface"
	defaultInterfacePort = 62218
)

type StorageConfig struct {
	UserName string `json:"username"`
	Password string `json:"-"` // dec password
	//EncPassword string `json:"password"`   // aes enc and base64, only used for storage.
	PrivateKey string `json:"private"`    // private key
	PublicKey  string `json:"-"`          // public key
	AutoLogin  bool   `json:"autologin"`  // autologin
	ServerAddr string `json:"serveraddr"` // server addr
}
