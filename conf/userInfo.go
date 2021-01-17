package conf

import "encoding/json"

type ServerInfo struct {
	Name      string `json:"name"`
	IP        string `json:"ip"`
	Protocol  string `json:"protocol"`
	Port      int    `json:"port"`
	URL       string `json:"url"`
	GatewayID int    `json:"gatewayid"`
}

type HostInfo struct {
	IP     string `json:"ip"`
	Domain string `json:"domain"`
}

type GatewayInfo struct {
	//	IP           string       `json:"client_ip"`
	GWPubkey     string       `json:"gateway_connection_pubkey"`
	EndPoint     string       `json:"gateway_endpoint"`
	Key          string       `json:"key"`
	Id           int          `json:"gateway_id"`
	AllowServers []ServerInfo `json:"allowed_servers"`
	DNSServers   []string     `json:"dns_server"`
}

type AllConfigInfo struct {
	UserId   string        `json:"usrID"`
	LifeTime int           `json:"lifetime"` // unit minutes
	HomeUrl  string        `json:"url"`
	ClientIp string        `json:"client_ip"`
	Gateway  []GatewayInfo `json:"gateway"`
	Hosts    []HostInfo    `json:"hosts"`
}

func (i AllConfigInfo) String() string {
	b, _ := json.Marshal(i)
	return string(b)
}
