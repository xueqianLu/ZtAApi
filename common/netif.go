package common

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

func GetIpV4Address(ipstr string) string {
	if strings.Contains(ipstr, ":") {
		strs := strings.Split(ipstr, ":")
		return strings.TrimSpace(strs[0])
	} else if strings.Contains(ipstr, "/") {
		strs := strings.Split(ipstr, "/")
		return strings.TrimSpace(strs[0])
	} else {
		return ipstr
	}
}

func GetMacString(mac []byte) string {
	var macstr string = ""
	for i := 0; i < len(mac); i++ {
		macstr += fmt.Sprintf("%02x:", mac[i])
	}
	if len(macstr) == 0 {
		return ""
	}
	return macstr[:len(macstr)-1]
}

func GetNetIfMac(localip string) (string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return "", errors.New("not found")
	}

	for _, ifp := range ifs {
		addrs, err := ifp.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ifip := net.ParseIP(GetIpV4Address(addr.String()))
			//log.Printf("localip = (%s), netif ip = (%s)\n", localip, addr.String())
			local := net.ParseIP(localip)
			//log.Printf("len(ifip) = %d, len(local) = %d\n", len(ifip), len(local))
			if ifip.Equal(local) {
				return ifp.HardwareAddr.String(), nil
			}
		}
	}
	return "", errors.New("not found")
}
