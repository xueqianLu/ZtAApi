package common

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

func GetIpAddress(conn net.Conn) string {
	addr := conn.LocalAddr().String()
	strs := strings.Split(addr, ":")
	return strs[0]
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
			ifip := net.ParseIP(addr.String())
			local := net.ParseIP(localip)
			if ifip.Equal(local) {
				return ifp.HardwareAddr.String(), nil
			}
		}
	}
	return "", errors.New("not found")
}
