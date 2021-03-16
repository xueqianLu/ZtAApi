package client

import (
	"fmt"
	"testing"
)

func TestGetServerInfo(t *testing.T) {
	serverlist := []string{
		"www.baidu.com",
		"192.168.1.238",
		"127.0.0.1",
		"127.0.0.1:8678",
		"aws.amazon.com",
	}
	for _, server := range serverlist {
		ip := getServerIp(server)
		fmt.Printf("get server(%s)'s ip = %s\n", server, ip)
	}
}
