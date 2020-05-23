package common

import (
	"encoding/json"
)

/*
$ systeminfo

主机名:           WIN10-901211241
OS 名称:          Microsoft Windows 10 专业版
OS 版本:          10.0.18363 暂缺 Build 18363
OS 制造商:        Microsoft Corporation
OS 配置:          独立工作站
OS 构件类型:      Multiprocessor Free
注册的所有人:     Windows 用户
注册的组织:
产品 ID:          00331-10000-00001-AA917
初始安装日期:     6/4/2019, 12:17:44 AM
系统启动时间:     5/4/2020, 11:54:24 AM
系统制造商:       LENOVO
系统型号:         20J6CTO1WW
系统类型:         x64-based PC
处理器:           安装了 1 个处理器。
                  [01]: Intel64 Family 6 Model 158 Stepping 9 GenuineIntel ~2496 Mhz
BIOS 版本:        LENOVO R0FET37W (1.17 ), 9/28/2017
Windows 目录:     C:\WINDOWS
系统目录:         C:\WINDOWS\system32
启动设备:         \Device\HarddiskVolume5
系统区域设置:     zh-cn;中文(中国)
输入法区域设置:   zh-cn;中文(中国)
时区:             (UTC+08:00) 北京，重庆，香港特别行政区，乌鲁木齐
物理内存总量:     15,989 MB
可用的物理内存:   7,189 MB
虚拟内存: 最大值: 18,677 MB
虚拟内存: 可用:   3,867 MB
虚拟内存: 使用中: 14,810 MB
页面文件位置:     C:\pagefile.sys
域:               WorkGroup
登录服务器:       \\WIN10-901211241
修补程序:         安装了 19 个修补程序。
                  [01]: KB4537572
                  [02]: KB4497932
                  [03]: KB4498523
                  [04]: KB4500109
                  [05]: KB4503308
                  [06]: KB4508433
                  [07]: KB4509096
                  [08]: KB4515383
                  [09]: KB4516115
                  [10]: KB4517245
                  [11]: KB4520390
                  [12]: KB4521863
                  [13]: KB4524569
                  [14]: KB4528759
                  [15]: KB4537759
                  [16]: KB4538674
                  [17]: KB4541338
                  [18]: KB4552152
                  [19]: KB4549951
网卡:             安装了 8 个 NIC。
                  [01]: Hyper-V Virtual Ethernet Adapter
                      连接名:      vEthernet (Default Switch)
                      启用 DHCP:   否
                      IP 地址
                        [01]: 172.17.13.113
                        [02]: fe80::70de:800c:cc4c:1e59
                  [02]: Intel(R) Ethernet Connection (5) I219-V
                      连接名:      以太网
                      启用 DHCP:   是
                      DHCP 服务器: 192.168.1.1
                      IP 地址
                        [01]: 192.168.1.212
                        [02]: fe80::6400:a929:8c0a:7913
                  [03]: Intel(R) Dual Band Wireless-AC 8265
                      连接名:      WLAN
                      状态:        媒体连接已中断
                  [04]: Microsoft Wi-Fi Direct Virtual Adapter
                      连接名:      本地连接* 11
                      启用 DHCP:   否
                      IP 地址
                        [01]: 192.168.137.1
                        [02]: fe80::419d:baa:6b3e:e07c
                  [05]: Bluetooth Device (Personal Area Network)
                      连接名:      蓝牙网络连接 2
                      状态:        媒体连接已中断
                  [06]: VMware Virtual Ethernet Adapter for VMnet1
                      连接名:      VMware Network Adapter VMnet1
                      启用 DHCP:   否
                      IP 地址
                        [01]: 192.168.126.1
                        [02]: fe80::fd7a:fc11:3c57:1eb
                  [07]: VMware Virtual Ethernet Adapter for VMnet8
                      连接名:      VMware Network Adapter VMnet8
                      启用 DHCP:   否
                      IP 地址
                        [01]: 192.168.159.1
                        [02]: fe80::b161:5cf3:782:c317
                  [08]: Microsoft KM-TEST Loopback Adapter
                      连接名:      以太网 2
                      启用 DHCP:   否
                      IP 地址
Hyper-V 要求:     虚拟机监视器模式扩展: 是
                  固件中已启用虚拟化: 是
                  二级地址转换: 是
                  数据执行保护可用: 是

*/

type SystemInfo struct {
	HostName     string `json:"hostname"`
	OSName       string `json:"osname"`
	OSVersion    string `json:"osversion"`
	OSVendor     string `json:"osvendor"`
	HWVendor     string `json:"hwvendor"`
	HWSerialName string `json:"hwserial"`
	HWType       string `json:"hwtype"`
	DeviceId     string `json:"deviceid"`
}

func (s *SystemInfo) String() string {
	b, _ := json.Marshal(s)
	return string(b)
}
