package main

import "C"
import (
	"encoding/json"
	//	"encoding/json"
	"fmt"
	"github.com/xueqianLu/ZtAApi/common"
	"unsafe"
	//	"github.com/xueqianLu/ZtAApi/common"
	//	"unsafe"
)

type EncryptLoginPktSM2Param struct {
	Username  string `json:"username"`
	Privkdata string `json:"private"`
	Pubkdata  string `json:"pubkey"`
	Data      string `json:"data"`
}

type DecrytLoginPktSM2Param struct {
	Privkdata string `json:"private"`
	Pubkdata  string `json:"pubkey"`
	Data      string `json:"data"`
}

type Response struct {
	Data  string `json:"data"`
	Error string `json:"error"`
}

//export DecrytLoginPktSM2
func DecrytLoginPktSM2(privk string, pubk string, data *C.char, cCharLength C.int) *C.char {
	var res Response
	godata := C.GoBytes(unsafe.Pointer(data), cCharLength)
	//log.Println("get param data length:", cCharLength)
	//log.Println("get param privk:", privk)
	//log.Println("get param pubk :", pubk)
	//log.Println("get param data :", common.ToHex(godata))
	resdata, err := DecryptLoginPktSM2(godata, []byte(privk), []byte(pubk))
	if err != nil {
		res.Error = err.Error()
	} else {
		res.Data = common.ToHex(resdata)
	}
	d, _ := json.Marshal(res)
	//log.Println("response:", string(d))
	return C.CString(string(d))
}

//export EncrytLoginPktSM2
func EncrytLoginPktSM2(username string, privk string, pubk string, data *C.char, cCharLength C.int) *C.char {
	var res Response
	godata := C.GoBytes(unsafe.Pointer(data), cCharLength)
	//log.Println("get param data length:", cCharLength)
	//log.Println("get param username:", username)
	//log.Println("get param privk:", privk)
	//log.Println("get param pubk :", pubk)
	//log.Println("get param data :", common.ToHex(godata))
	resdata, err := EncryptLoginPktSM2(username, []byte(privk), []byte(pubk), godata)
	if err != nil {
		res.Error = err.Error()
	} else {
		res.Data = common.ToHex(resdata)
	}
	d, _ := json.Marshal(res)
	//log.Println("response:", string(d))
	return C.CString(string(d))
}

//export SignCertificate
func SignCertificate(ca_pem string, ca_pri_pem string, csr string, days int) *C.char {
	var res Response
	//LInfo.Printf("sign certificate parameter")
	crt, err := ValidateCSRFromMem(csr, ca_pem, ca_pri_pem, days)
	if err != nil {
		LError.Printf("sign certificate failed, err:%s\n", err.Error())
		res.Error = err.Error()
	} else {
		res.Data = crt
	}

	d, _ := json.Marshal(res)
	//log.Println("response:", string(d))
	return C.CString(string(d))
}

//export LightLogin
func LightLogin(userName string, password string, server string,
	sysinfo string) *C.char {
	//LInfo.Printf("got login parameter userName(%s), password(%s), server(%s), sysinfo(%s)\n",
	//	userName, password, server, sysinfo)
	//LInfo.Printf("got login parameter userName(%s)\n",
	//	userName)
	data, err := lightLogin(userName, password, server, sysinfo)
	if err != nil {
		LError.Printf("light login failed, err:%s\n", err.Error())
		return nil
	}
	//LInfo.Printf("response %s\n", string(data))
	return C.CString(string(data))
}

type loginUser struct {
	name    string
	passwd  string
	server  string
	sysinfo string
}

func parseUserInfo(server string) []*loginUser {
	var sysinfo = "{\"hostname\":\"hostname\",\"osname\":\"osname\",\"osversion\":\"osversion\",\"osvendor\":\"osvendor\",\"hwvendor\":\"hwvendor\",\"hwserial\":\"hwserial\",\"hwtype\":\"hwtype\",\"deviceid\":\"1fc01cc9b5845071570201403aff8b83fa4f0826463c4d54a545ff2d46d4cc4a\"}"
	var s = make([]*loginUser, 0)
	for i := 1; i <= 5000; i++ {
		u := &loginUser{
			name:    fmt.Sprintf("%d", i),
			passwd:  "12345678",
			server:  server,
			sysinfo: sysinfo,
		}
		s = append(s, u)
	}
	return s
}

func main() {
	//ts := flag.Int("t", 10, "threads number")
	//ip := flag.String("ip", "192.168.0.200", "server ipaddress")
	//flag.Parse()
	//
	//var userinfos = parseUserInfo(*ip)
	//var length = len(userinfos)
	//var threads = *ts
	//splitl := length/threads
	//var sended, success, failed uint32 = 0,0,0
	//var wg = sync.WaitGroup{}
	//for i:=0; i < threads; i++ {
	//	wg.Add(1)
	//	users := userinfos[i*splitl:(i+1)*splitl]
	//	go func(users []*loginUser) {
	//		defer wg.Done()
	//		for m:=0; m < 1; m++ {
	//			for _, user := range users {
	//				atomic.AddUint32(&sended, 1)
	//				//LInfo.Println("user login name ", user.name, "at times ", m+1)
	//				_,err := lightLogin(user.name, user.passwd, user.server, user.sysinfo)
	//				if err != nil {
	//					atomic.AddUint32(&failed, 1)
	//					LError.Printf("user( %s ) login failed, err = %s\n", user.name, err)
	//				} else {
	//					atomic.AddUint32(&success, 1)
	//					//LInfo.Printf("user(%s) login success.", user.name)
	//				}
	//			}
	//		}
	//	}(users)
	//}
	//
	//LInfo.Printf("wait login test finish")
	//var ticker = time.NewTicker(time.Second)
	//defer ticker.Stop()
	//for sended != (failed + success) {
	//	select {
	//	case <-ticker.C:
	//		LInfo.Printf("total sended %d, passed %d, failed %d\n", sended, success, failed)
	//	}
	//}
	//wg.Wait()
	//LInfo.Printf("login test finish")
}
