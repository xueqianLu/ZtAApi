package main

import "C"
import (
	"encoding/json"
	"fmt"
	"github.com/xueqianLu/ZtAApi/common"
	"unsafe"
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

//export LightLogin
func LightLogin(userName string, password string, server string,
	sysinfo string) *C.char {
	LInfo.Printf("got login parameter userName(%s), password(%s), server(%s), sysinfo(%s)\n",
		userName, password, server, sysinfo)
	data, err := lightLogin(userName, password, server, sysinfo)
	if err != nil {
		LError.Printf("light login failed, err:%s\n", err.Error())
		return nil
	}
	LInfo.Printf("response %s\n", string(data))
	return C.CString(string(data))
}

//export SignCertificate
func SignCertificate(ca_pem string, ca_pri_pem string, csr string, days int) *C.char {
	LInfo.Printf("sign certificate parameter")
	crt, err := ValidateCSRFromMem(csr, ca_pem, ca_pri_pem, days)
	if err != nil {
		LError.Printf("sign certificate failed, err:%s\n", err.Error())
		return nil
	}
	return C.CString(crt)
}

type loginUser struct {
	name    string
	passwd  string
	server  string
	sysinfo string
}

func parseUserInfo() []*loginUser {
	var sysinfo = "{\"hostname\":\"hostname\",\"osname\":\"osname\",\"osversion\":\"osversion\",\"osvendor\":\"osvendor\",\"hwvendor\":\"hwvendor\",\"hwserial\":\"hwserial\",\"hwtype\":\"hwtype\",\"deviceid\":\"1fc01cc9b5845071570201403aff8b83fa4f0826463c4d54a545ff2d46d4cc4a\"}"
	var s = make([]*loginUser, 0)
	for i := 1; i <= 10000; i++ {
		u := &loginUser{
			name:    fmt.Sprintf("%d", i),
			passwd:  "12345678",
			server:  "47.93.84.115",
			sysinfo: sysinfo,
		}
		s = append(s, u)
	}
	return s
}

func main() {
	//ts := flag.Int("t", 10, "threads number")
	//flag.Parse()
	//
	//var userinfos = parseUserInfo()
	//var length = len(userinfos)
	//var threads = *ts
	//splitl := length/threads
	//var wg = sync.WaitGroup{}
	//for i:=0; i < threads; i++ {
	//	wg.Add(1)
	//	users := userinfos[i*splitl:(i+1)*splitl]
	//	go func(users []*loginUser) {
	//		defer wg.Done()
	//		for m:=0; m < 1; m++ {
	//			for _, user := range users {
	//				LInfo.Println("user login name ", user.name, "at times ", m+1)
	//				_,err := lightLogin(user.name, user.passwd, user.server, user.sysinfo)
	//				if err != nil {
	//					LError.Printf("user( %s ) login failed, err = %s\n", user.name, err)
	//				} else {
	//					LInfo.Printf("user(%s) login success.", user.name)
	//				}
	//			}
	//		}
	//	}(users)
	//}
	//LInfo.Printf("wait login test finish")
	//wg.Wait()
	//LInfo.Printf("login test finish")
}
