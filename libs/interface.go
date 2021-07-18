package main

import "C"
import (
	"encoding/json"
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

func main() {}
