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
	Info.Println("get param data length:", cCharLength)
	Info.Println("get param privk:", privk)
	Info.Println("get param pubk :", pubk)
	Info.Println("get param data :", common.ToHex(godata))
	resdata, err := DecryptLoginPktSM2(godata, []byte(privk), []byte(pubk))
	if err != nil {
		res.Error = err.Error()
	} else {
		res.Data = common.ToHex(resdata)
	}
	d, _ := json.Marshal(res)
	//Info.Println("response:", string(d))
	return C.CString(string(d))
}

//export EncrytLoginPktSM2
func EncrytLoginPktSM2(username string, privk string, pubk string, data *C.char, cCharLength C.int) *C.char {
	var res Response
	godata := C.GoBytes(unsafe.Pointer(data), cCharLength)
	//Info.Println("get param data length:", cCharLength)
	//Info.Println("get param username:", username)
	//Info.Println("get param privk:", privk)
	//Info.Println("get param pubk :", pubk)
	//Info.Println("get param data :", common.ToHex(godata))
	domain := "zta1.qrsecure.cn"
	deviceid := "37fca1d0ae30dbd7228c4c6de18a796ea865e3d074f791d9af010a5d5334a083"
	resdata, err := EncryptLoginPktSM2(domain, deviceid, username, []byte(privk), []byte(pubk), godata)
	if err != nil {
		res.Error = err.Error()
	} else {
		res.Data = common.ToHex(resdata)
	}
	d, _ := json.Marshal(res)
	//Info.Println("response:", string(d))
	return C.CString(string(d))
}

//export SignCertificate
func SignCertificate(ca_pem string, ca_pri_pem string, csr string, days int) *C.char {
	var res Response
	//LInfo.Printf("sign certificate parameter")
	crt, err := ValidateCSRFromMem(csr, ca_pem, ca_pri_pem, days)
	if err != nil {
		//Info.Printf("sign certificate failed, err:%s\n", err.Error())
		res.Error = err.Error()
	} else {
		res.Data = crt
	}

	d, _ := json.Marshal(res)
	//Info.Println("response:", string(d))
	return C.CString(string(d))
}

func main() {}
