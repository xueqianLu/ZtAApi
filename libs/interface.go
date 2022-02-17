package main

import "C"
import (
	"encoding/hex"
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
	Info.Println("EncrytLoginPktSM2 get param username:", username)
	Info.Println("EncrytLoginPktSM2 get param privk:", privk)
	//Info.Println("get param pubk :", pubk)
	Info.Println("EncrytLoginPktSM2 get param data :", common.ToHex(godata))
	resdata, err := EncryptLoginPktSM2(username, []byte(privk), []byte(pubk), godata)
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

//export SM4Encrypt
func SM4Encrypt(key string, data *C.char, cCharLength C.int) *C.char {
	godata := C.GoBytes(unsafe.Pointer(data), cCharLength)
	Info.Println("SM4Encrypt get param key:", key)
	Info.Println("SM4Encrypt get param data :", common.ToHex(godata))
	enc := common.SM4EncryptCBC([]byte(key), godata)
	var res Response
	if enc == nil {
		res.Error = "encrypt failed"
	} else {
		res.Data = "0x" + hex.EncodeToString(enc)
	}
	d, _ := json.Marshal(res)
	return C.CString(string(d))
}

//export SM4Decrypt
func SM4Decrypt(key string, data *C.char, cCharLength C.int) *C.char {
	godata := C.GoBytes(unsafe.Pointer(data), cCharLength)
	Info.Println("SM4Decrypt get param key:", key)
	Info.Println("SM4Decrypt get param data :", common.ToHex(godata))
	dec := common.SM4DecryptCBC([]byte(key), godata)
	var res Response
	if dec == nil {
		res.Error = "decrypt failed"
	} else {
		res.Data = "0x" + hex.EncodeToString(dec)
	}
	d, _ := json.Marshal(res)
	return C.CString(string(d))
}

func main() {}
