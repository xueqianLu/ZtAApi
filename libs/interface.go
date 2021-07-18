package main

import "C"
import (
	"encoding/json"
	"github.com/xueqianLu/ZtAApi/common"
	"log"
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
func DecrytLoginPktSM2(privk string, pubk string, data []byte) *C.char {
	var res Response
	resdata, err := DecryptLoginPktSM2([]byte(data), []byte(privk), []byte(pubk))
	if err != nil {
		res.Error = err.Error()
	} else {
		res.Data = common.ToHex(resdata)
	}
	d, _ := json.Marshal(res)
	log.Println("response:", string(d))
	return C.CString(string(d))
}

//export EncrytLoginPktSM2
func EncrytLoginPktSM2(username string, privk string, pubk string, data []byte) *C.char {
	var res Response
	resdata, err := EncryptLoginPktSM2(username, []byte(privk), []byte(pubk), data)
	if err != nil {
		res.Error = err.Error()
	} else {
		res.Data = common.ToHex(resdata)
	}
	d, _ := json.Marshal(res)
	log.Println("response:", string(d))
	return C.CString(string(d))
}

func main() {}
