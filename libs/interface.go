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
func DecrytLoginPktSM2(param string) string {
	var p DecrytLoginPktSM2Param
	var res Response
	if e := json.Unmarshal([]byte(param), &p); e != nil {
		log.Printf("unmarshal param to DecrytLoginPktSM2Param failed, err:%s\n", e.Error())
		res.Error = "unmarshal failed"
		d, _ := json.Marshal(res)
		return string(d)
	}
	data := common.FromHex(p.Data)
	pubk := []byte(p.Pubkdata)
	privk := []byte(p.Privkdata)
	resdata, err := DecryptLoginPktSM2(data, privk, pubk)
	if err != nil {
		res.Error = err.Error()
	} else {
		res.Data = common.ToHex(resdata)
	}
	d, _ := json.Marshal(res)
	return string(d)
}

//export EncrytLoginPktSM2
func EncrytLoginPktSM2(param string) string {
	var p EncryptLoginPktSM2Param
	var res Response
	if e := json.Unmarshal([]byte(param), &p); e != nil {
		log.Printf("unmarshal param to EncryptLoginPktSM2Param failed, err:%s\n", e.Error())
		res.Error = "unmarshal failed"
		d, _ := json.Marshal(res)
		return string(d)
	}
	data := common.FromHex(p.Data)
	pubk := []byte(p.Pubkdata)
	privk := []byte(p.Privkdata)
	resdata, err := EncryptLoginPktSM2(p.Username, data, privk, pubk)
	if err != nil {
		res.Error = err.Error()
	} else {
		res.Data = common.ToHex(resdata)
	}
	d, _ := json.Marshal(res)
	return string(d)
}

func main() {}
