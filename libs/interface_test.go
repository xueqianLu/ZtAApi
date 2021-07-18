package main

import (
	"encoding/json"
	"fmt"
	"github.com/xueqianLu/ZtAApi/common"
	"io/ioutil"
	"testing"
)

func keyinit() ([]byte, []byte) {
	pkd, e := ioutil.ReadFile("pk.pem")
	if e != nil {
		return nil, nil
	}
	pk, e := common.SM2ReadPrivateKeyFromMem(pkd)
	if e != nil {
		fmt.Println("read privatekey failed, e ", e)
		return nil, nil
	}
	pubc, e := common.SM2CreateCertificate("username", pk)
	if e != nil {
		fmt.Println("create cert failed, e ", e)
		return nil, nil
	}
	e = ioutil.WriteFile("pub.cert", pubc, 0644)
	if e != nil {
		fmt.Println("write pub.cert failed")
		return nil, nil
	}
	return pkd, pubc
}

func TestEncryptLoginPktSM2(t *testing.T) {

	var data = []byte{0x12, 0x23, 0x34}
	var param EncryptLoginPktSM2Param
	pkd, pubkd := keyinit()
	param.Username = "username"
	param.Privkdata = string(pkd)
	param.Pubkdata = string(pubkd)
	param.Data = common.ToHex(data)

	paramstr, _ := json.Marshal(param)
	fmt.Println("param:", string(paramstr))
	res := EncrytLoginPktSM2(string(paramstr))
	fmt.Println("res:", res)
}
