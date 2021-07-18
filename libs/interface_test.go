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

func TestDecryptLoginPktSM2(t *testing.T) {
	var data = "0xe006d7a9ff046dbec955f758042e8b7da283e2cfe887b8dd64018977637554d6f6f15dd49c139cbc728ca891a0dd745390cacab9783f05700f79998f4841f835006f306d022100c0390f6abd2b2a8e3056387ba5b7a55a220c5cd77fad2ba9ad1b3eea1eceaea5022100f2129ea1da518a0767b56c8a02a3b599cb5c4ef02414f5c4a53d509f29cbfdeb0420bb1203ee96d5072f3b9d41728cb781df5dd43e1ea095c6a189e4f5bcc3e91f6904039de0863046022100aa1cd9c3481fd302f55e154377437d1963a300695a8bebc6e55feee393686ae3022100d91c191694f089ded2ca8cca671cdc055785e162104b4bfa255e6f8b019af0df"
	var param DecrytLoginPktSM2Param
	pkd, pubkd := keyinit()
	param.Privkdata = string(pkd)
	param.Pubkdata = string(pubkd)
	param.Data = data

	paramstr, _ := json.Marshal(param)
	fmt.Println("param:", string(paramstr))
	res := DecrytLoginPktSM2(string(paramstr))
	fmt.Println("res:", res)
}
