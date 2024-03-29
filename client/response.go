package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/tjfoc/gmsm/sm2"
	. "github.com/ztasecure-lab/gologin/common"
	"log"
)

func GetDecryptResponseWithHmac(name string, key2 []byte, data []byte) ([]byte, error) {
	if len(data) < 96 {
		return nil, errors.New("Invalid response")
	}
	r_userindx := data[:32]
	r_random := data[32:64]
	r_encpac := data[64 : len(data)-32]
	r_hmac := data[len(data)-32:]

	hmac_data := BytesCombine(r_userindx, r_random, r_encpac)

	userNameSha := SHA256([]byte(name))
	userIndex := BytesXor(userNameSha, r_random)
	if bytes.Compare(r_userindx, userIndex) != 0 {
		return nil, errors.New("not match userindex")
	}

	hmac_hash := HMAC_SHA256(hmac_data, key2)
	//log.Println("ParseLoginResponse local hmac=", hex.EncodeToString(hmac_hash[:]))
	//log.Println("ParseLoginResponse local hmac=", hex.EncodeToString(hmac_hash[:]))
	if result := bytes.Compare(hmac_hash[:], r_hmac); result != 0 {
		return nil, errors.New("hmac not match")
	}
	decPac := SM4DecryptCBC(key2, r_encpac)
	//log.Println("AESDec loginRes:%s", hex.EncodeToString(decPac))
	//log.Println("AESDec loginRes:%s", string(decPac))

	return decPac, nil
}

func GetDecryptResponseWithSign(name string, data []byte, privk *sm2.PrivateKey, manager_cert *sm2.Certificate) ([]byte, error) {
	if len(data) < 96 {
		return nil, errors.New("Invalid response")
	}
	r_userindx := data[:32]
	r_random := data[32:64]
	r_enc_length := data[64:66]
	enc_length := int16(r_enc_length[0])<<8 | int16(r_enc_length[1])&0x00ff
	r_encpac := data[66 : 66+enc_length]
	r_sign := data[66+enc_length:]

	sign_data := BytesCombine(r_userindx, r_random, r_enc_length, r_encpac)

	if SM2CertVerifySignature(manager_cert, sign_data, r_sign) {
		log.Println("Verify response signature succeed")
	} else {
		log.Println("Verify response signature failed")
		return nil, errors.New("Verify response signature failed")
	}

	dec_data, err := SM2PrivDecrypt(privk, r_encpac)
	if err != nil {
		return nil, err
	}
	return dec_data, nil
}

func ParseLoginResponse(data []byte) (*LoginResData, error) {
	res := &LoginResponse{}
	if err := json.Unmarshal(data, &res); err != nil {
		log.Println("decpac unmarshal to loginrespacket failed.")
		return nil, err
	}
	return &res.LoginResData, nil
}

func ParseAdminLoginResponse(data []byte) (*AdminLoginResData, error) {
	res := &AdminLoginResponse{}
	if err := json.Unmarshal(data, &res); err != nil {
		log.Println("decpac unmarshal to loginrespacket failed.")
		return nil, err
	}
	return &res.AdminLoginResData, nil
}
