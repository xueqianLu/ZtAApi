package main

import (
	"encoding/hex"
	"errors"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/xueqianLu/ZtAApi/common"
	"log"
)

var (
	ErrInvalidParam    = errors.New("invalid param")
	ID_ErrInvalidParam = -1

	ErrParsePemFailed    = errors.New("parse from mem failed")
	ID_ErrParsePemFailed = -2

	ErrVerifySignature    = errors.New("unverified signature")
	ID_ErrVerifySignature = -3

	ErrSM2PrikDecrypt    = errors.New("sm2 privk decrypt failed")
	ID_ErrSM2PrikDecrypt = -4

	ErrSM2CertEncrypt    = errors.New("sm2 cert encrypt failed")
	ID_ErrSM2CertEncrypt = -5

	ErrSM2Signature    = errors.New("sm2 signature failed")
	ID_ErrSM2Signature = -6
)

func DecryptLoginPktSM2(data []byte, privkdata []byte, userCertData []byte) ([]byte, error) {
	if len(data) < 96 {
		return nil, ErrInvalidParam
	}
	privk, err := common.SM2ReadPrivateKeyFromMem(privkdata)
	if err != nil {
		log.Println("read private key failed, err", err)
		return nil, ErrParsePemFailed
	}
	user_cert, err := common.SM2ReadCertificateFromMem(userCertData)
	if err != nil {
		log.Println("read certificate failed, err", err)
		return nil, ErrParsePemFailed
	}
	r_userindx := data[:32]
	r_random := data[32:64]
	r_enc_length := data[64:66]
	enc_length := int16(r_enc_length[0])<<8 | int16(r_enc_length[1])&0x00ff
	r_encpac := data[66 : 66+enc_length]
	r_sign := data[66+enc_length:]

	sign_data := common.BytesCombine(r_userindx, r_random, r_enc_length, r_encpac)

	if common.SM2CertVerifySignature(user_cert, sign_data, r_sign) {
		log.Println("Verify response signature succeed")
	} else {
		log.Println("Verify response signature failed")
		return nil, ErrVerifySignature
	}
	log.Println("got signature 0x", hex.EncodeToString(r_sign))
	log.Println("got encrypt data length = ", len(r_encpac))
	log.Println("got encrypt data:0x", hex.EncodeToString(r_encpac))
	log.Println("decrypt with privk: 0x", privk.D.Text(16))

	dec_data, err := common.SM2PrivDecrypt(privk, r_encpac)
	if err != nil {
		log.Println("sm2 privk decrypt failed, err", err)
		return nil, ErrSM2PrikDecrypt
	}

	return dec_data, nil
}

type Ucmd struct {
	UserIndex common.Hash
	Random    common.Hash
	EncLength [2]byte
	EncPacket []byte
	Signature []byte
}

func (u *Ucmd) GenSignature(privk *sm2.PrivateKey) error {
	enclen := len(u.EncPacket)
	u.EncLength[0] = byte(enclen >> 8 & 0xff)
	u.EncLength[1] = byte(enclen & 0xff)

	data := common.BytesCombine(u.UserIndex[:], u.Random[:], u.EncLength[:], u.EncPacket[:])

	signature, err := common.SM2PrivSign(privk, data)
	if err != nil {
		log.Println("GenSignature failed, err ", err)
		return err
	}
	u.Signature = signature
	return nil
}

func (u *Ucmd) Data() []byte {
	return common.BytesCombine(u.UserIndex[:], u.Random[:], u.EncLength[:], u.EncPacket, u.Signature[:])
}

func EncryptLoginPktSM2(username string, privkdata []byte, userCertData []byte, data []byte) ([]byte, error) {
	var err error
	//	log.Println("in EncryptLoginPktSM2 privkdata", string(privkdata))
	privk, err := common.SM2ReadPrivateKeyFromMem(privkdata)
	if err != nil {
		log.Println("read private key failed, err", err)
		return nil, ErrParsePemFailed
	}
	user_cert, err := common.SM2ReadCertificateFromMem(userCertData)
	if err != nil {
		log.Println("read certificate failed, err", err)
		return nil, ErrParsePemFailed
	}

	cmd := &Ucmd{}
	cmd.Random = common.GenRandomHash()
	cmd.UserIndex.SetBytes(common.BytesXor(common.SHA256([]byte(username)), cmd.Random[:]))

	cmd.EncPacket, err = common.SM2CertEncrypt(user_cert, data)
	if err != nil {
		log.Println("cert encrypt failed, err ", err)
		return nil, ErrSM2CertEncrypt
	}

	if err = cmd.GenSignature(privk); err != nil {
		log.Println("gensignature failed,", err)
		return nil, ErrSM2Signature
	}
	return cmd.Data(), nil
}
