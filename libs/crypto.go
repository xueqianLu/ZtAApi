package main

import (
	"crypto/rand"
	"encoding/pem"
	"errors"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/xueqianLu/ZtAApi/common"
	"log"
	"math/big"
	"os"
	"time"
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

type decpkt struct {
	cmdtype    byte
	checkval   [32]byte
	useridx    [32]byte
	deviceid   [32]byte
	random     [32]byte
	enc_length [2]byte
}

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
	var blength = 32
	var offset = 0
	ptype := data[0]
	offset += 1
	ptype = ptype
	//log.Println("ptype:", ptype)

	r_checkval := data[offset : offset+blength]
	offset += blength
	r_checkval = r_checkval
	//log.Println("checkval:", common.ToHex(r_checkval))

	r_userindx := data[offset : offset+blength]
	offset += blength
	r_userindx = r_userindx
	//log.Println("r_userindx:", common.ToHex(r_userindx))

	r_deviceid := data[offset : offset+blength]
	offset += blength
	r_deviceid = r_deviceid
	//log.Println("r_deviceid:", common.ToHex(r_deviceid))

	r_random := data[offset : offset+blength]
	offset += blength
	r_random = r_random
	//log.Println("r_random:", common.ToHex(r_random))

	r_enc_length := data[offset : offset+2]
	offset += 2

	log.Printf("r_enc_length[0] = %x, r_enc_length[1] = %x\n", r_enc_length[0], r_enc_length[1])
	enc_length := int16(r_enc_length[0])<<8 | int16(r_enc_length[1])&0x00ff
	log.Println("enc_length = ", enc_length)
	r_encpac := data[offset : offset+int(enc_length)]
	offset += int(enc_length)

	r_sign := data[offset:]
	log.Println("r_signature ", common.ToHex(r_sign))

	sign_data := data[:offset]

	if common.SM2CertVerifySignature(user_cert, sign_data, r_sign) {
		log.Println("Verify response signature succeed")
	} else {
		log.Println("Verify response signature failed")
		return nil, ErrVerifySignature
	}
	//log.Println("got signature 0x", hex.EncodeToString(r_sign))
	//log.Println("got encrypt data length = ", len(r_encpac))
	//log.Println("got encrypt data:0x", hex.EncodeToString(r_encpac))
	//log.Println("decrypt with privk: 0x", privk.D.Text(16))

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

func genSerialNumber() *big.Int {
	var max, _ = new(big.Int).SetString("1000000000000000000000000", 10)
	r, _ := rand.Int(rand.Reader, max)
	return r
}

func ValidateCSRFromPem(csr_path string, ca_path string, ca_pri string,
	duration int, out_crt string) error {
	// load CA key pair
	//      public key
	caCRT, err := sm2.ReadCertificateFromPem(ca_path)
	if err != nil {
		return err
	}

	//      private key
	caPrivateKey, err := sm2.ReadPrivateKeyFromPem(ca_pri, nil) //[]byte("123456"))
	if err != nil {
		return err
	}

	// load client certificate request
	clientCSR, err := sm2.ReadCertificateRequestFromPem(csr_path)
	if err != nil {
		return err
	}

	// create client certificate template
	clientCRTTemplate := sm2.Certificate{
		Signature:          clientCSR.Signature,
		SignatureAlgorithm: clientCSR.SignatureAlgorithm,

		PublicKeyAlgorithm: clientCSR.PublicKeyAlgorithm,
		PublicKey:          clientCSR.PublicKey,

		SerialNumber: genSerialNumber(),
		Issuer:       caCRT.Subject,
		Subject:      clientCSR.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Duration(duration) * 24 * time.Hour),
		KeyUsage:     sm2.KeyUsageDigitalSignature,
		ExtKeyUsage:  []sm2.ExtKeyUsage{sm2.ExtKeyUsageClientAuth},
	}

	// create client certificate from template and CA public key
	clientCRTRaw, err := sm2.CreateCertificate(rand.Reader, &clientCRTTemplate, caCRT, clientCSR.PublicKey, caPrivateKey)
	if err != nil {
		return err
	}

	// save the certificate
	clientCRTFile, err := os.Create(out_crt)
	if err != nil {
		return err
	}
	pem.Encode(clientCRTFile, &pem.Block{Type: "CERTIFICATE", Bytes: clientCRTRaw})
	clientCRTFile.Close()

	return nil
}

func ValidateCSRFromMem(csr string, ca string, ca_pri string,
	duration int) (string, error) {
	// load CA key pair
	//      public key
	caCRT, err := sm2.ReadCertificateFromMem([]byte(ca))
	if err != nil {
		return "", err
	}

	//      private key
	caPrivateKey, err := sm2.ReadPrivateKeyFromMem([]byte(ca_pri), nil)
	if err != nil {
		return "", err
	}

	// load client certificate request
	clientCSR, err := sm2.ReadCertificateRequestFromMem([]byte(csr))
	if err != nil {
		return "", err
	}

	// create client certificate template
	clientCRTTemplate := sm2.Certificate{
		Signature:          clientCSR.Signature,
		SignatureAlgorithm: clientCSR.SignatureAlgorithm,

		PublicKeyAlgorithm: clientCSR.PublicKeyAlgorithm,
		PublicKey:          clientCSR.PublicKey,

		SerialNumber: genSerialNumber(),
		Issuer:       caCRT.Subject,
		Subject:      clientCSR.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Duration(duration) * 24 * time.Hour),
		KeyUsage:     sm2.KeyUsageDigitalSignature,
		ExtKeyUsage:  []sm2.ExtKeyUsage{sm2.ExtKeyUsageClientAuth},
	}

	// create client certificate from template and CA public key
	clientCRTRaw, err := sm2.CreateCertificate(rand.Reader, &clientCRTTemplate, caCRT, clientCSR.PublicKey, caPrivateKey)
	if err != nil {
		return "", err
	}

	// save the certificate
	return string(clientCRTRaw), nil
}
