package common

import (
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509/pkix"
	"errors"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
	"github.com/tjfoc/gmsm/sm4"
	"io/ioutil"
	"math/big"
)

func GetSM2PubkeyFromCert(cert *sm2.Certificate) (*sm2.PublicKey, error) {
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		{
			switch pub.Curve {
			case sm2.P256Sm2():
				sm2pub := &sm2.PublicKey{
					Curve: pub.Curve,
					X:     pub.X,
					Y:     pub.Y,
				}
				return sm2pub, nil
			default:
				return nil, errors.New("not P256Sm2")
			}
		}
	default:
		return nil, errors.New("not a sm2 cert")
	}
}

func SM2GenerateKey() (*sm2.PrivateKey, error) {
	return sm2.GenerateKey()
}

func SM2ReadCertificateRequestFromMem(data []byte) (*sm2.CertificateRequest, error) {
	return sm2.ReadCertificateRequestFromMem(data)
}

func SM2CreateCertificateRequest(filename string, username string, priv *sm2.PrivateKey) ([]byte, error) {
	country := "CN"
	province := "BJ"
	city := "BJ"
	company := "ZtA"
	department := "ZtASecure"
	email := username + "@163.com"
	templateReq := sm2.CertificateRequest{
		Subject: pkix.Name{
			OrganizationalUnit: []string{department},
			Country:            []string{country},
			Organization:       []string{company},
			Locality:           []string{city},
			Province:           []string{province},
			CommonName:         username,
		},
		EmailAddresses: []string{email},

		SignatureAlgorithm: sm2.SM2WithSM3,
	}
	ok, err := sm2.CreateCertificateRequestToPem(filename, &templateReq, priv)
	if ok {
		data, e := ioutil.ReadFile(filename)
		if e != nil {
			return nil, e
		} else {
			return data, nil
		}
	} else {
		return nil, err
	}
	//	return sm2.CreateCertificateRequestToMem(&templateReq, priv)
}

func SM2ReadCertificateFromMem(data []byte) (*sm2.Certificate, error) {
	if data == nil || len(data) == 0 {
		return nil, errors.New("invalid cert data")
	}
	return sm2.ReadCertificateFromMem(data)
}

//
func SM2CreateCertificate(username string, priv *sm2.PrivateKey) ([]byte, error) {
	country := "CN"
	province := "BJ"
	city := "BJ"
	company := "ZtA"
	department := "ZtASecure"
	email := username + "@163.com"

	template := sm2.Certificate{
		// SerialNumber is negative to ensure that negative
		// values are parsed. This is due to the prevalence of
		// buggy code that produces certificates with negative
		// serial numbers.
		SerialNumber: big.NewInt(-1),
		Subject: pkix.Name{
			OrganizationalUnit: []string{department},
			Country:            []string{country},
			Organization:       []string{company},
			Locality:           []string{city},
			Province:           []string{province},
			CommonName:         username,
		},
		EmailAddresses: []string{email},
		//NotBefore: time.Unix(1000, 0),
		//NotAfter:  time.Unix(100000, 0),

		SignatureAlgorithm: sm2.SM2WithSM3,

		//SubjectKeyId: []byte{1, 2, 3, 4},
		//KeyUsage:     sm2.KeyUsageCertSign,

		//BasicConstraintsValid: true,
		//IsCA:                  true,
	}

	pubKey, _ := priv.Public().(*sm2.PublicKey)
	return sm2.CreateCertificateToMem(&template, &template, pubKey, priv)
}
func SM2CertEncrypt(cert *sm2.Certificate, data []byte) ([]byte, error) {
	//证书加密
	encpub, e := GetSM2PubkeyFromCert(cert)
	if e != nil {
		return nil, e
	}
	encdata, e := encpub.Encrypt([]byte(data))
	if e != nil {
		return nil, e
	}
	return encdata, nil
}

func SM2PrivDecrypt(priv *sm2.PrivateKey, encdata []byte) ([]byte, error) {
	//私钥解密
	if priv == nil {
		return nil, errors.New("SM2PrivDec nil privkey")
	}
	return priv.Decrypt(encdata)
}

// return value format:signature [0:32] ==> r, signature[32:64] ==> s
func SM2PrivSign(priv *sm2.PrivateKey, data []byte) ([]byte, error) {
	//私钥签名
	hash := sm3.Sm3Sum(data)
	sig, e := priv.Sign(rand.Reader, hash[:], nil)
	if e != nil {
		return nil, e
	}
	r, s, e := sm2.SignDataToSignDigit(sig)
	if e != nil {
		return nil, e
	}
	signature := make([]byte, 64)
	copy(signature[:32], r.Bytes())
	copy(signature[32:], s.Bytes())

	return signature, nil
}

// signature[0:32] r
// signature[32:64] s

func SM2CertVerifySignature(cert *sm2.Certificate, data []byte, signature []byte) bool {
	//证书验签
	if cert == nil {
		return false
	}
	pubk, err := GetSM2PubkeyFromCert(cert)
	if err != nil {
		return false
	}
	r := big.NewInt(0).SetBytes(signature[:32])
	s := big.NewInt(0).SetBytes(signature[32:])
	sign, err := sm2.SignDigitToSignData(r, s)
	if err != nil {
		return false
	}

	hash := sm3.Sm3Sum(data)
	return pubk.Verify(hash, sign)
}

func SM3Hash(data []byte) Hash {
	var hash = Hash{}
	sum := sm3.Sm3Sum(data)
	hash.SetBytes(sum)
	return hash
}

func SM4EncryptCBC(key sm4.SM4Key, packet []byte) []byte {
	block, e := sm4.NewCipher(key)
	if e != nil {
		println("SM4DecryptCBC new cipher error", e)
		return nil
	}

	padding := PKCS7Padding(packet, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, []byte(ZTAIV))

	crypted := make([]byte, len(padding))
	blockMode.CryptBlocks(crypted, padding)

	return crypted
}

func SM4DecryptCBC(key sm4.SM4Key, crypted []byte) []byte {
	if len(crypted) == 0 || (len(crypted)%16) != 0 {
		println("SM4DecryptCBC Decrypt ", len(crypted))
		return nil
	}
	block, e := sm4.NewCipher(key)
	if e != nil {
		println("SM4DecryptCBC new cipher failed,", e)
		return nil
	}
	blockMode := cipher.NewCBCDecrypter(block, []byte(ZTAIV))
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)

	origData = PKCS7UnPadding(origData)
	return origData
}
