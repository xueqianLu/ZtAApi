package common

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log"
)

var (
	ZTAIV = "01234567890abcde"
	KEYIV = "1234567812345678"
)

// AES-128-CBC-PKCS

//AES enc
func AESEncrypt(origData, key []byte) []byte {
	block, _ := aes.NewCipher(key)
	//log.Println("AESEnc:data", hex.EncodeToString(origData))
	//log.Println("AESEnc:key", hex.EncodeToString(key))
	//log.Println("AESEnc:iv", ZTAIV)

	origData = PKCS7Padding(origData, block.BlockSize())
	//log.Println("AESEnc:paddata", hex.EncodeToString(origData))

	blockMode := cipher.NewCBCEncrypter(block, []byte(ZTAIV))

	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	//log.Println("AESEnc:encdata", hex.EncodeToString(crypted))
	return crypted
}

func PKCS7Padding(origData []byte, blockSize int) []byte {
	padding := blockSize - len(origData)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)

	return append(origData, padtext...)
}

//AES dec
func AESDecrypt(crypted, key []byte) []byte {
	block, _ := aes.NewCipher(key)
	blockMode := cipher.NewCBCDecrypter(block, []byte(ZTAIV))
	//log.Println("AESDec crypted data:", hex.EncodeToString(crypted))

	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)

	origData = PKCS7UnPadding(origData)
	return origData
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:length-unpadding]
}

// HMAC SHA256
func HMAC_SHA256(data []byte, key []byte) *Hash {
	//log.Println("HMAC:data", hex.EncodeToString(data))
	k := BytesCombine(key, []byte(ZTAIV))
	//log.Println("HMAC:key", hex.EncodeToString(k))
	h := hmac.New(sha256.New, k)
	h.Write(data)
	hmac := &Hash{}
	hmac.SetBytes(h.Sum(nil))
	//log.Println("HMAC:hmac", hex.EncodeToString(hmac.Bytes()))
	return hmac
}

func SHA256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func Base64Encode(data []byte) string {
	enc := base64.StdEncoding.EncodeToString(data)
	return enc
}

func Base64Decode(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

func GenRandomHash() Hash {

	val, err := rand.Prime(rand.Reader, 256)
	if err != nil {
		return Hash{}
	}
	random := Hash{}

	random.SetBytes(val.Bytes())
	return random
}

func DevideKey(key Hash) []byte {
	var keytmp = BytesXor(key[0:16], key[16:])
	var d = make([]byte, 16)
	copy(d[:], keytmp)
	log.Println("in devide key , before sm4, key is ", hex.EncodeToString(keytmp))
	var keyfin = SM4EncryptCBCWithIV(keytmp[:], d, []byte(KEYIV))
	log.Println("in devide key , after sm4, key is ", hex.EncodeToString(keyfin))
	return keyfin[:16]
}
