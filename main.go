package main

import (
	"bytes"
	"encoding/hex"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/xueqianLu/ZtAApi/common"
	"io/ioutil"
	"log"
	"math/big"
	"os"
)

func testss() {
	data := []byte("02cadf51ee6f72b6a71a4cea947ab8a3294c51b6b2087b9ffa3bb286679dbb6330bfc17f0aae4a7e2891d64235d600a6e5b84bd1d65ccd6dd045c7011168e2effdd10285e21d0e822f6b6479415c9ae9c22acfd6e965078bde0e4d34a0f42a74dd029d042c885fecda69b85d7545a9cb771ce12a03c2fa4294f9e1215f06ac912274757cddbb684fca93998347a5ef443dac7b27cc34906d2d0ff6b5b66264f39dc67809f84f53e4dcc57130f42d5c6ccf6a8917612298cd3b9688846c6e580606013f5f770cb0855e8af0e3a71e8469e86223fafe51885dbb71a726b34bc201f6e7326f2f1e6effd9807ee692e4af29fb35f5099a51ecef5621c76aeb7c86185fcc1e037a6f4af8a76a7295da1859aaa92a32c2dda3b990d7ef625057d32d7aa0cbc045625c274661e919ed1b2d66bd5fc958541f9a214da675cff4c4d74e64d4e9255625054418ab61022fc8938026cc270fbbe4aba3db570b49b486b12836693c7f17413fd2edae5c6b5022bde7a7ac4dbdee838bb8dc8a7036925189fa016d6d8049f3ea3da3b57c89c920d32aee038d7d51d81b3c7f28ea6bc7230c28045e502750ab1d3593629930578e30da99cf03dedc499ae840e2ba57dece242250837f0732f1945f76ab294c53845e21cf106124435baf1e235036a1e5e03325454ed11f6e559b1c0ea975641bb1504aa2e15400d8e701e8828bcd3c2e3e48017b85e83fd2ada3efadbdc974d43784fdd82d3ed4f11f76a96242fec0c4eaaf71e573085cfb7b6ab1ad5590c81a3c27beeb1aed68ec30d7e78eb7ae731abc901429e93e79e9b1671dff40e760bf74ae5f1b516bbd153c5f5bc525d42bb593ccd5ba1355c58c5e4954b0263dfa314d9bd63460a386300a621468d10ad4281d2d0eb2a039ab83555a2a5935f208855aa80f9080ef94b5837148b0f9ee13eea19171877907d4600eb86d0918b93f5f47e2625b7a4ea11a5b3b28f6456a7baf31a7a1c1492b6be2b12a682ebc6eaae6d8618bf56d72b38a4e33094c8a852949c8136bb0390b1cd9c862d4c3a72c5d84bd45a311c67ffbfba9e6e48d5d730c2a7705f862")
	sig, _ := hex.DecodeString("ff525f692bf8888718e1107e61892eab356f1a807a9b14ac2abeeb773bd52250a0b04716df683b86836b8bc3ec755ab1efcca0d9a4dfab7d2d33d677ac0d015d")
	sig_r := big.NewInt(0).SetBytes(sig[:32])
	sig_s := big.NewInt(0).SetBytes(sig[32:])

	signature, err := sm2.SignDigitToSignData(sig_r, sig_s)
	if err != nil {
		log.Println("sign to signdata failed, err ", err)
		return
	}

	privk, err := sm2.ReadPrivateKeyFromPem("prikey_sm2.pem", nil)
	pub := privk.PublicKey
	res := pub.Verify(data, signature)
	log.Println("verify with privk-->pubkey ", res)

	pub_x := pub.X.Bytes()
	pub_y := pub.Y.Bytes()
	log.Println("x:", hex.EncodeToString(pub_x), ",y:", hex.EncodeToString(pub_y))

	certdata, err := ioutil.ReadFile("center_pubkey_sm2.pem")
	if err != nil {
		log.Println("read file failed, err ", err)
		return
	}

	cert, err := common.SM2ReadCertificateFromMem(certdata)
	if err != nil {
		println("read cert failed, err ", err)
		return
	}
	hash := common.SM3Hash(data)
	log.Println("sm3hash data ", hex.EncodeToString(hash[:]))

	verify := common.SM2CertVerifySignature(cert, data, signature)
	println("verify = ", verify)

	verify = common.SM2CertVerifySignature(cert, hash[:], signature)
	println("verify = ", verify)
	return
}

func testSM2Verify() {
	data := []byte("02cadf51ee6f72b6a71a4cea947ab8a3294c51b6b2087b9ffa3bb286679dbb6330bfc17f0aae4a7e2891d64235d600a6e5b84bd1d65ccd6dd045c7011168e2effdd10285e21d0e822f6b6479415c9ae9c22acfd6e965078bde0e4d34a0f42a74dd029d042c885fecda69b85d7545a9cb771ce12a03c2fa4294f9e1215f06ac912274757cddbb684fca93998347a5ef443dac7b27cc34906d2d0ff6b5b66264f39dc67809f84f53e4dcc57130f42d5c6ccf6a8917612298cd3b9688846c6e580606013f5f770cb0855e8af0e3a71e8469e86223fafe51885dbb71a726b34bc201f6e7326f2f1e6effd9807ee692e4af29fb35f5099a51ecef5621c76aeb7c86185fcc1e037a6f4af8a76a7295da1859aaa92a32c2dda3b990d7ef625057d32d7aa0cbc045625c274661e919ed1b2d66bd5fc958541f9a214da675cff4c4d74e64d4e9255625054418ab61022fc8938026cc270fbbe4aba3db570b49b486b12836693c7f17413fd2edae5c6b5022bde7a7ac4dbdee838bb8dc8a7036925189fa016d6d8049f3ea3da3b57c89c920d32aee038d7d51d81b3c7f28ea6bc7230c28045e502750ab1d3593629930578e30da99cf03dedc499ae840e2ba57dece242250837f0732f1945f76ab294c53845e21cf106124435baf1e235036a1e5e03325454ed11f6e559b1c0ea975641bb1504aa2e15400d8e701e8828bcd3c2e3e48017b85e83fd2ada3efadbdc974d43784fdd82d3ed4f11f76a96242fec0c4eaaf71e573085cfb7b6ab1ad5590c81a3c27beeb1aed68ec30d7e78eb7ae731abc901429e93e79e9b1671dff40e760bf74ae5f1b516bbd153c5f5bc525d42bb593ccd5ba1355c58c5e4954b0263dfa314d9bd63460a386300a621468d10ad4281d2d0eb2a039ab83555a2a5935f208855aa80f9080ef94b5837148b0f9ee13eea19171877907d4600eb86d0918b93f5f47e2625b7a4ea11a5b3b28f6456a7baf31a7a1c1492b6be2b12a682ebc6eaae6d8618bf56d72b38a4e33094c8a852949c8136bb0390b1cd9c862d4c3a72c5d84bd45a311c67ffbfba9e6e48d5d730c2a7705f862")
	//sig1,_:=hex.DecodeString("3045022100b690d2f85b08dd16b1f5d8e98f142e8f8660d5ded101d1fb098392448c44662902204894ae20fb6c4026824db89675205a00428093ef6f0f0986d19ffd614ee08d14")
	//sig2,_:=hex.DecodeString("3046022100ddc05a234de8b6604661c160c01de3321fc3a49a0453645f8335dab0cb5b0a86022100e3e93aa810306b14dacce18b4ebbd56bdfd3d7d17c6757787a676b550c886ce2")
	privk, err := sm2.ReadPrivateKeyFromPem("prikey_sm2.pem", nil)
	println("privk:", hex.EncodeToString(privk.D.Bytes()))
	if err != nil {
		log.Println("read privk failed, err ", err)
		return
	}
	sig, err := common.SM2PrivSign(privk, data)
	if err != nil {
		log.Println("sm2priv sign failed, err ", err)
		return
	}

	r, s, _ := sm2.SignDataToSignDigit(sig)
	r_b := r.Bytes()
	s_b := s.Bytes()
	log.Println("r:", hex.EncodeToString(r_b), ",s:", hex.EncodeToString(s_b))

	certdata, err := ioutil.ReadFile("center_pubkey_sm2.pem")
	if err != nil {
		log.Println("read file failed, err ", err)
		return
	}

	cert, err := common.SM2ReadCertificateFromMem(certdata)
	if err != nil {
		println("read cert failed, err ", err)
		return
	}

	verify := common.SM2CertVerifySignature(cert, data, sig)
	println("verify = ", verify)
	return
}

func testsig() {
	sig, _ := hex.DecodeString("304402201fe863e5f737b1f555dfb171be171bc39f767faa45bff351cc8c9c22afd9264d02206b1833af9a5a94ecefdac53c6ac447746bbb7a4bf323457c9fa448be14f82d68")
	data := []byte("02cadf51ee6f72b6a71a4cea947ab8a3294c51b6b2087b9ffa3bb286679dbb6330bfc17f0aae4a7e2891d64235d600a6e5b84bd1d65ccd6dd045c7011168e2effdd10285e21d0e822f6b6479415c9ae9c22acfd6e965078bde0e4d34a0f42a74dd029d042c885fecda69b85d7545a9cb771ce12a03c2fa4294f9e1215f06ac912274757cddbb684fca93998347a5ef443dac7b27cc34906d2d0ff6b5b66264f39dc67809f84f53e4dcc57130f42d5c6ccf6a8917612298cd3b9688846c6e580606013f5f770cb0855e8af0e3a71e8469e86223fafe51885dbb71a726b34bc201f6e7326f2f1e6effd9807ee692e4af29fb35f5099a51ecef5621c76aeb7c86185fcc1e037a6f4af8a76a7295da1859aaa92a32c2dda3b990d7ef625057d32d7aa0cbc045625c274661e919ed1b2d66bd5fc958541f9a214da675cff4c4d74e64d4e9255625054418ab61022fc8938026cc270fbbe4aba3db570b49b486b12836693c7f17413fd2edae5c6b5022bde7a7ac4dbdee838bb8dc8a7036925189fa016d6d8049f3ea3da3b57c89c920d32aee038d7d51d81b3c7f28ea6bc7230c28045e502750ab1d3593629930578e30da99cf03dedc499ae840e2ba57dece242250837f0732f1945f76ab294c53845e21cf106124435baf1e235036a1e5e03325454ed11f6e559b1c0ea975641bb1504aa2e15400d8e701e8828bcd3c2e3e48017b85e83fd2ada3efadbdc974d43784fdd82d3ed4f11f76a96242fec0c4eaaf71e573085cfb7b6ab1ad5590c81a3c27beeb1aed68ec30d7e78eb7ae731abc901429e93e79e9b1671dff40e760bf74ae5f1b516bbd153c5f5bc525d42bb593ccd5ba1355c58c5e4954b0263dfa314d9bd63460a386300a621468d10ad4281d2d0eb2a039ab83555a2a5935f208855aa80f9080ef94b5837148b0f9ee13eea19171877907d4600eb86d0918b93f5f47e2625b7a4ea11a5b3b28f6456a7baf31a7a1c1492b6be2b12a682ebc6eaae6d8618bf56d72b38a4e33094c8a852949c8136bb0390b1cd9c862d4c3a72c5d84bd45a311c67ffbfba9e6e48d5d730c2a7705f862")
	certdata, err := ioutil.ReadFile("center_pubkey_sm2.pem")
	if err != nil {
		log.Println("read file failed, err ", err)
		return
	}

	cert, err := common.SM2ReadCertificateFromMem(certdata)
	if err != nil {
		println("read cert failed, err ", err)
		return
	}

	//hash := common.SM3Hash(data)
	//log.Println("sm3hash ",hex.EncodeToString(hash[:]))
	verify := common.SM2CertVerifySignature(cert, data, sig)
	println("verify = ", verify)

}

func binRead(filename string) []byte {
	fp, _ := os.Open(filename)
	defer fp.Close()

	data := make([]byte, 1024)
	// read bytes to slice
	n, err := fp.Read(data)
	if err != nil {
		log.Println("read file failed, err ", err)
		return nil
	}
	return data[:n]
}

func binWrite(filename string, data []byte) {
	fp, _ := os.Create(filename)
	defer fp.Close()

	fp.Write(data)

}
func w() {
	data, _ := hex.DecodeString("00663d7bd9fb3426834c42d495d799a98c972afbdf14c3e1ea3f862ab3884a80")
	binWrite("bdata", data)
}
func r() {
	data := binRead("bdata.sig")
	if data != nil {
		log.Println("bdata.sig:", hex.EncodeToString(data))
	}
}

func ssGMssl() {
	data, _ := hex.DecodeString("313233343536373839300a")
	sig := binRead("data.log.sig")
	if sig == nil {
		log.Println("read sig failed")
		return
	}
	log.Println("read sig: ", hex.EncodeToString(sig))
	pubk, err := sm2.ReadPublicKeyFromPem("pub.pem", []byte("1111"))
	if err != nil {
		log.Println("read pubkey failed, err", err)
		return
	}
	ret := pubk.Verify(data, sig)
	log.Println("verify gmssl ", ret)
}

func zta() {
	//priv,_:=sm2.ReadPrivateKeyFromPem("smprivk.pem",nil)
	cert, _ := sm2.ReadCertificateFromPem("client.cert")
	data := binRead("bdata")
	sig := binRead("bdata.sig")

	pub, _ := common.GetSM2PubkeyFromCert(cert)
	ret := pub.Verify(data, sig)
	log.Println("verify result ", ret)
}
func ztaVerify() {
	sig, _ := hex.DecodeString("30460221009901fc237e679ee165f83a1c32e5d4c26fa0c2e7167c8fa13b1463bb7fee81c3022100e140217e6499c3c74af4c2bb481a70cdad1d3a63f826d4add19b82040b59ac8e")
	data, _ := hex.DecodeString("00663d7bd9fb3426834c42d495d799a98c972afbdf14c3e1ea3f862ab3884a80")
	cert, _ := sm2.ReadCertificateFromPem("client.cert")
	pub, _ := common.GetSM2PubkeyFromCert(cert)
	ret := pub.Verify(data, sig)
	log.Println("verify result ", ret)
}
func ParseCertToPubkey() {
	certdata, err := ioutil.ReadFile("center_pubkey_sm2.pem")
	if err != nil {
		log.Println("read file failed, err ", err)
		return
	}

	cert, err := common.SM2ReadCertificateFromMem(certdata)
	if err != nil {
		println("read cert failed, err ", err)
		return
	}
	pub, _ := common.GetSM2PubkeyFromCert(cert)
	pubk_x := pub.X.Bytes()
	pubk_y := pub.Y.Bytes()
	log.Println("x:", hex.EncodeToString(pubk_x), ",y:", hex.EncodeToString(pubk_y))
	sm2.WritePublicKeytoPem("client_pub.pem", pub, nil)
}

func testEec() {
	data := "12345678901234567890"
	//cert, err := sm2.ReadCertificateFromPem("manager.pem")
	cert, err := sm2.ReadCertificateFromPem("center_pubkey_sm2.pem")
	if err != nil {
		log.Println("read cert failed, err ", err)
		return
	}

	encdata, err := common.SM2CertEncrypt(cert, []byte(data))
	if err != nil {
		log.Println("encrypt failed, err ", err)
		return
	}
	log.Println("encdata = ", hex.EncodeToString(encdata))

	privk, err := sm2.ReadPrivateKeyFromPem("prikey_sm2.pem", nil)
	if err != nil {
		log.Println("read privk failed, err ", err)
		return
	}
	decdata, err := privk.Decrypt(encdata)
	if err != nil {
		log.Println("privk decrypt failed, err ", err)
		return
	}
	ret := bytes.Compare(decdata, []byte(data)) == 0
	log.Printf("sm2 privkey decrypt compare %v\n", ret)
}

func testDec() {
	data := "12345678901234567890"
	//encdata, _ := hex.DecodeString("0440c490f133d5e1cf9cd3df0f49c02e164269e4c2fb225068106f50eb529a52a2588c868bf0ce5fd31ff2e7f01fccc5d743ad3c3df2cfa27019de2d1a0cf01cf7f7623fbade75f208be9f432fbb8ff5d2343eab40c2b967f11c88d7181b463c4f94ec5e3f81cd8f88a88f19ebbe1563537899f268")
	encdata, _ := hex.DecodeString("307d022076f7fb4d141a2c33c63ecd6b0420ef6d4195feb5e7ca35db9de8117eb5e735fc02210083a7b286d4fc2ed48786675b41c7adb28f5ec6909fb8d8d7f7b3db580ab971c304206e01eda7e75c8e82bcb6bcf2d66b14c2e59de7822ede55800c4b2b48a90f377604149143f6560256b478eba190f33862eb6459a7426f")
	//privk, err := sm2.ReadPrivateKeyFromPem("smprivk.pem", nil)
	privk, err := sm2.ReadPrivateKeyFromPem("prikey_sm2.pem", nil)
	if err != nil {
		log.Println("read privk failed, err ", err)
		return
	}
	decdata, err := privk.Decrypt(encdata)
	if err != nil {
		log.Println("privk decrypt failed, err ", err)
		return
	}
	ret := bytes.Compare(decdata, []byte(data)) == 0
	log.Printf("sm2 privkey decrypt compare %v\n", ret)
}

func main() {
	//testss()
	//testsig()
	//testSM2Verify()
	//testGMssl()
	//ssGMssl()
	//ParseCertToPubkey()
	//w()
	//r()
	testEec()
	//testDec()
}
