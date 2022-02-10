package main

import (
	"encoding/hex"
	"fmt"
	"github.com/xueqianLu/ZtAApi/common"
	"io/ioutil"
	"testing"
)

//
//func init(){
//	keygenerate()
//}

func keyget() ([]byte, []byte) {
	//pkd, e := ioutil.ReadFile("manager.pem")
	pkd, e := ioutil.ReadFile("priv1.pem")
	if e != nil {
		return nil, nil
	}
	//pubk, e := ioutil.ReadFile("client.cert")
	pubk, e := ioutil.ReadFile("pub1.cert")
	if e != nil {
		return nil, nil
	}
	return pkd, pubk
}

func keygetuser() ([]byte, []byte) {
	pkd, e := ioutil.ReadFile("testcert/client.pem")
	if e != nil {
		return nil, nil
	}
	pubk, e := ioutil.ReadFile("testcert/client.cert")
	if e != nil {
		return nil, nil
	}
	return pkd, pubk
}

func keygetmanager() ([]byte, []byte) {
	pkd, e := ioutil.ReadFile("testcert/manager.pem")
	if e != nil {
		return nil, nil
	}
	pubk, e := ioutil.ReadFile("testcert/manager.cert")
	if e != nil {
		return nil, nil
	}
	return pkd, pubk
}

func enckeyget() ([]byte, []byte) {
	pkd, e := ioutil.ReadFile("testcert/client.pem")
	if e != nil {
		return nil, nil
	}
	pubk, e := ioutil.ReadFile("testcert/manager.cert")
	if e != nil {
		return nil, nil
	}
	return pkd, pubk
}

func deckeyget() ([]byte, []byte) {
	//pkd, e := ioutil.ReadFile("manager.pem")
	pkd, e := ioutil.ReadFile("testcert/manager.pem")
	if e != nil {
		fmt.Println("read pem failed, e:", e)
		return nil, nil
	}
	//pubk, e := ioutil.ReadFile("client.cert")
	pubk, e := ioutil.ReadFile("testcert/client.cert")
	if e != nil {
		fmt.Println("read cert failed, e:", e)
		return nil, nil
	}
	return pkd, pubk
}

func keygenerate() ([]byte, []byte) {
	pkd, e := ioutil.ReadFile("client.pem")
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
	e = ioutil.WriteFile("client.cert", pubc, 0644)
	if e != nil {
		fmt.Println("write pub.cert failed")
		return nil, nil
	}
	return pkd, pubc
}

//func TestEncryptLoginPktSM2(t *testing.T) {
//	//keygenerate()
//	var data = []byte("12313213213213213213213333333333333333333333333333333333333333333333")
//	var param EncryptLoginPktSM2Param
//	pkd, pubkd := keyget()
//	param.Username = "username"
//	param.Privkdata = string(pkd)
//	param.Pubkdata = string(pubkd)
//	param.Data = common.ToHex(data)
//
//	var deviceid = "37fca1d0ae30dbd7228c4c6de18a796ea865e3d074f791d9af010a5d5334a083"
//	var domain = "zta1.qrsecure.cn"
//
//	//paramstr, _ := json.Marshal(param)
//	//fmt.Println("param:", string(paramstr))
//	//res := EncrytLoginPktSM2(string(paramstr))
//	res, _ := EncryptLoginPktSM2(domain, deviceid, param.Username, []byte(param.Privkdata), []byte(param.Pubkdata), data)
//	fmt.Println("res:", hex.EncodeToString(res))
//}
//
//func TestDecryptLoginPktSM2(t *testing.T) {
//	// 生成客户端证书
//
//	var data = "0x02447ea567c9688f8713f7d009beb56b327939d0a32a5f82c6ea55d7101be21cecee7f54927a8e29a6795eb3417f310c4f50b9dd0fa0bed96d027e74d5c65542bfc350dfc3cf7e31db1ab1b6e3c4e158234037e33867a7e059f4eb0d3c8af0d5c2e988f2890df984f9dd82dda1d1117255b41025436cc7dfc64050dfba480171e993fc93b82388f68ab8e1a8d3b43f113bb41025436cc7dfc64050dfba480171e9032730820323022100e327601f5fc5e9563d97d6d126551d4c5322b113e71ffab4a9395b78afe95c0e02207fec1292926fe3af7ae284339999a5adca6386a4bed7f4740ae7776beb30873404206eab05ed04d12dca268fc8bcbec398b53eb68925f76f08b94b6fd47bbd52fdc1048202b8e1c6de85ed2578897684151d5cd368645ec80fa7d0fc990927e9c0182c886f4d359edfdcea9373699fa154f978821de933b3aff271b86c6824c4e7178580bae77ffa57a12dd74c154b76348d820699e2ab80abec3658a34eccf33e8c3b25645e927897b2cf97acd8b9605b0461adc94c726dd887acbcc4a9e1e0900decf2a67bce45ff30945b468097ef944f866046d39a3b0babbd08919c8ad582bcc0a5a51470b3280b14d5cc5a5710178e6d1d264b4b679cce3a4b898287fbda84757d2d2f34315134e213851ad53d6ff6b41c7ad2dbecc23941e4e5362e86cc5576ead6057703314d2477f92b0b80fc4fac58d5dae2fcd8626ae80a52f7057104f31799fdd541798ac215ff8eb7ea375037560da4d03ac8f8655201b765e6b56733fd31bd1de8a8c5e91f772ce24fe5d5cb13cc328b2609fb50a86a38f9f77a5b1ce37452a609174013c4148c72bcdce9768f41ca86df456e62522ef9fdf98561db57c975c800e3892f7d30f884113399fca88d38a24ac973ecc024d166688e71f67e67a547f3e2c1affc38976a213dafd3b02fcbdf57541ccb0681b56e5c6e55f0e4ea4a617f5f235ab01df040906a41539466bf1b98273d0499d2f1c00798a62e7cdfa93eb85f6628c9086300a5c208ea43be9d751a15c94e9d693747ad67c60223324692f57526ca4cc2cafa0a31808f503dbdf0d2887ca796e5fc1d8d420674a0a2f108a9ca7c275821ccb501d37d091e95cef1817ea8c63b1b6b7567b93d3ba268af85cbb58db6cfd9565168cc36d8a948cfd3f156d70f4560daa187d63f7bfcee7fb70d8d5d494e17425ff8c734f174bd2bd0bc1e2660b11b50b9f6e36779cb93f02e59a5f4477493c3473bb72c3843939a7d035629e0e841d588a7220fec17de893ba3e79e7cd28fb8997f5c637a10a8b693eb422125e6305d49c54facbc8a2bcb7fb7a84df79e779d7734c590fce40ba8ff4259581da28d373046022100d78b23c6ce821e45402576d6e46094b93a1388f1ad94df8ad77362359b324f42022100d6f8af3e9e262d693339b932b35e5ea26368c4f3db61339831aec7afed764e15"
//	var param DecrytLoginPktSM2Param
//	pkd, pubkd := deckeyget()
//	param.Privkdata = string(pkd)
//	param.Pubkdata = string(pubkd)
//	param.Data = data
//
//	//paramstr, _ := json.Marshal(param)
//	//fmt.Println("param:", string(paramstr))
//	//res := DecrytLoginPktSM2(string(paramstr))
//	res, err := DecryptLoginPktSM2(common.FromHex(data), []byte(param.Privkdata), []byte(param.Pubkdata))
//	if err != nil {
//		fmt.Println("decrypt login failed, err:", err)
//	}
//	fmt.Println("res:", res)
//}

//func TestCsrToCrt(t *testing.T) {
//	var capath = "testcrt/ca.crt"
//	var capri = "testcrt/ca.key"
//	var csr = "testcrt/gateway.req"
//	var out = "testcrt/gateway.crt"
//	ValidateCSRFromPem(csr, capath, capri, 365, out)
//}
//func TestUserPair(t *testing.T) {
//	{
//		var data = []byte("12313213213213213213213333333333333333333333333333333333333333333333")
//		var param EncryptLoginPktSM2Param
//		pkd, pubkd := keygetuser()
//		param.Username = "username"
//		param.Privkdata = string(pkd)
//		param.Pubkdata = string(pubkd)
//		param.Data = common.ToHex(data)
//
//		var deviceid = "37fca1d0ae30dbd7228c4c6de18a796ea865e3d074f791d9af010a5d5334a083"
//		var domain = "zta1.qrsecure.cn"
//
//		res, err := EncryptLoginPktSM2(domain, deviceid, param.Username, []byte(param.Privkdata), []byte(param.Pubkdata), data)
//		if err != nil {
//			fmt.Println("encrypt login failed.err:", err)
//			return
//		}
//		//fmt.Println("res:", hex.EncodeToString(res))
//
//		res, err = DecryptLoginPktSM2(res, []byte(param.Privkdata), []byte(param.Pubkdata))
//		if err != nil {
//			fmt.Println("decrypt login failed, err:", err)
//			return
//		}
//		fmt.Println("res:", res)
//		fmt.Println("user pair test succeed.")
//	}
//}
//
//func TestManagerPair(t *testing.T) {
//	{
//		var data = []byte("12313213213213213213213333333333333333333333333333333333333333333333")
//		var param EncryptLoginPktSM2Param
//		pkd, pubkd := keygetmanager()
//		param.Username = "username"
//		param.Privkdata = string(pkd)
//		param.Pubkdata = string(pubkd)
//		param.Data = common.ToHex(data)
//
//		var deviceid = "37fca1d0ae30dbd7228c4c6de18a796ea865e3d074f791d9af010a5d5334a083"
//		var domain = "zta1.qrsecure.cn"
//
//		res, err := EncryptLoginPktSM2(domain, deviceid, param.Username, []byte(param.Privkdata), []byte(param.Pubkdata), data)
//		if err != nil {
//			fmt.Println("encrypt login failed.err:", err)
//			return
//		}
//		//fmt.Println("res:", hex.EncodeToString(res))
//
//		res, err = DecryptLoginPktSM2(res, []byte(param.Privkdata), []byte(param.Pubkdata))
//		if err != nil {
//			fmt.Println("decrypt login failed, err:", err)
//			return
//		}
//		fmt.Println("res:", res)
//		fmt.Println("manager pair test succeed.")
//	}
//}
//
//func TestEncAndDecryptLoginPktSM2(t *testing.T) {
//	var fdata []byte
//	{
//		var data = []byte("12313213213213213213213333333333333333333333333333333333333333333333")
//		var param EncryptLoginPktSM2Param
//		pkd, pubkd := enckeyget()
//		param.Username = "username"
//		param.Privkdata = string(pkd)
//		param.Pubkdata = string(pubkd)
//		param.Data = common.ToHex(data)
//
//		var deviceid = "37fca1d0ae30dbd7228c4c6de18a796ea865e3d074f791d9af010a5d5334a083"
//		var domain = "zta1.qrsecure.cn"
//
//		res, err := EncryptLoginPktSM2(domain, deviceid, param.Username, []byte(param.Privkdata), []byte(param.Pubkdata), data)
//		if err != nil {
//			fmt.Println("encrypt login failed.err:", err)
//			return
//		}
//		//fmt.Println("res:", hex.EncodeToString(res))
//		fdata = res
//
//	}
//	{
//		pkd, pubkd := deckeyget()
//		res, err := DecryptLoginPktSM2(fdata, []byte(pkd), []byte(pubkd))
//		if err != nil {
//			fmt.Println("decrypt login failed, err:", err)
//			return
//		}
//		fmt.Println("res:", res)
//		fmt.Println("user with manager pair test succeed.")
//	}
//}

func TestClientEncAndDecLoginPktSM2(t *testing.T) {
	var fdata []byte
	//{
	//	var data = common.Hex2Bytes("7b226465766963655f6964223a2230353336656337376336336166643530326139366536656263393663643733633162626234386663646533636562356334383263626636363538393965386338222c227075626b6579223a22466c39654750436c34772f39582f317277524d466568324e365236666d4d58346e6a346148386b5965694d3d222c2270776468617368223a2265663739376338313138663032646662363439363037646435643366386337363233303438633963303633643533326363393563356564376138393861363466222c2274696d657374616d70223a313634343531303938302c22757365726e616d65223a2239313939222c22706173737764223a223132333435363738222c227665726966795f636f6465223a22222c227365636f6e645f766572696679436f6465223a22222c2273797374656d5f696e666f223a7b22686f73746e616d65223a224c4150544f502d4a414d3230555556222c226f736e616d65223a224d6963726f736f66742b57696e646f77732b31302b254534254238253933254534254238253941254537253839253838222c226f7376657273696f6e223a2231302e302e31393034332b4e253246412b4275696c642b3139303433222c226f7376656e646f72223a224d6963726f736f667420436f72706f726174696f6e222c22687776656e646f72223a224c454e4f564f222c22687773657269616c223a22323059333030344b5553222c22687774797065223a225043222c226465766963656964223a2230353336656337376336336166643530326139366536656263393663643733633162626234386663646533636562356334383263626636363538393965386338227d2c226c6f67696e5f746f6b656e223a22222c226970223a223139322e3136382e312e3130222c226d6163223a2237303a63643a30643a66313a38373a6634227d")
	//	var packet = &client.Packet{
	//		Payload: data,
	//		Ptype: 2,
	//	}
	//	pkd, pubkd := enckeyget()
	//	privk, err := common.SM2ReadPrivateKeyFromMem(pkd)
	//	if err != nil {
	//		fmt.Println("read private key failed, err", err)
	//		return
	//	}
	//	pubk, err := common.SM2ReadCertificateFromMem(pubkd)
	//	if err != nil {
	//		fmt.Println("read certificate failed, err", err)
	//		return
	//	}
	//	username := "9199"
	//
	//	var deviceid = "0536ec77c63afd502a96e6ebc96cd73c1bbb48fcde3ceb5c482cbf665899e8c8"
	//	var domain = "zta1.qrsecure.cn"
	//
	//
	//	res := client.NewUserCommand(username, deviceid, domain, privk, pubk, packet)
	//	if res == nil {
	//		fmt.Println("encrypt login failed.err:", err)
	//		return
	//	}
	//	fmt.Println("res:", hex.EncodeToString(res.Data()))
	//	fdata = res.Data()
	//}
	{
		fdata = common.Hex2Bytes("029c27f9b459b9778e77b1704c62ce1926dd231f7d12adbb84ecf8a2ba7b433e4307f7a61b7777ad5fa4dc6ee0ae207e1ae4a9f84ccc7906ab422eab6f8e5433562ad82d4ac287b522c7336b4215f02a76f427c67b0b603f9fb4bbd286c2f1a42b00000000000000000000000000000000000000000000000000000000000000007a7461312e71727365637572652e636e0000000000000000000000000000000003263082032202202a26c5c1f7cfb6d5acaea98edaad77020c8e463db30c2be321caf0d06d7260d702207a6e2f38185bc7a67d957474c1a775a62e84f9d4f3eb8e5861dffe80b0bac276042073e3e0f828221288ef56fe3cf871c8b55ef8ae7b977667e63a80205539c5bb92048202b885ae55d4f484b7066c7a5dccfcc8e525aec950f023cd32b8e540d6b20159d28d59a01c380f9a90f67fcde1d48690124328df3481f236fbba2ed76a4f4623864c99a39d4998160b78bcc1497f7620459a4d7731829b2ae654dd8aa740596601616288e08203f62fa9851e9f65f76556ebe8edd8ce73bb0d0fdd33a5c6d73b1175e7ac71c270f1f32c284d82687b3fda9f814bc2dd2d074f4693fc806ed56fac7a13bb24540eb86bf0045cdfd26e49db342c7c04b1b374eee38065f8f0d7818e259eb1618332f8f2176091326181d2a00973fa7760fbf8dba69a6246cb7909e6893fb5e90c664838279b9cdb9767391b20a9a40eb125b78445950c4a42f67b3f9a619b776c7056afa99bc9fe489d8434cb76f0508b29805ce9115432e4a7642a6608b011ff89ef0a5000fc5281c5be140f2fb466c6f245738a0368e78baff646c5c8459133218ac43eb5ac075db82bb70a3fbf5062df8dfa82a9646656bf2cf5425ce966761f5734c09bcbcd3ea4d46328e6ac3f9d2a6ee8bbf8f272ecf80b506cce3f0655a0502c9d93c1617b5c1734d39d285b0170c34453b34d3b268d966b46a77dad6d2b4e63b5da1e933237fd2d317603c8e515ad77dbfbb4fadd327831719e368619bac2a921072a446bca81201bf0da7045a64202b20556a8f13b722c244ff017e23fe3fb6de32d2bbf628dccd1b54f02bb055aac77358f1cba168dcf2f144f391019b86c13fa33ef67601cbb4ea1f1bbb6353565a5df86978a1e698bc1ca37d1da826f628f12d0a42b36a66216bb6a5b9ac66a23130d9fafa764ab43ee57a2907c9c1f505f29e2790b7ae582dc1d2ca26f5e5cd4d60492347a6d617f679c60b606d10e1fbae7fa75abd99e32447cec36b58d6ac867c6477fe47b8db96a4febb30a6fca0d486f86e7cef2bcafb4f13e1bda220d6044aad0810bbe981ffe169bb0776ba7df85575d8e1cffbd68c99bbddad493c9b0423045022100bbf3c0b485f4063329c069bba8e1f03fa58b06caf411eab07bd230b00b379eb80220651d94f2452012dbb55372efbef49face237b24614fa7ec605cd776d4defd871")
		pkd, pubkd := deckeyget()
		res, err := DecryptLoginPktSM2(fdata, []byte(pkd), []byte(pubkd))
		if err != nil {
			fmt.Println("decrypt login failed, err:", err)
			return
		}
		fmt.Println("res:", hex.EncodeToString(res))
		fmt.Println("client user with manager pair test succeed.")
	}
}

//func TestCertDecrypt(t *testing.T) {
//	pkd, pubkd := deckeyget()
//	if
//}
