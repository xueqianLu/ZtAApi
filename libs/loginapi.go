package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/xueqianLu/ZtAApi/client"
	"github.com/xueqianLu/ZtAApi/common"
	"github.com/xueqianLu/ZtAApi/conf"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	ServerHost     = "127.0.0.1"
	ServerPort     = 36680
	RequestTimeout = 10 * time.Second
	MaxReadBuffer  = 60000
)

var (
	managerCerts  = sync.Map{} //make(map[string]*sm2.Certificate) // server ==> manager certs
	globalSysInfo = &common.SystemInfo{}
	userConfigs   = sync.Map{} //make(map[string]*userInfo)
)

type userInfo struct {
	username    string
	password    string
	server      string
	sysinfo     *common.SystemInfo
	managerCert *sm2.Certificate
	Sm2Priv     *sm2.PrivateKey
	Sm2Public   *sm2.PublicKey
	privk       *conf.Key
	csr         []byte
}

func checkAndGetUserConfig(user string, password string, server string, ninfo *userInfo) error {
	var err error
	if data, exist := userConfigs.Load(user); !exist {
		ninfo.username = user
		ninfo.password = password
		ninfo.server = server
		ninfo.Sm2Priv, _ = common.SM2GenerateKey()
		ninfo.Sm2Public = &ninfo.Sm2Priv.PublicKey
		ninfo.privk, _ = conf.NewPrivateKey()
		ninfo.csr, _ = common.SM2CreateCertificateRequestToMem(user, ninfo.Sm2Priv)
		userConfigs.Store(user, ninfo)
	} else {
		info := data.(*userInfo)
		ninfo.managerCert = info.managerCert
		ninfo.password = info.password
		ninfo.server = info.server
		ninfo.csr = info.csr
		ninfo.privk = info.privk
		ninfo.Sm2Priv = info.Sm2Priv
		ninfo.Sm2Public = info.Sm2Public
		ninfo.username = info.username
	}
	return err
}

func requestWithTimeout(conn net.Conn, data []byte, timeout time.Duration) ([]byte, error) {
	//log.Println("write to server ", hex.EncodeToString(cmd.Data()))
	if _, err := conn.Write(data); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ch := make(chan error, 1)
	msg := make([]byte, MaxReadBuffer)
	readLen := 0
	go func() {
		//log.Println("wait to read msg")
		rlen, err := conn.Read(msg)
		readLen = rlen
		log.Println("read msg from server len ", rlen, "at time ", time.Now().String()) //, "msg", hex.EncodeToString(msg))
		ch <- err
	}()

	select {
	case <-ctx.Done():
		// request timeout
		log.Println("request context timeout at ", time.Now().String())
		return nil, client.ErrRequestTimeout
	case err, _ := <-ch:
		if err != nil {
			return nil, err
		} else {
			log.Println("request return with msg", hex.EncodeToString(msg[:readLen]))
			return msg[:readLen], nil
		}
	}
}

func requestToServer(server string, cmd client.Command) ([]byte, error) {
	ip := server

	serverAddr := ip + ":" + strconv.Itoa(ServerPort)
	log.Println("request to server", serverAddr)

	var response []byte
	var reserr error
	for i := 0; i < 1; i++ {
		log.Println("send request times ", i)
		conn, err := net.Dial("udp", serverAddr)
		if err != nil {
			log.Println("net.Dial failed, err", err)
			return nil, err
		}

		response, reserr = requestWithTimeout(conn, cmd.Data(), time.Second*5)
		conn.Close()
		if reserr == client.ErrRequestTimeout {
			continue
		} else {
			break
		}
	}
	return response, reserr

}

func lightLogin(userName string, password string, server string,
	sysinfo string, managerCert string) ([]byte, error) {

	info := &userInfo{}
	var err error
	var res, decPac []byte
	checkAndGetUserConfig(userName, password, server, info)

	if globalSysInfo == nil {
		var nsysinfo = &common.SystemInfo{}
		err = json.Unmarshal([]byte(sysinfo), &nsysinfo)
		if err != nil {
			log.Println("ClientLogin parse sysinfo failed, sysinfo:", sysinfo)
			return nil, err
		}
		info.sysinfo = nsysinfo
		globalSysInfo = nsysinfo
	}

	cert, err := sm2.ReadCertificateFromPem(managerCert)
	if err != nil {
		fmt.Errorf("read manager cert failed (%s)\n", err)
		return nil, err
	}
	if cert == nil && needExchangeCert(server) {
		fmt.Printf("goto exchenage cert\n")
		clientExchangeCert(info)
	}
	for i := 0; i < 6; i++ {
		cmd, e := client.NewLoginCmd(info.username, info.password, info.privk.Public().String(), globalSysInfo.DeviceId,
			info.Sm2Priv, info.managerCert, *info.sysinfo, "", "")
		if cmd == nil || e != nil {
			log.Println("NewLoginCmd failed", "err", e.Error())
			return nil, e
		}

		res, err = requestToServer(info.server, cmd)
		if err == client.ErrRequestTimeout {
			continue
		}
		if err != nil {
			log.Println("request to server err:", err)
			return nil, err
		}
		// den
		decPac, err = client.GetDecryptResponseWithSign(info.username, res, info.Sm2Priv, info.managerCert)
		if err == common.ErrSM2Decrypt {
			continue
		}
		if err != nil {
			return nil, err
		}
		break
	}
	if err != nil {
		return nil, err
	}
	head := &client.ServerResponse{}
	if err = json.Unmarshal(decPac, &head); err != nil {
		log.Println("decpac unmarshal to server response failed.")
		return nil, err
	}
	// parse res
	var login = &client.LoginResponse{}
	if err = json.Unmarshal(decPac, &login); err != nil {
		log.Println("decpac unmarshal to LoginResponse failed.")
		return nil, err
	} else {
		d, _ := json.Marshal(login)
		return d, nil
	}
	//
	//var userConfig string
	//userConfig += login.SliceInfo
	//var reqSliceOffset = login.SliceOffset + 1
	//for i := reqSliceOffset; i < login.SliceCount; i++ {
	//	if configSlice, e := ClientReqSliceInfo(info, i); e != nil {
	//		log.Println("request userconfig failed, e:", e.Error())
	//		return nil, e
	//	} else {
	//		userConfig += configSlice.SliceInfo
	//	}
	//}
	//allConfigInfo := &conf.AllConfigInfo{}
	//allConfigInfo.VerifyType = login.VerifyType
	//
	//if len(userConfig) > 0 {
	//	if decodedConfig, ne := common.Base64Decode(userConfig); ne != nil {
	//		return nil, errors.New(fmt.Sprintf("decode userconfig failed, e:%s", ne.Error()))
	//	} else {
	//		log.Println("after decode base64:", decodedConfig)
	//		if err = json.Unmarshal(decodedConfig, &allConfigInfo); err != nil {
	//			log.Println("user login, unmarshal to allConfigInfo failed.")
	//			return nil, err
	//		}
	//	}
	//}
	//if head.Status != 1 {
	//	msg, _ := common.Base64Decode(head.Msg)
	//	err = errors.New(string(msg))
	//}
	//d,_ := json.Marshal(allConfigInfo)
	//
	//return d, err

}

func needExchangeCert(server string) bool {
	if _, exist := managerCerts.Load(server); exist {
		return false
	} else {
		return true
	}
}

func clientExchangeCert(info *userInfo) error {
	var err error
	var res, decPac []byte
	var csr []byte

	csr = info.csr
	if csr == nil {
		return errors.New("have no scsr data")
	}

	for retry := 0; retry < 6; retry++ {
		cmd, e := client.NewNormalExchangeCertCmd(info.username, info.password, string(csr), *info.sysinfo)
		if e != nil {
			log.Println("NewLoginCmd failed", "err", e.Error())
			return e
		}
		res, err = requestToServer(info.server, cmd)
		if err == client.ErrRequestTimeout {
			continue
		}
		if err != nil {
			return err
		}
		// den
		decPac, err = client.GetDecryptResponseWithHmac(info.username, cmd.Key2, res)
		if err == common.ErrSM2Decrypt {
			continue
		}
		if err != nil {
			return err
		}
		break
	}

	if err != nil {
		return err
	}

	head := &client.ServerResponse{}
	if err = json.Unmarshal(decPac, &head); err != nil {
		log.Println("decpac unmarshal to server response failed.")
		return err
	}
	//log.Printf("decode login response status = %d\n", head.Status)
	if head.Status != 1 {
		msg, _ := common.Base64Decode(head.Msg)
		err = errors.New(string(msg))
		return err
	}

	// parse res
	var resinfo = &client.ExchangeCertResponse{}
	if err = json.Unmarshal(decPac, &resinfo); err != nil {
		log.Println("decpac unmarshal to LoginResponse failed.")
		return err
	}

	var certData string
	certData += resinfo.SliceInfo
	var reqSliceOffset = resinfo.SliceOffset + 1
	for i := reqSliceOffset; i < resinfo.SliceCount; i++ {
		if certSlice, e := ClientReqCertSlice(info, i); e != nil {
			log.Println("request cert slice failed, e:", e.Error())
			return e
		} else {
			certData += certSlice.SliceInfo
		}
	}
	var certs = &client.CertResData{}
	if len(certData) > 0 {
		if decodeCerts, ne := common.Base64Decode(certData); ne != nil {
			return errors.New(fmt.Sprintf("decode cert data failed, e:%s", ne.Error()))
		} else {
			log.Println("after decode base64:", decodeCerts)
			if err = json.Unmarshal(decodeCerts, &certs); err != nil {
				log.Println("exchange certs, unmarshal to certResData failed, ", err.Error())
				return err
			}
		}
	}
	cert, _ := common.SM2ReadCertificateFromMem([]byte(certs.ManagerCert))
	managerCerts.Store(info.server, cert)
	info.managerCert = cert
	return nil
}

func ClientReqCertSlice(info *userInfo, offset int) (*client.SliceInfoResData, error) {
	var err error
	var res, decPac []byte
	var csr []byte

	csr = info.csr
	if csr == nil {
		return nil, errors.New("have no scsr data")
	}

	for retry := 0; retry < 6; retry++ {
		cmd, e := client.NewNormalReqCertSliceCmd(info.username, info.password, offset, *info.sysinfo)
		if e != nil {
			log.Println("NewReqCertSliceCmd failed", "err", e.Error())
			return nil, e
		}
		res, err = requestToServer(info.server, cmd)
		if err == client.ErrRequestTimeout {
			continue
		}
		if err != nil {
			return nil, err
		}
		// den
		decPac, err = client.GetDecryptResponseWithHmac(info.username, cmd.Key2, res)
		if err == common.ErrSM2Decrypt {
			continue
		}
		if err != nil {
			return nil, err
		}

		break
	}
	if err != nil {
		return nil, err
	}
	head := &client.ServerResponse{}
	if err = json.Unmarshal(decPac, &head); err != nil {
		log.Println("decpac unmarshal to server response failed.")
		return nil, err
	}
	//log.Printf("decode login response status = %d\n", head.Status)
	if head.Status != 1 {
		msg, _ := common.Base64Decode(head.Msg)
		err = errors.New(string(msg))
		return nil, err
	}

	// parse res
	var resinfo = &client.ExchangeCertResponse{}
	if err = json.Unmarshal(decPac, &resinfo); err != nil {
		log.Println("decpac unmarshal to LoginResponse failed.")
		return nil, err
	}
	return &resinfo.SliceInfoResData, nil
}

func ClientReqSliceInfo(info *userInfo, offset int) (*client.SliceInfoResData, error) {

	var res, decPac []byte
	var err error
	for retry := 0; retry < 6; retry++ {
		managerCert := info.managerCert
		cmd, _ := client.NewReqUserInfoCmd(info.username, info.password, info.sysinfo.DeviceId, offset, info.Sm2Priv, managerCert)
		res, err = requestToServer(info.server, cmd)
		if err == client.ErrRequestTimeout {
			continue
		}
		if err != nil {
			return nil, err
		}
		// den
		decPac, err = client.GetDecryptResponseWithSign(info.username, res, info.Sm2Priv, managerCert)
		if err == common.ErrSM2Decrypt {
			continue
		}
		if err != nil {
			return nil, err
		}
		break
	}
	if err != nil {
		return nil, err
	}

	head := &client.ServerResponse{}
	if err = json.Unmarshal(decPac, &head); err != nil {
		log.Println("decpac unmarshal to server response failed.")
		return nil, err
	}
	if head.Status != 1 {
		msg, _ := common.Base64Decode(head.Msg)
		err = errors.New(string(msg))
		return nil, err
	}
	// parse res
	var slist = &client.UserInfoResponse{}
	if err = json.Unmarshal(decPac, &slist); err != nil {
		log.Println("decpac unmarshal to LoginResponse failed.")
		return nil, err
	}
	return &slist.SliceInfoResData, nil
}
