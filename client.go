package ZtAApi

import "C"
import "github.com/xueqianLu/ZtAApi/client"

//export clientSetOrGeneratePrivk
func clientSetOrGeneratePrivk(priv string) *C.char {
	pk := client.SetOrGeneratePrivateKey(priv)
	return C.CString(pk)
}

//export clientSetUserInfo
func clientSetUserInfo(username string, passwd string) int32 {
	client.SetUserInfo(username, passwd)
	return 0
}

//export clientSetServerInfo
func clientSetServerInfo(serveraddr string) int32 {
	client.SetServerInfo(serveraddr)
	return 0
}

//export clientGetLoginInfo
func clientGetLoginInfo() *C.char {
	info := client.GetZtALoginInfo()
	return C.CString(info)
}

//export clientLogin
func clientLogin(sysinfo string) *C.Char {
	err := client.ClientLogin(sysinfo)
	if err == nil {
		return nil
	} else {
		return C.CString(err.Error())
	}
}

//export clientLogout
func clientLogout() *C.Char {
	err := client.ClientLogout(false)
	if err == nil {
		return nil
	} else {
		return C.CString(err.Error())
	}
}

//export clientChangepwd
func clientChangepwd(newpwd string) *C.Char {
	err := client.ClientChangePwd(newpwd)
	if err == nil {
		return nil
	} else {
		return C.CString(err.Error())
	}
}
