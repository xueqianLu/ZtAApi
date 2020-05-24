package common

import (
	"log"
	"os"
)

var (
	gloger = log.New(os.Stdout, "", 0)
)

func Setlog(loger *log.Logger) {
	gloger = loger
}

func Getlog() *log.Logger {
	return gloger
}
