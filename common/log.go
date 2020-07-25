package common

import (
	"io"
	"log"
)

var (
//gloger = log.New(os.Stdout, "", 0)
)

func Setlog(writer io.Writer) {
	log.SetOutput(writer)
	log.SetFlags(0)
}

//
//func Getlog() *log.Logger {
//	log.Println()
//	return gloger
//}
