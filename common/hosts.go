package common

import (
	"bufio"
	"fmt"
	"github.com/Workiva/go-datastructures/set"
	"io"
	"log"
	"os"
	"strings"
)

type DomainList struct {
	*set.Set
}

func NewDomainList(domain string) *DomainList {
	s := set.New(domain)
	return &DomainList{s}
}

func NewDomainListWithItems(domains ...interface{}) *DomainList {
	s := set.New(domains)
	return &DomainList{s}
}

func (d *DomainList) String() string {
	v := d.Flatten()
	var ret = ""
	for _, domain := range v {
		ret = fmt.Sprintf("\t%s\t%s", domain.(string), ret)
	}
	return ret
}

func ParseHostsFile(path string) map[string]*DomainList {
	fi, err := os.Open(path)
	if err != nil {
		log.Println("open error ", err)
		return nil
	}
	defer fi.Close()

	hostinfo := make(map[string]*DomainList)
	br := bufio.NewReader(fi)
	for {
		a, _, c := br.ReadLine()
		if c == io.EOF {
			break
		}
		line := string(a)

		if strings.HasPrefix(line, "#") {
			continue
		}

		section := strings.Split(line, "\t")
		fmt.Println("get splits len ", len(section))

		if len(section) > 1 {
			ip := strings.TrimSpace(section[0])
			domainlist := hostinfo[ip]
			for _, s := range section[1:] {
				//log.Println(strings.TrimSpace(ip),"--->", strings.TrimSpace(s))
				log.Println(ip, "--->", s)
				domain := strings.TrimSpace(s)
				if domainlist == nil {
					domainlist = NewDomainList(domain)
					hostinfo[ip] = domainlist
				} else {
					domainlist.Add(domain)
				}
			}
		}
	}
	return hostinfo
}

func MergeHostMap(syshost, nhost map[string]*DomainList) map[string]*DomainList {
	var merged = make(map[string]*DomainList)
	for ip, domainlist := range syshost {
		ndomains := domainlist.Flatten()
		if dlist := merged[ip]; dlist != nil {
			dlist.Add(ndomains)
		} else {
			dlist = NewDomainListWithItems(ndomains)
			merged[ip] = dlist
		}
	}
	for ip, domainlist := range nhost {
		ndomains := domainlist.Flatten()
		if dlist := merged[ip]; dlist != nil {
			dlist.Add(ndomains)
		} else {
			dlist = NewDomainListWithItems(ndomains)
			merged[ip] = dlist
		}
	}

	return merged
}

func WriteToHosts(hostinfo map[string]*DomainList, path string) error {
	fi, err := os.Open(path)
	if err != nil {
		log.Println("open error ", err)
		return nil
	}
	defer fi.Close()

	w := bufio.NewWriter(fi)
	for ip, dlist := range hostinfo {
		lineStr := fmt.Sprintf("%s%s", ip, dlist.String())
		fmt.Fprintln(w, lineStr)
	}
	return w.Flush()
}
