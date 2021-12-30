package common

import (
	"bufio"
	"fmt"
	"gopkg.in/fatih/set.v0"
	"io"
	"log"
	"os"
	"strings"
)

type DomainList struct {
	set.Interface
}

func NewDomainList(domain string) *DomainList {
	s := set.New(set.ThreadSafe)
	s.Add(domain)
	return &DomainList{s}
}

func (d *DomainList) String() string {
	var ret = ""
	d.Each(func(item interface{}) bool {
		ret = fmt.Sprintf("\t%s\t%s", item.(string), ret)
		return true
	})
	return ret
}

func (d *DomainList) Flatten() []string {
	var ret = make([]string, 0)
	d.Each(func(item interface{}) bool {
		ret = append(ret, item.(string))
		return true
	})
	return ret
}

func ParseHostsFile(path string) map[string]*DomainList {
	defer func() {
		if err := recover(); err != nil {
			log.Println("Parse host file err:", err)
		}
	}()
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
		log.Println("get splits len ", len(section))

		if len(section) > 1 {
			ip := strings.TrimSpace(section[0])
			domainlist := hostinfo[ip]
			for _, s := range section[1:] {
				//log.Println(strings.TrimSpace(ip),"--->", strings.TrimSpace(s))
				domain := strings.TrimSpace(s)
				if len(domain) < 1 {
					continue
				}
				if domainlist == nil {
					domainlist = NewDomainList(domain)
					hostinfo[ip] = domainlist
				} else {
					domainlist.Add(domain)
				}
			}
			if domainlist == nil || domainlist.Size() == 0 {
				delete(hostinfo, ip)
			}
		}
	}
	return hostinfo
}

func MergeHostMap(syshost, nhost map[string]*DomainList) map[string]*DomainList {
	var merged = make(map[string]*DomainList)
	if syshost != nil {
		for ip, domainlist := range syshost {
			ndomains := domainlist.Flatten()
			if ndomains == nil || len(ndomains) == 0 {
				continue
			}
			//log.Println("ip = ", ip, "domainlist = ", domainlist.String())
			if dlist, ok := merged[ip]; ok {
				for _, domain := range ndomains {
					dlist.Add(domain)
				}
			} else {
				for _, domain := range ndomains {
					if dlist == nil {
						dlist = NewDomainList(domain)
					} else {
						dlist.Add(domain)
					}
				}
				merged[ip] = dlist
			}
		}
	}
	if nhost != nil {
		for ip, domainlist := range nhost {
			ndomains := domainlist.Flatten()
			if ndomains == nil || len(ndomains) == 0 {
				continue
			}
			//log.Println("ip = ", ip, "domainlist = ", domainlist.String())
			if dlist := merged[ip]; dlist != nil {
				for _, domain := range ndomains {
					dlist.Add(domain)
				}
			} else {
				for _, domain := range ndomains {
					if dlist == nil {
						dlist = NewDomainList(domain)
					} else {
						dlist.Add(domain)
					}
				}
				merged[ip] = dlist
			}
		}
	}

	return merged
}

func WriteToHosts(hostinfo map[string]*DomainList, path string) error {
	fi, err := os.Create(path)
	if err != nil {
		log.Println("create error ", err)
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
