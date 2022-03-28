package main

import (
	"encoding/base64"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
)

func makeData(reg *regexp.Regexp) []byte {
	rsp, err := http.Get("https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt")
	if err != nil {
		panic(err)
	}
	rspData, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		panic(err)
	}
	strData, err := base64.StdEncoding.DecodeString(string(rspData))
	if err != nil {
		panic(err)
	}
	lines := strings.Split(string(strData), "\n")
	directMap := make(map[string]bool, len(lines))
	//value true means suffix,false means all match
	proxyMap := make(map[string]bool, len(lines))
	unknownMap := make(map[string]bool, len(lines))
	for _, line := range lines {
		if len(line) < 2 {
			unknownMap[line] = true
			continue
		}
		switch line[0] {
		case '!', '[':
			break
		case '|':
			if line[1] == '|' {
				//||: Stands for matching specific URI, in such a case, no need to write down scheme, e.g. ||example.com will match (replace www with any subdomain):
				//http://example.com
				//http://www.example.com
				//https://example.com
				//https://www.example.com
				//
				//It will NOT match:
				//
				//http://anotherexample.com
				//https://anotherexample.com
				//http://example.com.co
				//https://example.com.co
				if name := reg.FindString(line); name != "" {
					proxyMap[name] = true
				} else {
					unknownMap[line] = true
				}
			} else {
				//|: Stands for matching from beginning (In URI, it's scheme): e.g.|http://example.com will match:
				//http://example.com
				//http://example.com/page
				//http://example.com.co
				//
				//It will NOT match (replace www with any subdomain):
				//
				//http://www.example.com
				//https://example.com/page
				//https://example.com
				//https://www.example.com
				//https://example.com.co
				if name := reg.FindString(line); name != "" {
					proxyMap[name] = false
				} else {
					unknownMap[line] = false
				}
			}
			break
		case '.':
			//.example.com
			//It means example.com is suffering a block while http://sub.example.com is not brought in.
			if name := reg.FindString(line); name != "" {
				proxyMap[name] = true
			} else {
				unknownMap[line] = true
			}
			break
		case '@':
			//@@: Stands for whitelist rules.
			//Although GFWList was designed to conform to the GFW mechanisms,
			//it still has consideration of whitelist since sometimes there are some exceptions under special circumstances.
			//			@@|http://blog.ontrac.com
			if len(line) > 11 && strings.Contains(line[11:], "/") {
				unknownMap[line] = true
				break
			}
			if name := reg.FindString(line); name != "" {
				directMap[name] = true
			} else {
				unknownMap[line] = false
			}
			break
		default:
			if name := reg.FindString(line); name != "" {
				proxyMap[name] = false
			} else {
				unknownMap[line] = false
			}
			break
		}
	}
	sb := strings.Builder{}
	sb.Write(initData)
	sb.WriteString("[Rule]\n")
	for line, _ := range directMap {
		sb.WriteString("DOMAIN,")
		sb.WriteString(line)
		sb.WriteString(",DIRECT\n")
	}
	for line, b := range proxyMap {
		if b {
			sb.WriteString("DOMAIN-SUFFIX,")
		} else {
			sb.WriteString("DOMAIN,")
		}
		sb.WriteString(line)
		sb.WriteString(",PROXY\n")
	}
	sb.WriteString("[Host]\nlocalhost = 127.0.0.1\n")
	return []byte(sb.String())
}

var initData = []byte(`# Shadowrocket: 2022-03-25 16:07:46
[General]
bypass-system = true
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local, captive.apple.com
tun-excluded-routes = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 255.255.255.255/32
dns-server = system
ipv6 = true
prefer-ipv6 = false
dns-fallback-system = false
dns-direct-system = false
icmp-auto-reply = true
always-reject-url-rewrite = false
private-ip-answer = true
dns-direct-fallback-proxy = true
`)

func main() {
	reg := regexp.MustCompile(`[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+`)
	if reg == nil {
		panic("reg is nil")
	}
	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		rs := makeData(reg)
		writer.Write(rs)
	})
	http.ListenAndServe(":8082", nil)
}
