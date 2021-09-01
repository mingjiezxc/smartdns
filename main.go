package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/etcd/clientv3"
	"github.com/miekg/dns"
)

var (
	DnsMsgChan      = make(chan DnsMsg, 100000)
	cli             *clientv3.Client
	LineDnsServers  []string
	AclMap          = make(map[string]AclData)
	ForwardGroupMap = make(map[string]map[string]ForwardData)
	LineDnsMap      = make(map[string]string)
)

type DnsMsg struct {
	Addr *net.UDPAddr
	Msg  []byte
}

type AclData struct {
	// source ip
	IP string `json:"IP"`

	// acl data
	Netmask int64
	Cidr    string

	// forward group list
	ForwardGroup []string

	// Master linedns 正则表达式文本
	MasterLineDnsReStr string
	// Master 使用的上层DNS
	MasterDns []string

	// backup linedns 正则表达式文本
	BackupLineDnsReStr string
	// backup 使用的上层DNS
	BackupDns []string

	// master & backup linedns query timeout
	Timeout int64

	// tmp data
	MasterLineDnsRe    *regexp.Regexp
	MasterLineDns      []string
	BackupLineDnsRe    *regexp.Regexp
	BackupLineDns      []string
	Domain             string
	EndChan            chan int
	JobChan            chan int
	JobNumber          int
	DoneJobNumber      int
	MasterLineDnsQuery chan string
	BakupDnsQuery      chan string
	Msg                *dns.Msg
}

type ForwardData struct {
	LineDnsReStr string `json:"lineDnsReStr"`
	LineDnsRe    *regexp.Regexp
	Dns          []string `json:"dns"`
}

type ForwardData2 struct {
	LineDnsReStr string   `json:"lineDnsReStr"`
	Dns          []string `json:"dns"`
}

func main() {
	var err error
	cli, err = clientv3.New(clientv3.Config{
		Endpoints:   []string{"localhost:2379"},
		DialTimeout: 10 * time.Second,
	})
	if ErrCheck(err) {
		os.Exit(1)
	}
	defer cli.Close()

	go AclMapWatch()
	go ForwardGroupMapWatch()
	go LineDnsMapWatch()

	EtcdDataInit()

	// attach request handler func
	dns.HandleFunc(".", DnsMsgProcess)

	// start server
	port := 5353
	server := &dns.Server{Addr: ":" + strconv.Itoa(port), Net: "udp"}
	log.Printf("Starting at %d\n", port)
	err = server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}

}

func EtcdDataInit() {
	// /acl/ip/pool/$ip
	// /forward/abc/hk
	// /line/dns/bj/ct/192.168.1.2
	// /line/dns/hk/hk/19.168.1.2

	// update acldata
	if resp, err := EtcdClinet("/acl/ip/pool/"); err == nil {
		for _, ev := range resp.Kvs {
			ip := strings.Split(string(ev.Key), "/")[4]
			var tmpAclData AclData
			err = json.Unmarshal(ev.Value, &tmpAclData)
			if err != nil {
				continue
			}
			tmpRe, _ := regexp.Compile(tmpAclData.MasterLineDnsReStr)
			tmpAclData.MasterLineDnsRe = tmpRe

			tmpRe, _ = regexp.Compile(tmpAclData.BackupLineDnsReStr)
			tmpAclData.BackupLineDnsRe = tmpRe

			AclMap[ip] = tmpAclData
		}
	}

	// update forward
	if resp, err := EtcdClinet("/forward/"); err == nil {
		for _, ev := range resp.Kvs {
			keyStr := string(ev.Key)
			groupName := strings.Split(keyStr, "/")[2]
			domainName := strings.Split(keyStr, "/")[3]

			var tmpData ForwardData
			err = json.Unmarshal(ev.Value, &tmpData)
			if err != nil {
				continue
			}

			tmpRe, _ := regexp.Compile(tmpData.LineDnsReStr)
			tmpData.LineDnsRe = tmpRe
			ForwardGroupMap[groupName] = map[string]ForwardData{domainName: tmpData}
		}
	}

	// update LineDnsMap
	if resp, err := EtcdClinet("/line/dns/"); err == nil {
		for _, ev := range resp.Kvs {
			keyStr := string(ev.Key)
			zoneName := strings.Split(keyStr, "/")[3]
			lineType := strings.Split(keyStr, "/")[4]
			addr := strings.Split(keyStr, "/")[5]
			newKey := "/" + zoneName + "/" + lineType + "/"
			LineDnsMap[newKey] = addr
		}
	}
}

func AclMapWatch() {
	rch := cli.Watch(context.Background(), "/acl/ip/pool/", clientv3.WithPrefix())
	for wresp := range rch {
		for _, ev := range wresp.Events {
			tmpList := strings.Split(string(ev.Kv.Key), "/")
			if len(tmpList) != 5 {
				continue
			}

			ip := tmpList[4]

			switch ev.Type.String() {
			case "PUT":
				var tmpAclData AclData
				err := json.Unmarshal(ev.Kv.Value, &tmpAclData)
				if err != nil {
					continue
				}
				tmpRe, _ := regexp.Compile(tmpAclData.MasterLineDnsReStr)
				tmpAclData.MasterLineDnsRe = tmpRe

				tmpRe, _ = regexp.Compile(tmpAclData.BackupLineDnsReStr)
				tmpAclData.BackupLineDnsRe = tmpRe

				AclMap[ip] = tmpAclData
			case "DELETE":
				delete(AclMap, ip)
			}
		}
	}
}

func ForwardGroupMapWatch() {
	rch := cli.Watch(context.Background(), "/forward/", clientv3.WithPrefix())
	for wresp := range rch {
		for _, ev := range wresp.Events {
			keyStr := string(ev.Kv.Key)
			tmpList := strings.Split(keyStr, "/")
			if len(tmpList) != 4 {
				continue
			}

			groupName := tmpList[2]
			domainName := tmpList[3]

			switch ev.Type.String() {
			case "PUT":
				var tmpData ForwardData
				err := json.Unmarshal(ev.Kv.Value, &tmpData)
				if err != nil {
					continue
				}
				tmpRe, _ := regexp.Compile(tmpData.LineDnsReStr)
				tmpData.LineDnsRe = tmpRe
				ForwardGroupMap[groupName] = map[string]ForwardData{domainName: tmpData}

			case "DELETE":
				delete(ForwardGroupMap[groupName], domainName)
			}
		}
	}
}

func LineDnsMapWatch() {
	rch := cli.Watch(context.Background(), "/line/dns/", clientv3.WithPrefix())
	for wresp := range rch {
		for _, ev := range wresp.Events {
			keyStr := string(ev.Kv.Key)
			tmpList := strings.Split(keyStr, "/")

			if len(tmpList) != 6 {
				continue
			}

			zoneName := tmpList[3]
			lineType := tmpList[4]
			addr := tmpList[5]
			newKey := "/" + zoneName + "/" + lineType + "/"

			switch ev.Type.String() {
			case "PUT":
				LineDnsMap[newKey] = addr

			case "DELETE":
				delete(LineDnsMap, newKey)
			}
		}
	}
}

func EtcdClinet(key string) (resp *clientv3.GetResponse, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	resp, err = cli.Get(ctx, key, clientv3.WithPrefix())
	cancel()
	ErrCheck(err)
	return
}

func DnsMsgProcess(w dns.ResponseWriter, r *dns.Msg) {

	// acl check , not on acl exit thread
	addr := strings.Split(w.RemoteAddr().String(), ":")[0]

	acl, ok := AclMap[addr]
	// Not on Acl exit
	if !ok {
		w.WriteMsg(r)
		return
	}

	acl.Msg = new(dns.Msg).SetReply(r)

	// check query is nil exit
	if len(acl.Msg.Question) < 1 {
		return
	}

	acl.Domain = acl.Msg.Question[0].Name
	acl.CheckRquestDns(acl.Domain)
	acl.CheckLineDns()

	acl.MasterLineDnsQuery = make(chan string, 10)
	acl.BakupDnsQuery = make(chan string, 10)
	acl.EndChan = make(chan int)

	acl.ParseQuery()

	w.WriteMsg(acl.Msg)

}

func (acl *AclData) ParseQuery() {
	go acl.QueryLineDns()
	var DnsQureyRR string

	// 等待 master dns 回复
	select {
	case DnsQureyRR = <-acl.MasterLineDnsQuery:
	case <-acl.EndChan:
		return
	case <-time.After(time.Duration(acl.Timeout) * time.Second):
	}

	// master dns timeout，加入 bakup dns 等待
	// 再次 time out exit
	if len(DnsQureyRR) == 0 {
		select {
		case DnsQureyRR = <-acl.MasterLineDnsQuery:
		case DnsQureyRR = <-acl.BakupDnsQuery:
		case <-acl.EndChan:
			return
		case <-time.After(1 * time.Second):
			return
		}
	}

	// 获取取到结果，返回给用户
	rrList := strings.Split(DnsQureyRR, "\n")

	for _, dnsRR := range rrList {
		rr, _ := dns.NewRR(dnsRR)
		if rr != nil {
			acl.Msg.Answer = append(acl.Msg.Answer, rr)
		}
	}

}

func (acl *AclData) QueryLineDns() {

	acl.JobChan = make(chan int, acl.JobNumber)

	for _, dnsServer := range acl.MasterLineDns {
		go acl.RequestLineDns("Master", dnsServer)
	}

	for _, dnsServer := range acl.BackupLineDns {
		go acl.RequestLineDns("Backup", dnsServer)
	}

	for _ = range acl.JobChan {
		acl.DoneJobNumber++
		if acl.DoneJobNumber == acl.JobNumber {
			return
		}
	}

}

// get 需要查询的上层DNS
func (acl *AclData) CheckRquestDns(domain string) {

	domainArry := strings.Split(domain, ".")
	var newDomain string

	for _, group := range acl.ForwardGroup {
		if requestDns, ok := ForwardGroupMap[group][domain]; ok {
			acl.MasterDns = requestDns.Dns
			acl.MasterLineDnsRe = requestDns.LineDnsRe
			return
		}
	}

	if len(domainArry) == 1 {
		return
	}

	if len(domainArry) > 1 {
		for _, tmpDomain := range domainArry[1:] {
			if newDomain == "" {
				newDomain = tmpDomain
			} else {
				newDomain = newDomain + "." + tmpDomain

			}
		}
	}

	acl.CheckRquestDns(newDomain)
}

// on etcd get LineDns Servers
func (acl *AclData) CheckLineDns() {
	for key, dns := range LineDnsMap {
		if acl.MasterLineDnsRe.MatchString(key) {
			acl.MasterLineDns = append(acl.MasterLineDns, dns)
		}

		if acl.BackupLineDnsRe.MatchString(key) {
			acl.BackupLineDns = append(acl.BackupLineDns, dns)
		}
	}

	acl.JobNumber = (len(acl.MasterLineDns) * len(acl.MasterDns)) + (len(acl.BackupLineDns) * len(acl.BackupDns))

}

func (acl *AclData) RequestLineDns(dnsType string, lineDns string) {
	q := acl.Msg.Question[0]

	url := fmt.Sprint("http://" + lineDns + "/query/" + q.Name + "/" + strconv.Itoa(int(q.Qtype)) + "/" + strconv.Itoa(int(q.Qclass)) + "/")

	var tDns []string
	switch dnsType {
	case "Master":
		tDns = acl.MasterDns
	case "Backup":
		tDns = acl.BackupDns
	}

	for _, d := range tDns {
		go acl.RequestLineDnsHttp(dnsType, url+d)
	}

}

func (acl *AclData) RequestLineDnsHttp(dnsType string, url string) {
	resp, err := http.Get(url)

	if ErrCheck(err) {
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if ErrCheck(err) {
		return
	}

	// var tmpString string
	// err = json.Unmarshal(body, &tmpString)

	if !ErrCheck(err) {
		switch dnsType {
		case "Master":
			acl.MasterLineDnsQuery <- string(body)

		case "Backup":
			acl.BakupDnsQuery <- string(body)
		}
	}
	acl.JobChan <- 1
}

func ErrCheck(err error) bool {
	if err != nil {
		log.Println(err.Error())
		return true
	}
	return false
}
