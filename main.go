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
	IP             string
	Domain         string
	Dns            []string
	Netmask        int64
	Cidr           string
	ForwardGroup   []string
	MasterDnsRe    *regexp.Regexp
	MasterDnsReStr string
	MasterDns      []string
	BackupDnsRe    *regexp.Regexp
	BackupDnsReStr string
	BackupDns      []string
	EndChan        chan int
	JobChan        chan int
	JobNumebr      int
	DoneJobNumber  int
	MasterDnsQuery chan []string
	BakupDnsQuery  chan []string
	Timeout        time.Duration
	Msg            *dns.Msg
}

type ForwardData struct {
	LineDnsReStr string
	LineDnsRe    *regexp.Regexp
	Dns          []string
}

func main() {
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{"localhost:2379"},
		DialTimeout: 5 * time.Second,
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
	dns.HandleFunc("service.", DnsMsgProcess)

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
			err = json.Unmarshal(ev.Value, tmpAclData)
			if err != nil {
				continue
			}
			tmpRe, _ := regexp.Compile(tmpAclData.MasterDnsReStr)
			tmpAclData.MasterDnsRe = tmpRe

			tmpRe, _ = regexp.Compile(tmpAclData.BackupDnsReStr)
			tmpAclData.BackupDnsRe = tmpRe

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
			err = json.Unmarshal(ev.Value, tmpData)
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
			ip := strings.Split(string(ev.Kv.Key), "/")[4]

			switch ev.Type.String() {
			case "PUT":
				var tmpAclData AclData
				err := json.Unmarshal(ev.Kv.Value, tmpAclData)
				if err != nil {
					continue
				}
				tmpRe, _ := regexp.Compile(tmpAclData.MasterDnsReStr)
				tmpAclData.MasterDnsRe = tmpRe

				tmpRe, _ = regexp.Compile(tmpAclData.BackupDnsReStr)
				tmpAclData.BackupDnsRe = tmpRe

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
			groupName := strings.Split(keyStr, "/")[2]
			domainName := strings.Split(keyStr, "/")[3]

			switch ev.Type.String() {
			case "PUT":
				var tmpData ForwardData
				err := json.Unmarshal(ev.Kv.Value, tmpData)
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
	rch := cli.Watch(context.Background(), "/forward/", clientv3.WithPrefix())
	for wresp := range rch {
		for _, ev := range wresp.Events {
			keyStr := string(ev.Kv.Key)
			zoneName := strings.Split(keyStr, "/")[3]
			lineType := strings.Split(keyStr, "/")[4]
			addr := strings.Split(keyStr, "/")[5]
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
	ctx, cancel := context.WithTimeout(context.Background(), 10)
	resp, err = cli.Get(ctx, "key", clientv3.WithPrefix())
	cancel()
	ErrCheck(err)
	return
}

func DnsMsgProcess(w dns.ResponseWriter, r *dns.Msg) {
	// acl check , not on acl exit thread
	acl, ok := AclMap[w.RemoteAddr().String()]
	if !ok {
		return
	}

	switch r.Opcode {
	case dns.OpcodeQuery:
		acl.Msg = new(dns.Msg).SetReply(r)
		err := acl.init()
		if err == nil {
			acl.ParseQuery()
		}
	}

	w.WriteMsg(acl.Msg)

}

func (acl *AclData) init() error {
	if len(acl.Msg.Question) < 1 {
		return fmt.Errorf("question is nil")
	}

	acl.Domain = acl.Msg.Question[0].Name
	acl.CheckRquestDns(acl.Domain)
	acl.CheckLineDns()

	acl.MasterDnsQuery = make(chan []string, 10)
	acl.BakupDnsQuery = make(chan []string, 10)
	acl.EndChan = make(chan int)
	return nil
}

func (acl *AclData) ParseQuery() {
	go acl.QueryLineDns()
	var DnsQureyRR []string

	// 等待 master dns 回复
	select {
	case DnsQureyRR = <-acl.MasterDnsQuery:
	case <-acl.EndChan:
		return
	case <-time.After(3 * time.Second):
	}

	// master dns timeout，加入 bakup dns 等待
	// 再次 time out exit
	if len(DnsQureyRR) == 0 {
		select {
		case DnsQureyRR = <-acl.MasterDnsQuery:
		case DnsQureyRR = <-acl.BakupDnsQuery:
		case <-acl.EndChan:
			return
		case <-time.After(3 * time.Second):
			return
		}
	}

	// 获取取到结果，返回给用户
	for _, dnsRR := range DnsQureyRR {
		rr, err := dns.NewRR(dnsRR)
		if ErrCheck(err) {
			continue
		}
		acl.Msg.Answer = append(acl.Msg.Answer, rr)
	}

}

func (acl *AclData) QueryLineDns() {

	acl.JobChan = make(chan int, acl.JobNumebr)

	for _, dnsServer := range acl.MasterDns {
		go acl.RequestLineDns("Master", dnsServer)
	}

	for _, dnsServer := range acl.BackupDns {
		go acl.RequestLineDns("Backup", dnsServer)
	}

	for _ = range acl.JobChan {
		acl.DoneJobNumber++
		if acl.DoneJobNumber == acl.JobNumebr {
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
			acl.Dns = requestDns.Dns
			acl.MasterDnsRe = requestDns.LineDnsRe
			return
		}
	}

	if len(domainArry) == 1 {
		return
	}

	if len(domainArry) > 1 {
		for _, tmpDomain := range domainArry[1:] {
			newDomain = newDomain + "." + tmpDomain
		}
	}

	acl.CheckRquestDns(newDomain)
}

// on etcd get LineDns Servers
func (acl *AclData) CheckLineDns() {
	for key, dns := range LineDnsMap {
		if acl.MasterDnsRe.MatchString(key) {
			acl.MasterDns = append(acl.MasterDns, dns)
		}

		if acl.BackupDnsRe.MatchString(key) {
			acl.BackupDns = append(acl.BackupDns, dns)
		}
	}

	acl.JobNumebr = len(acl.MasterDns) + len(acl.BackupDns)

}

func (acl *AclData) RequestLineDns(dnsType string, lineDns string) {
	resp, err := http.Get(fmt.Sprintf("http://%s/%s/%s", lineDns, acl.Domain, acl.Dns))

	if ErrCheck(err) {
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if ErrCheck(err) {
		return
	}

	var tmpString []string
	err = json.Unmarshal(body, tmpString)

	if !ErrCheck(err) {
		switch dnsType {
		case "Master":
			acl.MasterDnsQuery <- tmpString

		case "Backup":
			acl.BakupDnsQuery <- tmpString
		}
	}
	acl.JobChan <- 1

}

func ErrCheck(err error) bool {
	if err != nil {
		log.Panicln(err.Error())
		return true
	}
	return false
}
