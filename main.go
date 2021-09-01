package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
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
	"gopkg.in/yaml.v2"
)

var (
	appConfig YamlConfig
	// etcd client
	cli *clientv3.Client

	// etcd data
	AclMap          = make(map[string]AclData)
	ForwardGroupMap = make(map[string]map[string]ForwardData)
	LineDnsMap      = make(map[string]string)
)

type YamlConfig struct {
	AppName       string   `yaml:"AppName"`
	ListeningPort int      `yaml:"ListeningPort"`
	EtcdServers   []string `yaml:"EtcdServers"`
	EtcdUser      string   `yaml:"EtcdUser"`
	EtcdPassword  string   `yaml:"EtcdPassword"`
}

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

func init() {

	// read config file
	configfile, err := ioutil.ReadFile("./config.yaml")
	if ErrCheck(err) {
		os.Exit(1)
	}

	// yaml marshal config
	err = yaml.Unmarshal(configfile, &appConfig)
	if ErrCheck(err) {
		os.Exit(2)
	}

	cli, err = clientv3.New(clientv3.Config{
		Endpoints:   appConfig.EtcdServers,
		Username:    appConfig.EtcdUser,
		Password:    appConfig.EtcdPassword,
		DialTimeout: 10 * time.Second,
	})
	if ErrCheck(err) {
		os.Exit(3)
	}

}

func main() {

	defer cli.Close()

	// 监听数据变更，实时更新数据
	go AclMapWatch()
	go ForwardGroupMapWatch()
	go LineDnsMapWatch()

	// 注册 app
	go EtcdAppRegedit()

	// 获取所有 acl ,forward 数据 进行初始化
	EtcdDataInit()

	// attach request handler func
	dns.HandleFunc(".", DnsMsgProcess)

	// start server
	server := &dns.Server{Addr: ":" + strconv.Itoa(appConfig.ListeningPort), Net: "udp"}
	log.Printf("Starting at %d\n", appConfig.ListeningPort)
	err := server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}

}

// on etcd  KeepAlive app key
func EtcdAppRegedit() {
	for {
		resp, err := cli.Grant(context.TODO(), 10)
		if ErrCheck(err) {
			continue
		}

		key := "/smartdns/app/" + appConfig.AppName

		_, err = cli.Put(context.TODO(), key, "online", clientv3.WithLease(resp.ID))
		if ErrCheck(err) {
			continue
		}

		// to renew the lease only once
		_, err = cli.KeepAlive(context.TODO(), resp.ID)
		if ErrCheck(err) {
			continue
		}
		break
	}
	log.Println("EtcdAppRegedit Config done")
}

func EtcdDataInit() {
	// /acl/ip/pool/$ip
	// /forward/abc/hk
	// /line/dns/bj/ct/192.168.1.2
	// /line/dns/hk/hk/19.168.1.2

	// update acldata
	if resp, err := EtcdClinet("/acl/ip/pool/"); err == nil {
		for _, ev := range resp.Kvs {
			AclMapUpdate("PUT", ev.Key, ev.Value)
		}
	}

	// update forward
	if resp, err := EtcdClinet("/forward/"); err == nil {
		for _, ev := range resp.Kvs {
			ForwardGroupMapUpdate("PUT", ev.Key, ev.Value)
		}
	}

	// update LineDnsMap
	if resp, err := EtcdClinet("/line/dns/"); err == nil {
		for _, ev := range resp.Kvs {
			LineDnsMapUpdate("PUT", ev.Key, ev.Value)
		}
	}
}

func AclMapUpdate(typeStr string, key []byte, value []byte) error {
	tmpList := strings.Split(string(key), "/")
	if len(tmpList) != 5 {
		return fmt.Errorf("key len err")
	}

	ip := tmpList[4]

	switch typeStr {
	case "PUT":
		var tmpAclData AclData
		err := json.Unmarshal(value, &tmpAclData)
		if err != nil {
			return err
		}
		tmpRe, _ := regexp.Compile(tmpAclData.MasterLineDnsReStr)
		tmpAclData.MasterLineDnsRe = tmpRe

		tmpRe, _ = regexp.Compile(tmpAclData.BackupLineDnsReStr)
		tmpAclData.BackupLineDnsRe = tmpRe

		AclMap[ip] = tmpAclData
	case "DELETE":
		delete(AclMap, ip)
	}
	return nil
}

func AclMapWatch() {
	rch := cli.Watch(context.Background(), "/acl/ip/pool/", clientv3.WithPrefix())
	for wresp := range rch {
		for _, ev := range wresp.Events {
			AclMapUpdate(ev.Type.String(), ev.Kv.Key, ev.Kv.Value)
		}
	}
}

func ForwardGroupMapUpdate(typeStr string, key []byte, value []byte) error {
	keyStr := string(key)
	tmpList := strings.Split(keyStr, "/")
	if len(tmpList) != 4 {
		return fmt.Errorf("key len err")
	}

	groupName := tmpList[2]
	domainName := tmpList[3]

	switch typeStr {
	case "PUT":
		var tmpData ForwardData
		err := json.Unmarshal(value, &tmpData)
		if err != nil {
			return err
		}
		tmpRe, _ := regexp.Compile(tmpData.LineDnsReStr)
		tmpData.LineDnsRe = tmpRe
		ForwardGroupMap[groupName] = map[string]ForwardData{domainName: tmpData}

	case "DELETE":
		delete(ForwardGroupMap[groupName], domainName)
	}
	return nil
}

func ForwardGroupMapWatch() {
	rch := cli.Watch(context.Background(), "/forward/", clientv3.WithPrefix())
	for wresp := range rch {
		for _, ev := range wresp.Events {
			ForwardGroupMapUpdate(ev.Type.String(), ev.Kv.Key, ev.Kv.Value)
		}
	}
}

func LineDnsMapUpdate(typeStr string, key []byte, value []byte) error {

	keyStr := string(key)
	tmpList := strings.Split(keyStr, "/")

	if len(tmpList) != 6 {
		return fmt.Errorf("key len err")
	}

	zoneName := tmpList[3]
	lineType := tmpList[4]
	addr := tmpList[5]
	newKey := "/" + zoneName + "/" + lineType + "/"

	switch typeStr {
	case "PUT":
		LineDnsMap[newKey] = addr

	case "DELETE":
		delete(LineDnsMap, newKey)
	}
	return nil
}

func LineDnsMapWatch() {
	rch := cli.Watch(context.Background(), "/line/dns/", clientv3.WithPrefix())
	for wresp := range rch {
		for _, ev := range wresp.Events {
			LineDnsMapUpdate(ev.Type.String(), ev.Kv.Key, ev.Kv.Value)
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

	addr := strings.Split(w.RemoteAddr().String(), ":")[0]

	// acl check , not on acl exit thread
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

	// init data
	acl.Domain = acl.Msg.Question[0].Name
	acl.CheckRquestDns(acl.Domain)
	acl.CheckLineDns()

	acl.MasterLineDnsQuery = make(chan string, 10)
	acl.BakupDnsQuery = make(chan string, 10)
	acl.EndChan = make(chan int)

	// 开始请求 line dns
	acl.ParseQuery()

	// 返回给用户
	w.WriteMsg(acl.Msg)

}

func (acl *AclData) ParseQuery() {

	// start query
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

	switch dnsType {
	case "Master":
		for _, d := range acl.MasterDns {
			go acl.RequestLineDnsHttp(url+d, acl.MasterLineDnsQuery)
		}

	case "Backup":
		for _, d := range acl.BackupDns {
			go acl.RequestLineDnsHttp(url+d, acl.BakupDnsQuery)
		}
	}

}

func (acl *AclData) RequestLineDnsHttp(url string, dataChan chan string) {
	resp, err := http.Get(url)
	defer func() { acl.JobChan <- 1 }()

	if ErrCheck(err) {
		return
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return
	}

	body, err := io.ReadAll(resp.Body)
	if ErrCheck(err) {
		return
	}

	dataChan <- string(body)

}

func ErrCheck(err error) bool {
	if err != nil {
		log.Println(err.Error())
		return true
	}
	return false
}
