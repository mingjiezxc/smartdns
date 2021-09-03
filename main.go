package main

import (
	"io/ioutil"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/etcd/clientv3"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v2"
)

var (
	appConfig YamlConfig

	// etcd data
	AclMap          = make(map[string]AclData)
	ForwardGroupMap = make(map[string]map[string]ForwardData)
	LineDnsMap      = make(map[string]string)
	QueryMap        = make(map[uint16]*UserQuestion)
)

type YamlConfig struct {
	AppName            string   `yaml:"AppName"`
	DnsListeningPort   string   `yaml:"DnsListeningPort"`
	QueryListeningPort string   `yaml:"QueryListeningPort"`
	EtcdServers        []string `yaml:"EtcdServers"`
	EtcdUser           string   `yaml:"EtcdUser"`
	EtcdPassword       string   `yaml:"EtcdPassword"`
}

type UserQuestion struct {
	Response      dns.ResponseWriter
	Msg           *dns.Msg
	TimeNow       int64
	TimeOut       int64
	BackupQuery   bool
	MasterLineDns []string
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
	TimeOut int64

	// tmp data
	MasterLineDnsRe *regexp.Regexp
	MasterLineDns   []string
	BackupLineDnsRe *regexp.Regexp
	BackupLineDns   []string
	DnsQueryData    *DnsQuery
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

	// query dns listening
	go QueryListeningServerStart()

	// clean job
	go CleanDnsQuestionJob()

	// start dns server
	DnsServerStart()

}

func QueryListeningServerStart() {
	p := make([]byte, 1472)

	port, err := strconv.Atoi(appConfig.QueryListeningPort)
	if ErrCheck(err) {
		os.Exit(5)
	}

	addr := net.UDPAddr{
		Port: port,
		IP:   net.ParseIP("0.0.0.0"),
	}
	ser, err := net.ListenUDP("udp", &addr)
	if ErrCheck(err) {
		os.Exit(5)
	}

	log.Println("Query Server Starting at ", appConfig.QueryListeningPort)
	for {
		n, _, err := ser.ReadFromUDP(p)
		if err != nil {
			continue
		}
		go ReturnDnsUser(p[0:n])
	}
}

func ReturnDnsUser(data []byte) {

	// unMarshal data
	newDnsQuery := &DnsQuery{}
	err := proto.Unmarshal(data, newDnsQuery)
	if err != nil {
		return
	}

	// check exist
	query, ok := QueryMap[uint16(newDnsQuery.Id)]
	if !ok {
		return
	}

	// is backup linedns data ,已有other backup sleep
	if !newDnsQuery.Master && query.BackupQuery {
		return
	}

	// check master line dns online status
	var masterLineDnsStatus bool
	for _, lineDns := range query.MasterLineDns {
		if _, ok := LineDnsMap[lineDns]; ok {
			masterLineDnsStatus = true
			break
		}
	}

	// check master ,backup , timeout
	if !newDnsQuery.Master && masterLineDnsStatus {
		if ttl := time.Now().Unix() - query.TimeNow; ttl < query.TimeOut {
			QueryMap[uint16(newDnsQuery.Id)].BackupQuery = true
			time.Sleep(time.Duration(ttl) * time.Second)
		}
	}

	// update dns msg rr
	for _, dnsRR := range newDnsQuery.Rr {
		rr, _ := dns.NewRR(dnsRR)
		if rr != nil {
			query.Msg.Answer = append(query.Msg.Answer, rr)
		}
	}

	// return user
	query.Response.WriteMsg(query.Msg)

	// del  data
	delete(QueryMap, uint16(newDnsQuery.Id))
}

func DnsServerStart() {
	// attach request handler func
	dns.HandleFunc(".", DnsMsgProcess)

	// start dns server
	server := &dns.Server{Addr: ":" + appConfig.DnsListeningPort, Net: "udp"}
	log.Printf("Dns Server Starting at %s\n", appConfig.DnsListeningPort)
	err := server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}
}

func DnsMsgProcess(w dns.ResponseWriter, r *dns.Msg) {

	addr := strings.Split(w.RemoteAddr().String(), ":")[0]

	// acl check , not on acl exit thread
	acl, ok := AclMap[addr]

	// Not on Acl exit
	if !ok {

		w.WriteMsg(r)
		delete(QueryMap, r.Id)
		return
	}

	// check query is nil exit
	if len(r.Question) < 1 {
		return
	}

	tmpDnsMsg := new(dns.Msg).SetReply(r)

	QueryMap[r.Id] = &UserQuestion{
		Response: w,
		Msg:      tmpDnsMsg,
		TimeNow:  time.Now().Unix(),
	}

	// init data
	acl.DnsQueryData = &DnsQuery{
		Id:       uint32(r.Id),
		Tport:    appConfig.QueryListeningPort,
		Domain:   tmpDnsMsg.Question[0].Name,
		Dnstype:  uint32(tmpDnsMsg.Question[0].Qtype),
		Dnsclass: uint32(tmpDnsMsg.Question[0].Qclass),
	}
	// check dns on forward
	acl.CheckRquestDns(tmpDnsMsg.Question[0].Name)

	// get Master & backup LineDns
	acl.CheckLineDns()

	// 开始请求 line dns
	acl.SendLineDnsUdp(true)
	acl.SendLineDnsUdp(false)

}

func (acl *AclData) SendLineDnsUdp(master bool) {
	var lineDnsList []string
	var dnsList []string

	if master {
		lineDnsList = acl.MasterLineDns
		dnsList = acl.MasterDns
	} else {
		lineDnsList = acl.BackupLineDns
		dnsList = acl.BackupDns
	}

	for _, lineDns := range lineDnsList {
		c, err := net.Dial("udp4", lineDns)

		if err == nil {
			for _, dns := range dnsList {
				acl.DnsQueryData.Master = master
				acl.DnsQueryData.Tdns = dns
				pData, err := proto.Marshal(acl.DnsQueryData)
				if err == nil {
					c.Write(pData)
				}

			}
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

}

func ErrCheck(err error) bool {
	if err != nil {
		log.Println(err.Error())
		return true
	}
	return false
}

func CleanDnsQuestionJob() {
	for {
		time.Sleep(120 * time.Second)

		for key, val := range QueryMap {
			if time.Now().Unix()-val.TimeNow > 120 {
				delete(QueryMap, key)
			}
		}
	}

}
