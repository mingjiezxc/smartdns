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

	// string ip + / + domain
	QueryMap = make(map[string]*UserQuestion)
)

type YamlConfig struct {
	AppName            string   `yaml:"AppName"`
	DnsListeningPort   string   `yaml:"DnsListeningPort"`
	QueryListeningPort string   `yaml:"QueryListeningPort"`
	EtcdServers        []string `yaml:"EtcdServers"`
	EtcdUser           string   `yaml:"EtcdUser"`
	EtcdPassword       string   `yaml:"EtcdPassword"`
	MaxTtl             int64    `yaml:"MaxTtl"`
	DnsQueryTimeOut    int64    `yaml:"DnsQueryTimeOut"`
	CacheClen          int64    `yaml:"CacheClen"`
	CacheExtend        int64    `yaml:"CacheExtend"`
}

type UserQuestion struct {
	Acl          string
	ResponseList []dns.ResponseWriter
	Ttl          int64
	LastTime     int64
	DnsMsg       *dns.Msg
	BackupQuery  bool
	MasterQuery  bool
	Cache        bool
	CacheCount   int64
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
		n, u, err := ser.ReadFromUDP(p)
		if err != nil {
			continue
		}
		go ReturnDnsUser(u, p[0:n])
	}
}

func ReturnDnsUser(addr *net.UDPAddr, data []byte) {

	// unMarshal data
	newDnsQuery := &DnsQuery{}
	err := proto.Unmarshal(data, newDnsQuery)
	if err != nil {
		return
	}

	// check exist
	query, ok := QueryMap[newDnsQuery.Ip+"/"+newDnsQuery.Domain]
	if !ok {
		return
	}

	// 检查是否有其他进程在更新
	if newDnsQuery.Master {
		if query.MasterQuery {
			return
		}
		query.MasterQuery = true
	}

	if !newDnsQuery.Master {
		// Master Dns 已返回 退出
		if query.MasterQuery {
			return
		}
		// 已有其他 Backup Dns 返回 退出
		if query.BackupQuery {
			return
		}

		query.BackupQuery = true

		// 检查是否已 time out ,
		tmpTime := query.LastTime - time.Now().Unix()
		if tmpTime > appConfig.DnsQueryTimeOut {
			time.Sleep(time.Duration(tmpTime - appConfig.DnsQueryTimeOut))
		}

		// 再次 检查 Master 是否已返回
		if query.MasterQuery {
			return
		}

	}

	// update dns msg rr
	var tmpRr []dns.RR
	var tmpTtl int64
	for _, dnsRR := range newDnsQuery.Rr {
		rr, _ := dns.NewRR(dnsRR)
		if rr != nil {
			tmpRr = append(tmpRr, rr)
		}

		tmpTtl = int64(rr.Header().Ttl)
	}
	query.DnsMsg.Answer = tmpRr

	if tmpTtl < appConfig.MaxTtl {
		query.Ttl = tmpTtl
	}

	// return user
	for _, i := range query.ResponseList {
		i.WriteMsg(query.DnsMsg)
		query.ResponseList = query.ResponseList[1:]
	}

	// 标记 cache
	query.Cache = true

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
		return
	}

	// check query is nil exit
	if len(r.Question) < 1 {
		return
	}

	tmpDnsMsg := new(dns.Msg).SetReply(r)

	mapkey := addr + "/" + r.Question[0].Name

	// check cache status
	if query, ok := QueryMap[mapkey]; !ok {
		QueryMap[mapkey] = &UserQuestion{
			Acl:      addr,
			Ttl:      appConfig.MaxTtl,
			LastTime: time.Now().Unix(),
			DnsMsg:   tmpDnsMsg,
		}
	} else {
		// check cache 是否存在，如存在返回 cache
		if query.Cache {
			w.WriteMsg(query.DnsMsg)
			QueryMap[mapkey].CacheCount++
			return
		}
	}

	QueryMap[mapkey].ResponseList = append(QueryMap[mapkey].ResponseList, w)

	// init data
	acl.DnsQueryData = &DnsQuery{
		Ip:       addr,
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
		time.Sleep(time.Duration(appConfig.CacheClen))

		for key, val := range QueryMap {
			if time.Now().Unix()-val.LastTime > val.Ttl {

				if QueryMap[key].CacheCount > appConfig.CacheExtend {
					acl := AclMap[QueryMap[key].Acl]
					QueryMap[key].MasterQuery = false
					QueryMap[key].BackupQuery = false

					acl.SendLineDnsUdp(true)
					acl.SendLineDnsUdp(false)
					QueryMap[key].CacheCount = 0

					continue
				}

				if len(QueryMap[key].ResponseList) == 0 {
					delete(QueryMap, key)
				}
			}
		}
	}

}
