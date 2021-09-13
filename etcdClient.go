package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/coreos/etcd/clientv3"
)

var (
	// etcd client
	cli *clientv3.Client
)

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
	if resp, err := EtcdClinet("/forward/group/"); err == nil {
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
	rch := cli.Watch(context.Background(), "/forward/group/", clientv3.WithPrefix())
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
