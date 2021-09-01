# smartdns

# etcd keys
    smartdns 会读取以下 key 进行初始化，数据能实时更新。
    acl: /acl/ip/pool/$ip
    forward: /forward/$groupName/$domain
    linedns: /line/dns/$zone/$line/$IP:$Port

## acl
// acl 组 只存在管理页面 /acl/group/$cidr
// 为快速获取 ip acl and config 不使用 /24 之类的，直接单IP /acl/ip/pool/$ip

```python
{
    # 用于优先级，如有ACL组中有 192.168.0.0/16 , 192.168.0.0/24 则 192.168.0.0/24 优先
    # 更新 192.168.0.0/16 时检查 16 是否大于 24
    # 使用完整值主要是方便 debug 确认最优先的是来自那个 CIDR
    Cidr : "192.168.0.0/24",
    Netmask： 24 ， 
    # 优先 LineDns
    # 即如 "/gz/cm/" 则同时请求查询 /gz/cm/ 下所有 linedns,那个快回复就使用那个回复用户
    # 并同时请求上层MasterDns ["114.114.114.114", "1.1.1.1"] ,那个快回复就使用那个回复用户
    # "/.*/cm/"  所有 CM线路 下的所有LineDNS
    # "/gz/.*/"  所有 gz线路 下的所有LineDNS
	# Master linedns 正则表达式文本
	MasterLineDnsReStr "/gz/cm/"

    # 用户指定上层DNS ，"0.0.0.0" 或 "" 则迭代查询
	# Master 使用的上层DNS
	MasterDns ["114.114.114.114", "1.1.1.1"]

    # 备份 LineDns
    # 与 Master 同时请求，但需等待 Timeout 才会反回数据
	# backup linedns 正则表达式文本
	BackupLineDnsReStr "/gz/.*/"

	# backup 使用的上层DNS
	BackupDns ["233.5.5.5", "1.1.1.1"]

    # 写入时请注意组的顺序
    ForwardGroup: ["group1", "group2"] 

	# master linedns query timeout 秒
    # 不建议大 2， 因一般 dns client 10 秒 timeout， 每间隔3秒会重试
	Timeout 2

}
```

## forward

    获取 domain forward 配置 /forward/$groupName/$domain
    将某个 domain 在 master Line 转到指定线路与使用指定的DNS

```python
[{"LineDnsReStr": "/hk/.*/", "Dns":["114.114.114.114", "1.1.1.1"]}]
```

// 例子etcd暂定使用右则匹配
用户请求 www.google.com.hk

// 按以下顺序搜索如成功则不继续

```json
/forward/abc/www.google.com.hk.
/forward/abc/google.com.hk.
/forward/abc/com.hk.
/forward/abc/hk.
```

## LineDns
// linedns使用 keepalive key 来确认DNS是否在线 /line/dns/*zone*/LINKE/$IP:$Port

```json
/line/dns/gz/cm/192.168.1.1:8888
/line/dns/bj/ct/192.168.1.2:8888
/line/dns/hk/hk/19.168.1.2:8888
/line/dns/hk/hk/19.168.1.2:8888
```



[![](https://mermaid.ink/img/eyJjb2RlIjoic2VxdWVuY2VEaWFncmFtXG4gICAgVXNlci0-PlNtYXJ0ZG5zOiBRdWVyeSBEbnNcblxuICAgIGFsdCBOb3QgT24gQWNsIFxuICAgICAgICBTbWFydGRucy0tPj5Vc2VyOiByZWplY3RcbiAgICBlbmRcblxuICAgIGFsdCBvbiBGb3J3YXJkIGxpc3RcbiAgICBGb3J3YXJkX0xpc3QtLT4-IFNtYXJ0ZG5zOiB1cGRhdGUgTWFzdGVyIGluZm9cbiAgICBlbmRcblxuICAgIGFsdCDlkIzml7blj5Hotbfor7fmsYIgXG4gICAgU21hcnRkbnMgLS0-PiBNYXN0ZXJfTGluZTogRE5TIFF1ZXJ5XG4gICAgU21hcnRkbnMgLS0-PiBCYWNrdXBfTGluZTogRE5TIFF1ZXJ5XG4gICAgZW5kXG5cbiAgICBhbHQg5qOA5p-lIE1hc3RlciDnrYnlvoXoh7MgdGltZW91dFxuICAgIFNtYXJ0ZG5zIC0tPj4gTWFzdGVyX0xpbmU6IOetieW-heaVsOaNrlxuICAgIGVsc2VcbiAgICBNYXN0ZXJfTGluZSAtLT4-IFNtYXJ0ZG5zOiDov5Tlm57nu5PmnpxcbiAgICBTbWFydGRucyAtLT4-IFVzZXI6IOi_lOWbnue7k-aenFxuICAgIGVuZFxuXG4gICAgYWx0IE1hc3RlciBUaW1lIG91dCAs5re75YqgIEJhY2t1cCDnrYnlvoXoh7MgdGltZW91dCBcbiAgICBTbWFydGRucyAtLT4-IEJhY2t1cF9MaW5lOiDnrYnlvoXmlbDmja5cbiAgICBlbHNlXG4gICAgQmFja3VwX0xpbmUgLS0-PiBTbWFydGRuczog6L-U5Zue57uT5p6cXG4gICAgU21hcnRkbnMgLS0-PiBVc2VyOiDov5Tlm57nu5PmnpxcbiAgICBlbmRcblxuICAgIGFsdCDlho3mrKF0aW1lb3V0XG4gICAgU21hcnRkbnMgLS0-PiBVc2VyOiDov5Tlm57nqbpcbiAgICBlbmRcblxuIiwibWVybWFpZCI6eyJ0aGVtZSI6ImRlZmF1bHQifSwidXBkYXRlRWRpdG9yIjpmYWxzZSwiYXV0b1N5bmMiOnRydWUsInVwZGF0ZURpYWdyYW0iOmZhbHNlfQ)](https://mermaid-js.github.io/mermaid-live-editor/edit/##eyJjb2RlIjoic2VxdWVuY2VEaWFncmFtXG4gICAgVXNlci0-PlNtYXJ0ZG5zOiBRdWVyeSBEbnNcblxuICAgIGFsdCBOb3QgT24gQWNsIFxuICAgICAgICBTbWFydGRucy0tPj5Vc2VyOiByZWplY3RcbiAgICBlbmRcblxuICAgIGFsdCBvbiBGb3J3YXJkIGxpc3RcbiAgICBGb3J3YXJkX0xpc3QtLT4-IFNtYXJ0ZG5zOiB1cGRhdGUgTWFzdGVyIGluZm9cbiAgICBlbmRcblxuICAgIGFsdCDlkIzml7blj5Hotbfor7fmsYIgXG4gICAgU21hcnRkbnMgLS0-PiBNYXN0ZXJfTGluZTogRE5TIFF1ZXJ5XG4gICAgU21hcnRkbnMgLS0-PiBCYWNrdXBfTGluZTogRE5TIFF1ZXJ5XG4gICAgZW5kXG5cbiAgICBhbHQg5qOA5p-lIE1hc3RlciDnrYnlvoXoh7MgdGltZW91dFxuICAgIFNtYXJ0ZG5zIC0tPj4gTWFzdGVyX0xpbmU6IOetieW-heaVsOaNrlxuICAgIGVsc2VcbiAgICBNYXN0ZXJfTGluZSAtLT4-IFNtYXJ0ZG5zOiDov5Tlm57nu5PmnpxcbiAgICBTbWFydGRucyAtLT4-IFVzZXI6IOi_lOWbnue7k-aenFxuICAgIGVuZFxuXG4gICAgYWx0IE1hc3RlciBUaW1lIG91dCAs5re75YqgIEJhY2t1cCDnrYnlvoXoh7MgdGltZW91dCBcbiAgICBTbWFydGRucyAtLT4-IEJhY2t1cF9MaW5lOiDnrYnlvoXmlbDmja5cbiAgICBlbHNlXG4gICAgQmFja3VwX0xpbmUgLS0-PiBTbWFydGRuczog6L-U5Zue57uT5p6cXG4gICAgU21hcnRkbnMgLS0-PiBVc2VyOiDov5Tlm57nu5PmnpxcbiAgICBlbmRcblxuICAgIGFsdCDlho3mrKF0aW1lb3V0XG4gICAgU21hcnRkbnMgLS0-PiBVc2VyOiDov5Tlm55wd1xuICAgIGVuZFxuXG4iLCJtZXJtYWlkIjoie1xuICBcInRoZW1lXCI6IFwiZGVmYXVsdFwiXG59IiwidXBkYXRlRWRpdG9yIjpmYWxzZSwiYXV0b1N5bmMiOnRydWUsInVwZGF0ZURpYWdyYW0iOmZhbHNlfQ)