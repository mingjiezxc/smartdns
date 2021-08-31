# smartdns

# etcd keys

## acl

// acl 组 只存在管理页面 /acl/group/$cidr

// 为快速获取 ip acl and config 不使用 /24 之类的，直接单IP /acl/ip/pool/$ip

```python

    # 用于优先级，如有ACL组中有 192.168.0.0/16 , 192.168.0.0/24 则 192.168.0.0/24 优先
    # 更新 192.168.0.0/16 时检查 16 是否大于 24
    # 使用完整值主要是方便 debug 确认最优先的是来自那个 CIDR
    Cidr : "192.168.0.0/24",

    # 优先线路
    # 即如 "/gz/cm" 则优先同时请求查询 /gz/cm/ 下所有 linedns,那个快回复就使用那个回复用户
    # 一般还会在 linedns 中随机抽2 ~ 3 台DNS同时请求作为备用数据，如 优先线路 timeout 或不在线 则使用备用数据回复用户
    # linedns 同时请求两个上层DNS ["114.114.114.114", "1.1.1.1"] ,那个快回复就使用那个回复用户
    # "/gz/cm/.*" 优先 广州，CM线路 下的所有DNS为主优先服务器
    # "/gz/ct/192.168.1.1" 优先 广州，CT线路, 中的 某个DNS为主优先服务器
    # "\/.*\/cm" 优先 所有 CM 线路
	# Master linedns 正则表达式文本
	MasterLineDnsReStr string
	# backup linedns 正则表达式文本
	BackupLineDnsReStr string

    # 用户指定上层DNS ，"0.0.0.0" 或 "" 则迭代查询
	# Master 使用的上层DNS
	MasterDns []string


	# backup 使用的上层DNS
	BackupDns []string

    # 怕 list 乱序可能需要添加编号
    # 如果无序怕 group1 goolge.com是 转到 8.8.8.8,group2 是转到 1.1.1.1 ，无优先级了。
    ForwardGroup: ["group1", "group2"] 

	# master & backup linedns query timeout 秒
	Timeout int64

}
```

## forward

    获取 domain forward 配置 /forward/*GroupName*/domain
    将某个 domain 在 master Line 转到指定线路与使用指定的DNS

```python
[{"LineDnsReStr": "/hk/.*", "Dns":["114.114.114.114", "1.1.1.1"]}]
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

// 使用 keepalive key 来确认DNS是否在线 /line/dns/*zone*/LINKE/$IP

```json
/line/dns/gz/cm/192.168.1.1 
/line/dns/bj/ct/192.168.1.2 
/line/dns/hk/hk/19.168.1.2 
/line/dns/hk/hk/19.168.1.2
```



[![](https://mermaid.ink/img/eyJjb2RlIjoic2VxdWVuY2VEaWFncmFtXG4gICAgVXNlci0-PlNtYXJ0ZG5zOiBRdWVyeSBEbnNcblxuICAgIGFsdCBOb3QgT24gQWNsIFxuICAgICAgICBTbWFydGRucy0tPj5Vc2VyOiByZWplY3RcbiAgICBlbmRcblxuICAgIGFsdCBvbiBGb3J3YXJkIGxpc3RcbiAgICBGb3J3YXJkX0xpc3QtLT4-IFNtYXJ0ZG5zOiB1cGRhdGUgTWFzdGVyIGluZm9cbiAgICBlbmRcblxuICAgIGFsdCDlkIzml7blj5Hotbfor7fmsYIgXG4gICAgU21hcnRkbnMgLS0-PiBNYXN0ZXJfTGluZTogRE5TIFF1ZXJ5XG4gICAgU21hcnRkbnMgLS0-PiBCYWNrdXBfTGluZTogRE5TIFF1ZXJ5XG4gICAgZW5kXG5cbiAgICBhbHQg5qOA5p-lIE1hc3RlciDnrYnlvoXoh7MgdGltZW91dFxuICAgIFNtYXJ0ZG5zIC0tPj4gTWFzdGVyX0xpbmU6IOetieW-heaVsOaNrlxuICAgIGVsc2VcbiAgICBNYXN0ZXJfTGluZSAtLT4-IFNtYXJ0ZG5zOiDov5Tlm57nu5PmnpxcbiAgICBTbWFydGRucyAtLT4-IFVzZXI6IOi_lOWbnue7k-aenFxuICAgIGVuZFxuXG4gICAgYWx0IE1hc3RlciBUaW1lIG91dCAs5re75YqgIEJhY2t1cCDnrYnlvoXoh7MgdGltZW91dCBcbiAgICBTbWFydGRucyAtLT4-IEJhY2t1cF9MaW5lOiDnrYnlvoXmlbDmja5cbiAgICBlbHNlXG4gICAgQmFja3VwX0xpbmUgLS0-PiBTbWFydGRuczog6L-U5Zue57uT5p6cXG4gICAgU21hcnRkbnMgLS0-PiBVc2VyOiDov5Tlm57nu5PmnpxcbiAgICBlbmRcblxuICAgIGFsdCDlho3mrKF0aW1lb3V0XG4gICAgU21hcnRkbnMgLS0-PiBVc2VyOiDov5Tlm57nqbpcbiAgICBlbmRcblxuIiwibWVybWFpZCI6eyJ0aGVtZSI6ImRlZmF1bHQifSwidXBkYXRlRWRpdG9yIjpmYWxzZSwiYXV0b1N5bmMiOnRydWUsInVwZGF0ZURpYWdyYW0iOmZhbHNlfQ)](https://mermaid-js.github.io/mermaid-live-editor/edit/##eyJjb2RlIjoic2VxdWVuY2VEaWFncmFtXG4gICAgVXNlci0-PlNtYXJ0ZG5zOiBRdWVyeSBEbnNcblxuICAgIGFsdCBOb3QgT24gQWNsIFxuICAgICAgICBTbWFydGRucy0tPj5Vc2VyOiByZWplY3RcbiAgICBlbmRcblxuICAgIGFsdCBvbiBGb3J3YXJkIGxpc3RcbiAgICBGb3J3YXJkX0xpc3QtLT4-IFNtYXJ0ZG5zOiB1cGRhdGUgTWFzdGVyIGluZm9cbiAgICBlbmRcblxuICAgIGFsdCDlkIzml7blj5Hotbfor7fmsYIgXG4gICAgU21hcnRkbnMgLS0-PiBNYXN0ZXJfTGluZTogRE5TIFF1ZXJ5XG4gICAgU21hcnRkbnMgLS0-PiBCYWNrdXBfTGluZTogRE5TIFF1ZXJ5XG4gICAgZW5kXG5cbiAgICBhbHQg5qOA5p-lIE1hc3RlciDnrYnlvoXoh7MgdGltZW91dFxuICAgIFNtYXJ0ZG5zIC0tPj4gTWFzdGVyX0xpbmU6IOetieW-heaVsOaNrlxuICAgIGVsc2VcbiAgICBNYXN0ZXJfTGluZSAtLT4-IFNtYXJ0ZG5zOiDov5Tlm57nu5PmnpxcbiAgICBTbWFydGRucyAtLT4-IFVzZXI6IOi_lOWbnue7k-aenFxuICAgIGVuZFxuXG4gICAgYWx0IE1hc3RlciBUaW1lIG91dCAs5re75YqgIEJhY2t1cCDnrYnlvoXoh7MgdGltZW91dCBcbiAgICBTbWFydGRucyAtLT4-IEJhY2t1cF9MaW5lOiDnrYnlvoXmlbDmja5cbiAgICBlbHNlXG4gICAgQmFja3VwX0xpbmUgLS0-PiBTbWFydGRuczog6L-U5Zue57uT5p6cXG4gICAgU21hcnRkbnMgLS0-PiBVc2VyOiDov5Tlm57nu5PmnpxcbiAgICBlbmRcblxuICAgIGFsdCDlho3mrKF0aW1lb3V0XG4gICAgU21hcnRkbnMgLS0-PiBVc2VyOiDov5Tlm55wd1xuICAgIGVuZFxuXG4iLCJtZXJtYWlkIjoie1xuICBcInRoZW1lXCI6IFwiZGVmYXVsdFwiXG59IiwidXBkYXRlRWRpdG9yIjpmYWxzZSwiYXV0b1N5bmMiOnRydWUsInVwZGF0ZURpYWdyYW0iOmZhbHNlfQ)