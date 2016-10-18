# SDN-vlan\_v2

利用環境配置資訊，自動化連接 VLAN 群體，完成在 SDN 下的 VLAN 管理。

## 功能

* 自動回覆 ARP Request
	* 去除因 ARP 產生的廣播封包。

* 以 Switch 為單位，建立各個 VLAN 群體，達成 VLAN 封包轉送
	* 一個 VLAN 產生一棵無迴圈樹，並以此樹轉送封包。

## 環境配置

```python
self.vlans = {'switches':{
						1:[{"toswitch":2,"port":30},{"toswitch":3,"port":40},{"toswitch":4,"port":50}],
						2:[{"toswitch":1,"port":30},{"toswitch":3,"port":40}],
						3:[{"toswitch":1,"port":30},{"toswitch":2,"port":40}],
						4:[{"toswitch":1,"port":30}]
						},
			  'hosts':[
					  	{"MAC":'00:00:00:00:00:01',"IP":'10.0.0.1',"VLAN_ID":20},
			  			{"MAC":'00:00:00:00:00:02',"IP":'10.0.0.2',"VLAN_ID":20},
			  			{"MAC":'00:00:00:00:00:03',"IP":'10.0.0.3',"VLAN_ID":30},
			  			{"MAC":'00:00:00:00:00:04',"IP":'10.0.0.4',"VLAN_ID":30},
			  			{"MAC":'00:00:00:00:00:05',"IP":'10.0.0.5',"VLAN_ID":30}
			  			]
			 }
```

* switches 範例：

```python
(Switch ID):[{trunk 通往的 Switch:1, trunk 使用的 port:30},{trunk 通往的 Switch:2, trunk 使用的 port:40}]
```

* hosts 範例：

```python
{"MAC":'主機 MAC address',"IP":'主機 IP',"VLAN_ID":主機所屬 VLAN}
```

## Table 轉送邏輯

```python
# 預留用來過濾封包
Table 0：
	* 沒有 Match 任何規格 -> 轉送至 Table 1

# 1. 加入對應 VLAN tag
# 2. 接收 ARP 封包，轉往 Controller
Table 1:
	priority=99
	* Match(eth_src=管轄內主機, vlan_vid=none) -> 加入對應 VLAN tag，轉往 Table 2
	priority=999
	* Match(eth_src=管轄內主機, eth_dst='ff:ff:ff:ff:ff:ff') -> 送往 Controller

# 1. VLAN 通道
# 2. 轉送封包至對應主機
Table 2:
	priority=20
	* Match(vlan_vid=此 Switch 所在的 VLAN 群體) -> 送往 trunk
	priority=50
	* Match(eth_src ,vlan_vid) -> 送往對應主機
```

## VLAN 建樹流程

* Switch 加入個別 VLAN 樹之條件（情境）：
	1. Switch 中包含此 VLAN 之主機。
	2. Switch 位於它台 Switch 連接至此 VLAN 樹的最短路徑上。

* Switch 符合條件（情境）後：
	* 情境 1
		1. 學習此主機，並將規則的優先權設定為 50。
		2. 在每一個 trunk 下規則，開通包含此 VLAN ID 的封包，並將規則的優先權設定為 20。
	* 情境 2
		1. 在每一個 trunk 下規則，開通包含此 VLAN ID 的封包，並將規則的優先權設定為 20。

## VLAN 建樹邏輯

```python
if switch 偵測到新的 host 加入:
	if switch 並不在 host 所屬 VLAN 群體（樹）中:
		使用洪水演算法找尋此 VLAN 離目前 switch 最近的 switch，並開通這條路徑，使目前 switch 加入 VLAN 群體。 
```