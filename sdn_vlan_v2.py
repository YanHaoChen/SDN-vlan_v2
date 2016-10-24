from ryu.base import app_manager

# protocol
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ether import ETH_TYPE_8021Q

# control
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls

# parse packet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.ofproto import ether

# vlan set
from vlan_set import vlans_set

# bfs
import Queue

# get link
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link

class sdn_vlan_v2(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
	def __init__(self, *args, **kwargs):
		super(sdn_vlan_v2, self).__init__(*args, **kwargs)
		self.topology_api_app = self
		self.switches_table = {}
		self.vlans_table = {}

		vlans_config = vlans_set().vlans

		self.switch_trunks = {}

		self.hosts = vlans_config["hosts"]

	###### other

	### find trunk
	def find_trunk(self, dpid):
		result = []
		
		for trunk in self.switch_trunks[dpid]:
			result.append(trunk["port"])

		return result

	### BFS and Flood fill

	def bfs_and_flood_fill(self, start_node, vlan_id=-1, end_node=-1):
		master_queue = Queue.Queue()
		go_through_mark = {}
		step_count = 0
		find_switch = -1
		go_through_mark[find_switch] = 99999999
		master_queue.put(start_node)
		go_through_mark[start_node] = step_count

		# bfs and add cost
		while not master_queue.empty():
			
		 	the_node = master_queue.get()
	 		# find the switch which have some vlan id.
	 		for switch_trunk in self.switch_trunks[the_node]:
	 			next_switch = switch_trunk["toswitch"]
	 			#live and don't go through
	 			if next_switch in self.switches_table and next_switch not in go_through_mark:
					go_through_mark[next_switch] = go_through_mark[the_node] + 1
					# find or not
					"""if switch_trunk["toswitch"] in self.vlans_table[vlan_id]:
	 					find_switch = switch_trunk["toswitch"]
	 					break
					"""
	 				master_queue.put(next_switch)


	 	for switch in self.vlans_table[vlan_id]:
	 		if switch in go_through_mark and go_through_mark[switch] != 0:
	 			if go_through_mark[switch] < go_through_mark[find_switch]:
	 				find_switch = switch

	 	result_array = []
	 	now_switch = find_switch

	 	if find_switch == -1:
	 		return result_array
	 	else:
	 		while go_through_mark[now_switch] != 0:
	 			result_array.append(now_switch)
	 			for switch_trunk in self.switch_trunks[now_switch]:
	 				next_switch = switch_trunk["toswitch"]
	 				if next_switch in go_through_mark:
	 					if go_through_mark[next_switch] < go_through_mark[now_switch]:
	 						now_switch = next_switch	 			

	 		result_array.append(start_node)
	 		return result_array
	###### flow

	### add_flow

	def add_flow(self, datapath, match=None, inst=[], table=0, priority=32768, buffer_id=0xffffffff):

		mod = datapath.ofproto_parser.OFPFlowMod(
			datapath=datapath, cookie=0, cookie_mask=0, table_id=table,
			command=datapath.ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
			priority=priority, buffer_id=buffer_id,
			out_port=datapath.ofproto.OFPP_ANY, out_group=datapath.ofproto.OFPG_ANY,
			flags=0, match=match, instructions=inst)

		datapath.send_msg(mod)

	### del_flow

	def del_flow(self, datapath, match, table):

		mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath,
												command=datapath.ofproto.OFPFC_DELETE,
												out_port=datapath.ofproto.OFPP_ANY,
												out_group=ofproto.OFPG_ANY,
												match=match)

		datapath.send_msg(mod)

	###### packet

	### send_packet

	def send_packet(self, datapath, port, pkt):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		pkt.serialize()
		data = pkt.data
		action = [parser.OFPActionOutput(port=port)]

		out = parser.OFPPacketOut(datapath=datapath,
									buffer_id=ofproto.OFP_NO_BUFFER,
									in_port=ofproto.OFPP_CONTROLLER,
									actions=action,
									data=data)
		datapath.send_msg(out)


	######  handlers of events

	### features_handler

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		self.switches_table.setdefault(datapath.id,{})
		self.switches_table[datapath.id]["instance"] = datapath
		self.switch_trunks.setdefault(datapath.id,[])

		table_0_match = None
		goto_table_1_action = parser.OFPInstructionGotoTable(table_id=1)
		table_0_inst = [goto_table_1_action]
		self.add_flow(datapath=datapath, match=table_0_match, inst=table_0_inst, priority=0, table=0)

		for trunk in self.switch_trunks[datapath.id]:
			table_1_match = parser.OFPMatch(in_port=trunk["port"])
			goto_table_2_action = parser.OFPInstructionGotoTable(table_id=2)
			table_1_inst = [goto_table_2_action]
			self.add_flow(datapath=datapath, match=table_1_match, inst=table_1_inst, priority=99, table=1)

			trunk_drop_match = parser.OFPMatch(in_port=trunk["port"])
			# drop
			self.add_flow(datapath=datapath, match=trunk_drop_match, inst=[], priority=0, table=2)
		return

	### packet_in_handler

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def packet_in_handler(self,ev):

		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		port = msg.match['in_port']

		pkt = packet.Packet(data=msg.data)

		pkt_ethernet = pkt.get_protocol(ethernet.ethernet)

		if pkt_ethernet.ethertype == 35020:
			return

		if not pkt_ethernet:
			return

		# arp
		"""pkt_arp =pkt.get_protocol(arp.arp)
		if pkt_arp:
			self.arp_handler(datapath=datapath, port=port, pkt_ethernet=pkt_ethernet, pkt_arp=pkt_arp)
		"""
		# learning
		self.learning_handler(datapath, port, pkt)


	@set_ev_cls(event.EventSwitchEnter)
	def get_topology(self, ev):
		switch_list = get_switch(self.topology_api_app, None)
		switches=[switch.dp.id for switch in switch_list]
		links_list = get_link(self.topology_api_app, None)
		links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
		
		for switch in self.switch_trunks:
			self.switch_trunks[switch] = [] 

		for link in links_list:
			self.switch_trunks[link.src.dpid].append({"toswitch":link.dst.dpid,"port":link.src.port_no})

		for switch in switches:
			self.config_trunk_port(switch)
		
	###### handlers of situations

	### learning
	def learning_handler(self, datapath, port, pkt):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		trunks = self.find_trunk(datapath.id)
		src_vlan = -1
		src_ip = ""

		pkt_ethernet = pkt.get_protocol(ethernet.ethernet)

		for host in self.hosts:
			if pkt_ethernet.src == host["MAC"]:
				src_vlan = host["VLAN_ID"]
				src_ip = host["IP"]

		if src_vlan < 0:
			return

		pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)

		if pkt_ipv4:
			if pkt_ipv4.src != src_ip:
				print "IP is wrong!"
				return

		self.switches_table[datapath.id].setdefault("hosts",{})
		self.switches_table[datapath.id]["hosts"][pkt_ethernet.src] = port
		none_vlan_tag_match = parser.OFPMatch(eth_src=pkt_ethernet.src, vlan_vid=0x0000)
		push_vlan_tag_action = parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
																[parser.OFPActionPushVlan(ETH_TYPE_8021Q),
																parser.OFPActionSetField(vlan_vid=src_vlan)])
		goto_table_2_action = parser.OFPInstructionGotoTable(table_id=2)
		table_1_inst = [push_vlan_tag_action,goto_table_2_action]
		self.add_flow(datapath=datapath, match=none_vlan_tag_match, inst=table_1_inst, priority=99, table=1)

		src_ip_and_vlan_match = parser.OFPMatch(eth_dst=pkt_ethernet.src, vlan_vid=0x1000 | src_vlan)
		goto_the_port_action = parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
																[parser.OFPActionPopVlan(ETH_TYPE_8021Q),
																parser.OFPActionOutput(port)])
		table_2_inst = [goto_the_port_action]
		self.add_flow(datapath=datapath, match=src_ip_and_vlan_match, inst=table_2_inst, priority=50, table=2)
		
		vlan_match = parser.OFPMatch(vlan_vid=0x1000 | src_vlan)
		vlan_broadcast_actions = []

		try:
			for trunk in self.vlans_table[src_vlan][datapath.id]:
				vlan_broadcast_actions.append(parser.OFPActionOutput(trunk))
	
		except:
			pass
		
		vlan_broadcast_actions.append(parser.OFPActionPopVlan(ETH_TYPE_8021Q))
		for host in self.hosts:
			if host["MAC"] in self.switches_table[datapath.id]["hosts"]:
				if host["VLAN_ID"] == src_vlan:
					vlan_broadcast_actions.append(parser.OFPActionOutput(self.switches_table[datapath.id]["hosts"][host["MAC"]]))

		if vlan_broadcast_actions != []:
			broadcast_actions = parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,vlan_broadcast_actions)
			broadcast_inst = [broadcast_actions]
			self.add_flow(datapath=datapath, match=vlan_match, inst=broadcast_inst, priority=20, table=2)


		# path
		# 
		self.vlans_table.setdefault(src_vlan,{})
		if datapath.id not in self.vlans_table[src_vlan]:
			# add vlan subset
			self.vlans_table[src_vlan].setdefault(datapath.id,[])

			# Create a path to vlan subset
			if len(self.vlans_table[src_vlan]) > 1:
				dpid = int(datapath.id)
				go_through_switches = self.bfs_and_flood_fill(dpid,src_vlan)

				if go_through_switches = []:
					print "No path."
					del self.vlans_table[src_vlan][datapath.id]
					return

				switch_count = 0
				print "switch:%s, vlan:%s, find path:%s" % (datapath.id, src_vlan, go_through_switches)

				#####
				for switch in go_through_switches:
					self.vlans_table[src_vlan].setdefault(switch,[])

				for switch in go_through_switches:

					now_datapath = self.switches_table[switch]["instance"]
					now_ofproto = now_datapath.ofproto
					now_parser = now_datapath.ofproto_parser
					toswitch_mark = []
					# open the trunk
					vlan_match = now_parser.OFPMatch(vlan_vid=0x1000 | src_vlan)
					now_output_actions = []
					for trunk in self.switch_trunks[switch]:
						if trunk["toswitch"] in self.vlans_table[src_vlan] and trunk["toswitch"] not in toswitch_mark:
							now_output_actions.append(now_parser.OFPActionOutput(trunk["port"]))
							self.vlans_table[src_vlan][switch].append(trunk["port"])
							toswitch_mark.append(trunk["toswitch"])

					now_output_actions.append(parser.OFPActionPopVlan(ETH_TYPE_8021Q))
					for host in self.hosts:
						if host["MAC"] in self.switches_table[now_datapath.id]["hosts"]:
							if host["VLAN_ID"] == src_vlan:
								now_output_actions.append(now_parser.OFPActionOutput(self.switches_table[now_datapath.id]["hosts"][host["MAC"]]))

					if now_output_actions != []:
						now_out_of_switch_action = now_parser.OFPInstructionActions(now_ofproto.OFPIT_APPLY_ACTIONS,now_output_actions)
						now_trunk_inst = [now_out_of_switch_action]
						self.add_flow(datapath=now_datapath, match=vlan_match, inst=now_trunk_inst, priority=20, table=2)

		print "vlan:%s,set:%s" % (src_vlan, self.vlans_table[src_vlan])
	### arp
	def arp_handler(self, datapath, port, pkt_ethernet, pkt_arp):
		if pkt_arp.opcode != arp.ARP_REQUEST:
			return

		src_vlan = -1
		src_mac = pkt_ethernet.src
		src_ip = ""

		dst_vlan = -1
		dst_mac = ""
		dst_ip = pkt_arp.dst_ip
		#find vlan
		for host in self.hosts:
			if pkt_ethernet.src == host["MAC"]:
				src_vlan = host["VLAN_ID"]
				src_ip = host["IP"] 

			if str(dst_ip) == host["IP"]:
				dst_vlan = host["VLAN_ID"]
				dst_mac = host["MAC"]

			if src_vlan > 0 and dst_vlan > 0:
				break

		# The dst host is not in the set.
		if not dst_vlan:
			print "The dst host is not in the set."
			return

		# They are not the same vlan.
		if src_vlan != dst_vlan:
			print "They are not the same vlan."
			return
		pkt = packet.Packet()
		pkt.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_ARP,
											dst=src_mac,
											src=dst_mac))
		pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
									src_mac=dst_mac,
									src_ip=dst_ip,
									dst_mac=src_mac,
									dst_ip=src_ip
								)
						)
		self.send_packet(datapath, port, pkt)

	### config trunk port

	def config_trunk_port(self, datapath_id):

		datapath = self.switches_table[datapath_id]["instance"]
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		table_0_match = None
		goto_table_1_action = parser.OFPInstructionGotoTable(table_id=1)
		table_0_inst = [goto_table_1_action]
		self.add_flow(datapath=datapath, match=table_0_match, inst=table_0_inst, priority=0, table=0)

		for trunk in self.switch_trunks[datapath.id]:
			table_1_match = parser.OFPMatch(in_port=trunk["port"])
			goto_table_2_action = parser.OFPInstructionGotoTable(table_id=2)
			table_1_inst = [goto_table_2_action]
			self.add_flow(datapath=datapath, match=table_1_match, inst=table_1_inst, priority=99, table=1)

			trunk_drop_match = parser.OFPMatch(in_port=trunk["port"])
			# drop
			self.add_flow(datapath=datapath, match=trunk_drop_match, inst=[], priority=0, table=2)
		return