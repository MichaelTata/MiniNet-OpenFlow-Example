from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.ofproto import ether
from ryu.lib.packet.ether_types import ETH_TYPE_IP
from ryu.lib.packet import icmp
from ryu.lib.packet import ipv4

class Controller(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]






	def __init__(self, *args, **kwargs):
		super(Controller, self).__init__(*args, **kwargs)
		
		self.mac_to_port = {}
		
		#Virtual IP for server
		self.virtualip = '10.0.0.10'
		
		#Binary flag, to determine which of the two servers to distribute request.
		self.loadflag = 0
		
		#Hardcoded values for our servers. 
		self.serverfiveip = '10.0.0.5'
		self.serverfivemac = '00:00:00:00:00:05'
		self.serverfiveport = 5

		self.serversixip = '10.0.0.6'
		self.serversixmac = '00:00:00:00:00:06'
		self.serversixport = 6


		#Used to map ip to mac for the server arp req
		self.iptomac = {'10.0.0.1':'00:00:00:00:00:01',
				'10.0.0.2':'00:00:00:00:00:02',
				'10.0.0.3':'00:00:00:00:00:03',
				'10.0.0.4':'00:00:00:00:00:04',
				'10.0.0.5':'00:00:00:00:00:05',
				'10.0.0.6':'00:00:00:00:00:06'}


	#Function to add a flow to the switch
	def add_flow(self, datapath, priority, match, actions, buffer_id=None):
	
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)] 

		mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
		datapath.send_msg(mod)
		return

	#Handle incoming packets that do not have established flows.
	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
       
	   
		msg = ev.msg
		
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
	
		client_in_port = msg.match['in_port']


		
		pkt = packet.Packet(msg.data)

		#Get Ethernet packet.
		eth = pkt.get_protocol(ethernet.ethernet)
		
		
		#If this is an arp request, process it. otherwise, drop the packet(Flows are established via ARP req from client). 
		if eth.ethertype == ether.ETH_TYPE_ARP:
		
		
			arp_packet = pkt.get_protocol(arp.arp) 
			
			sourceip = arp_packet.src_ip
			targetip = arp_packet.dst_ip
			
			sourcemac = eth.src
			targetmac = eth.dst
			
			self.mac_to_port[sourcemac] = client_in_port
			
			#Client searching for server.
			if targetip == self.virtualip:
				
				if self.loadflag == 0:
					targetmac = self.serverfivemac
				else:
					targetmac = self.serversixmac
					
					
				#Set up ARP Packet REPLY
				arppkt = packet.Packet()
				arppkt.add_protocol(ethernet.ethernet(dst=sourcemac,src=targetmac, ethertype=ether_types.ETH_TYPE_ARP))
				arppkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=targetmac,src_ip=targetip, dst_mac=sourcemac, dst_ip=sourceip))
				arppkt.serialize()	
					

				#Send out the port we received it from.
				actions = [parser.OFPActionOutput(ofproto.OFPP_IN_PORT)]
				packetsend = parser.OFPPacketOut(datapath=datapath, in_port=client_in_port,
                        data=arppkt.data, actions=actions, buffer_id=ofproto.OFP_NO_BUFFER)	
					
					
				if targetip == self.virtualip:
					#Load balancing decision. Alternates between servers
					if self.loadflag == 0:
						
						#print("Server 5.")
						targetip = self.serverfiveip
						outport = self.serverfiveport
						self.loadflag = 1
					
					else:
					
						#print("Server 6.")
						targetip = self.serversixip
						outport = self.serversixport
						self.loadflag = 0	
					
					
				#Set up the flow from the client to the server. #ip_proto=1,
				match = parser.OFPMatch(in_port=client_in_port, eth_type=ETH_TYPE_IP, eth_dst=targetmac, eth_src=sourcemac,ipv4_dst=self.virtualip)
			
				#For action ipv4 dest should be 10.0.0.5 or 10.0.0.6. Thus outport here should be 5 or 6
				actions = [parser.OFPActionSetField(ipv4_dst=targetip),
					parser.OFPActionOutput(outport)]
			
				self.add_flow(datapath, 1, match, actions)
			

				
				#
				match = parser.OFPMatch(in_port=outport, eth_type=ETH_TYPE_IP,   
										ipv4_src=targetip,						 
										eth_dst=sourcemac,
										eth_src=targetmac)						 
									
				actions = [parser.OFPActionSetField(ipv4_src=self.virtualip), parser.OFPActionOutput(client_in_port)]						 
					   
					   

				self.add_flow(datapath, 1, match, actions)	
					
					
					
			#Server searching for client.	
			else:
				
				
				targetmac = self.iptomac[targetip]
				outport = self.mac_to_port[sourcemac]
				
				#Set up ARP Packet REPLY
				arppkt = packet.Packet()
				arppkt.add_protocol(ethernet.ethernet(dst=sourcemac,src=targetmac, ethertype=ether_types.ETH_TYPE_ARP))
				arppkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=targetmac,src_ip=targetip, dst_mac=sourcemac, dst_ip=sourceip))
				arppkt.serialize()	
					
					
				#Send out the port we received it from.
				actions = [parser.OFPActionOutput(ofproto.OFPP_IN_PORT)]
				packetsend = parser.OFPPacketOut(datapath=datapath, in_port=client_in_port,
                        data=arppkt.data, actions=actions, buffer_id=ofproto.OFP_NO_BUFFER)
					
				
			
						
			#Send out onto the wire.			
			datapath.send_msg(packetsend)
			return None
			
		else:
			#Drop packet.
			return None
			
			
