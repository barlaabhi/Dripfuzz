from core.logger import get_logger

import pyradamsa
import base64,os,time,binascii
import random
import socket
import sys	
from types import *
import struct
import time
import logging
import pickle
from scapy.all import *
from requests.exceptions import ReadTimeout
from core.brute_address import *

class Modbus(Packet):
	name = "Modbus/tcp"
	fields_desc = [ ShortField("Transaction Identifier", 1),
				ShortField("Protocol Identifier", 0),
				ShortField("Length", 2),
				XByteField("Unit Identifier",0),
				ByteField("Function Code", 0)
				]


class PackGen(object):

	def __init__(self, r0obj):
		self.r0obj = r0obj
		self.HOST = "127.0.0.1"
		self.src_port = 49901
		self.dest_port = 1502
		self.verbosity = self.r0obj.log_level
		self.pyradamsa_obj = pyradamsa.Radamsa()
		self.logger = get_logger("PackGen", self.verbosity)
		self.valid_address = Brute().get_address_range()

	def create_socket(self):
		
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.settimeout(0.5)
			ret_code = sock.connect_ex((self.HOST, self.dest_port))
		
		except:
			pass
		
		return sock,ret_code

	def create_connection(self):

		ret_code = None

		while(ret_code!=0):
			sock_obj,ret_code = self.create_socket()

		self.logger.info("[+] Connected to Server: %s" % self.HOST)

		return sock_obj


	def AddToPCAP(self, packet):
		pkt = Ether()/IP()/TCP(sport=self.src_port, dport = self.dest_port)/packet/Modbus()
		wrpcap('test.pcap', pkt, append=True)

	def send_socket(self, packet):

		self.logger.debug("[*] Send Packet")

		sock_obj = self.create_connection()

		#AddToPCAP(ModbusPacket)
		#AddToPCAP(RespPacket)

		try:
			sock_obj.send(packet)

		except:

			self.logger.error("[-] Sending Failed!")
			sock_obj.close()
			#sock_obj = self.create_connection()
		
		else:

			self.logger.debug("[+] Sent Packet: %s" % hexstr(packet))
			
			print("[*] Sent: %s" % hexstr(packet))

			try:

				RespPacket = sock_obj.recv(1024)
				print('[*] Received: %s'% hexstr(RespPacket))

			except:
				self.logger.error("[-] Failed to receive")
				
		return

	def send_system(self,packet):

		self.logger.debug("send_packet")

		print("[*] Sent: %s" % hexstr(packet))

		self.logger.debug("[+] Sent Packet: %s" % hexstr(packet))

		base64_str = base64.b64encode(packet+b'\x00').decode() # null byte to continue sending packets
		
		command = f"echo {base64_str} | base64 -d | nc 127.0.0.1 1502"
		
		os.system(command)

	def mutate_bytes_radamsa(self,data,length):

		if type(data)!=bytes:

			struct_const = [">B",">H"]

			data = data & pow(2,(8*length))-1
			data = struct.pack(struct_const[length-1],data)

		while(1):

			mutated_string = self.pyradamsa_obj.fuzz(data, max_mut=length)

			if mutated_string != bytes(length) and mutated_string != b'' and len(mutated_string) == length:
				
				return mutated_string

	def get_valid_address(self,data,fn_code):
		
		return int.from_bytes(data,"big") % (self.valid_address[fn_code][1] - self.valid_address[fn_code][0] + 1) + self.valid_address[fn_code][0] 



	def mutate_packet(self,packet):

		tmp_packet = b''

		# trans ID 
		trans_id1 = self.mutate_bytes_radamsa(random.randint(0,255),1)
		trans_id2 = self.mutate_bytes_radamsa(random.randint(0,255),1)
		

		# protocol id  = 0
		protocol_id1 = b'\x00'
		protocol_id2 = b'\x00'

		# unit ID
		unit_id = struct.pack(">B",random.choice([0x00,0xFF]))

		# fn_code
		fn_code = random.choice([1,2,3,5,6,16,23])
		function_code = struct.pack(">B",fn_code)


		# function data 1 / Start Address
		func_data1 = self.mutate_bytes_radamsa(packet[8:12],2)

		if fn_code > 6:
			# set length to 16 for function codes 16,23

			register_count = b'\x00\x01'
			byte_count = b'\x02'
			values_to_write = b'\x00\xff'

			#start_address = int.from_bytes(func_data1,"big") % (383 - 352 + 1) + 352
			start_address = self.get_valid_address(func_data1,fn_code)

			if fn_code == 16:
				length_2 = struct.pack(">B",9)
				length_1 = struct.pack(">B",0)

				tmp_packet = trans_id1 + trans_id2 + protocol_id1 + protocol_id2 + length_1 + length_2 + unit_id + function_code + struct.pack(">H",start_address) + register_count + byte_count + values_to_write


			elif fn_code == 23:
				length_2 = struct.pack(">B",13)
				length_1 = struct.pack(">B",0)
				read_count = b'\x00\x01'

				
				func_data1 = self.mutate_bytes_radamsa(start_address,2)
				read_start_address = self.get_valid_address(func_data1,fn_code)

				func_data1 = self.mutate_bytes_radamsa(start_address,2)
				start_address = self.get_valid_address(func_data1,fn_code)
				#start_address =  random.choice([0x135,0x160,0x161,0x162,0x163,0x164,0x165,0x166]) # -> crash addresses

				tmp_packet = trans_id1 + trans_id2 + protocol_id1 + protocol_id2 + length_1 + length_2 + unit_id + function_code + struct.pack(">H",read_start_address) + read_count + struct.pack(">H",start_address) + register_count + byte_count + values_to_write 

		else:
			# set length to 6 for function codes 1-6
			length_2 = struct.pack(">B",6)
			length_1 = struct.pack(">B",0)

			
			start_address =  self.get_valid_address(func_data1,fn_code)

			#Count - function data 2
			func_data2 = self.mutate_bytes_radamsa(packet[10:12],2) 
		
			if fn_code == 1 or fn_code == 2 or fn_code == 3 or fn_code == 4:

				count = (int.from_bytes(func_data2,"big") % 0x10) + 1

			elif fn_code == 5:
				
				count = random.choice([0x0000,0xFF00])

			else:
				
				count = int.from_bytes(func_data2,"big")

			tmp_packet = trans_id1 + trans_id2 + protocol_id1 + protocol_id2 + length_1 + length_2 + unit_id + function_code + struct.pack(">H",start_address) + struct.pack(">H",count)
			
		return tmp_packet

	def formPacket(self, fields_dict):

		self.logger.debug("formPacket")

		packet = {}
		for key in fields_dict.keys():
			packet[key] = fields_dict[key][random.randint(0, 9)]

		#tmp_packet
		#packet = {'transID1': 122, 'transID2': 24, 'protoID1': 0, 'protoID2': 0, 'length1': 0, 'length2': 6, 'unitID': 1, 'functionCode': 4, 'functionData1': b'\xC8', 'functionData2': 1}

		temp_packet = []
		for i in packet.values():
			temp_packet.append(i)

		packet = bytes(bytearray(temp_packet[:-2]) + temp_packet[-2] + temp_packet[-1])

		print("[*] Sample Packet: ",packet)

		while(1):
			packet = self.mutate_packet(packet)
			self.send_socket(packet)