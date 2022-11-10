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

		self.SOCK = None

	def create_connection(self, port):
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		except socket.error as msg:
			sys.stderr.write("[ERROR] %s\n" % msg[1])
		try:
			#sock.bind((HOST,src_port))
			sock.settimeout(0.5)
			sock.connect((self.HOST, self.dest_port))

		except socket.error as msg:
			self.logger.warning("[-] Connection Failed!")
		else:
			self.logger.info("[+] Connected to Server: %s" % self.HOST)
		
		return sock

	def make_packet(self, packet):

		TotalModbusPacket =  b''
		TotalModbusPacket += struct.pack(">B", packet['transID1'])
		TotalModbusPacket += struct.pack(">B", packet['transID2'])
		TotalModbusPacket += struct.pack(">B", packet['protoID1'])
		TotalModbusPacket += struct.pack(">B", packet['protoID2'])
		TotalModbusPacket += struct.pack(">B", packet['length1'])
		TotalModbusPacket += struct.pack(">B", packet['length2'])
		TotalModbusPacket += struct.pack(">B", packet['unitID'])
		TotalModbusPacket += struct.pack(">B", packet['functionCode'])
		TotalModbusPacket += struct.pack(">H", packet['functionData1'])
		TotalModbusPacket += struct.pack(">H", packet['functionData2'])
		return TotalModbusPacket


	def AddToPCAP(self, packet):
		pkt = Ether()/IP()/TCP(sport=self.src_port, dport = self.dest_port)/packet/Modbus()
		wrpcap('test.pcap', pkt, append=True)

	def send_socket(self, packet):

		self.logger.debug("send_packet")

		# remove make packet 
		#ModbusPacket = self.make_packet(packet) 
		#AddToPCAP(ModbusPacket)
		#AddToPCAP(RespPacket)

		try:
		
			self.SOCK.sendall(packet+b'\x00')
		
		except socket.timeout:
			
			self.logger.error("[-] Sending Timed Out!")
		
		except socket.error:

			self.logger.error("[-] Sending Failed!")
			self.SOCK.close()
			self.SOCK = self.create_connection(self.dest_port)
		
		else:
			self.logger.debug("[+] Sent Packet: %s" % hexstr(packet))
			
			print("[*] Sent: %s" % hexstr(packet))

			# try:

			# 	RespPacket = self.SOCK.recv(1024)
			# 	print('[*] Received: %s'% hexstr(RespPacket))

			# except TimeoutError:
			# 	pass
		return

	def send_system(self,packet):

		self.logger.debug("send_packet")

		print("[*] Sent: %s" % hexstr(packet))

		self.logger.debug("[+] Sent Packet: %s" % hexstr(packet))

		base64_str = base64.b64encode(packet+b'\x00').decode()
		
		command = f"echo {base64_str} | base64 -d | nc 127.0.0.1 1502"
		
		os.system(command)


	def get_mutated_string(self,data,length):

		# Assuming this fn is fixed
		if type(data)!=bytes:

			struct_const = [">B",">H"]

			data = data & pow(2,(8*length))-1
			data = struct.pack(struct_const[length-1],data)


		while(1):

			mutated_string = self.pyradamsa_obj.fuzz(data, max_mut=length)

			if mutated_string != bytes(length) and mutated_string != b'' and len(mutated_string) == length:
				
				return mutated_string



	def mutate_modbus_radamsa(self,packet):

		tmp_packet = b''

		# trans ID 
		trans_id1 = self.get_mutated_string(random.randint(0,255),1)
		trans_id2 = self.get_mutated_string(random.randint(0,255),1)
		

		# protocol id  = 0
		protocol_id1 = b'\x00'
		protocol_id2 = b'\x00'

		# unit ID
		unit_id = struct.pack(">B",random.choice([0x00,0xFF]))

		# fn_code
		fn_code = random.choice([1,2,3,5,6])
		function_code = struct.pack(">B",fn_code)


		#function data 1
		func_data1 = self.get_mutated_string(packet['start_addr'],2)

		if fn_code > 6:
			# set length to 16 for function codes 16,23

			register_count = b'\x00\x01'
			byte_count = b'\x02'
			values_to_write = b'\x00\xff'

			start_address = int.from_bytes(func_data1,"big") % (383 - 352 + 1) + 352


			if fn_code == 16:
				length_2 = struct.pack(">B",9)
				length_1 = struct.pack(">B",0)

				tmp_packet = trans_id1 + trans_id2 + protocol_id1 + protocol_id2 + length_1 + length_2 + unit_id + function_code + struct.pack(">H",start_address) + register_count + byte_count + values_to_write


			elif fn_code == 23:
				length_2 = struct.pack(">B",13)
				length_1 = struct.pack(">B",0)
				read_count = b'\x00\x01'

				
				func_data1 = self.get_mutated_string(start_address,2)

				read_start_address = int.from_bytes(func_data1,"big") % (383 - 352 + 1) + 352
				
				start_address = int.from_bytes(func_data1,"big") % (383 - 330 + 1) + 330 #random.choice([0x135,0x136,0x137,0x14D,0x14E,0x14F,0x15D,0x15E,0x15F]) -> crash addresses

				tmp_packet = trans_id1 + trans_id2 + protocol_id1 + protocol_id2 + length_1 + length_2 + unit_id + function_code + struct.pack(">H",read_start_address) + read_count + struct.pack(">H",start_address) + register_count + byte_count + values_to_write 

			return tmp_packet

		# else
		# set length to 6 for function codes 1-6
		length_2 = struct.pack(">B",6)
		length_1 = struct.pack(">B",0)

		
		if fn_code == 1 or fn_code == 5:

			start_address =  int.from_bytes(func_data1,"big") % (341 - 304 + 1) + 304 

		elif fn_code == 2:

			start_address = int.from_bytes(func_data1,"big") % (473 - 452 + 1) + 452

		elif fn_code == 3:
			
			start_address = int.from_bytes(func_data1,"big") % (387 - 352  + 1) + 352

		elif fn_code == 6:
			
			start_address = int.from_bytes(func_data1,"big") % (383 - 352 + 1) + 352


		#Count - function data 2
		func_data2 = self.get_mutated_string(packet['count'],2) 
	
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
		#packet = {'transID1': 122, 'transID2': 24, 'protoID1': 0, 'protoID2': 0, 'length1': 0, 'length2': 6, 'unitID': 1, 'functionCode': 4, 'functionData1': 0xC8, 'functionData2': 0}

		print("[*] Initial Packet: ",packet)

		#self.SOCK = self.create_connection(self.dest_port)
		
		while(1):
			mutated_packet = self.mutate_modbus_radamsa(packet)
			self.send_system(mutated_packet)