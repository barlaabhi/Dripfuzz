from core.logger import get_logger

import pyradamsa
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

	def send_packet(self, packet,sock):

		self.logger.debug("send_packet")

		# remove make packet 
		ModbusPacket = self.make_packet(packet) 
		#AddToPCAP(ModbusPacket)
		#AddToPCAP(RespPacket)
		try:
			sock.send(ModbusPacket)
		except socket.timeout:
			self.logger.error("[-] Sending Timed Out!")
		except socket.error:
			self.logger.error("[-] Sending Failed!")
			sock.close()
			sock = self.create_connection(self.dest_port)
		else:
			self.logger.debug("[+] Sent Packet: %s" % hexstr(ModbusPacket))
			
			print("[*] Sent: %s" % hexstr(ModbusPacket))

			try:
				RespPacket = sock.recv(1024)
				print('[*] Received: %s'% hexstr(RespPacket))

			except TimeoutError:
				pass
		return


	def get_mutated_string(self,data,length):

		struct_const = [">B",">H"]

		data = data & pow(2,(8*length))-1
		data = struct.pack(struct_const[length-1],data)

		mutated_string = b''

		while len(mutated_string) < (length+1) and mutated_string <= bytes(length):

			mutated_string = self.pyradamsa_obj.fuzz(data,max_mut=length)


		return mutated_string




	def mutate_modbus_radamsa(self,packet):
		

		# set length to 6
		packet['length2'] = 6
		packet['length1'] = 0

		# protocol id  = 0
		packet['protoID1'] = 0
		packet['protoID2'] = 0

		#packet['unitID'] = 0xFF

		# trans ID 
		trans_id1 = self.get_mutated_string(packet['transID1'],1)
		packet['transID1'] = int.from_bytes(trans_id1,"big")


		trans_id2 = self.get_mutated_string(packet['transID2'],1)
		packet['transID2'] = int.from_bytes(trans_id2,"big")

		# Function Code
		func_code = self.get_mutated_string(packet['functionCode'],1)
		packet['functionCode'] = ( int.from_bytes(func_code,"big") % 6 ) + 1

		func_data1 = self.get_mutated_string(packet['functionData1'],2)
		packet['functionData1'] = int.from_bytes(func_data1,"big")

		# Function data 2
		
		func_data2 = self.get_mutated_string(packet['functionData2'],2)
		
		if packet['functionCode'] == 1 or packet['functionCode'] == 2:

			packet['functionData2'] = (int.from_bytes(func_data2,"big") % 0x7D0) + 1

		elif packet['functionCode'] == 3 or packet['functionCode'] == 4:

			packet['functionData2'] = (int.from_bytes(func_data2,"big") % 0x7D) + 1

		elif packet['functionCode'] == 5:
			
			packet['functionData2'] = random.choice([0x0000,0xFF00])
		else:
			
			packet['functionData2'] = int.from_bytes(func_data2,"big")

		# Function data 1

		# rand % (max - min + 1) + min -> get a value between min and max

		func_data1 = self.get_mutated_string(packet['functionData1'],2)

		if packet['functionCode'] == 1:

			packet['functionData1'] =  int.from_bytes(func_data1,"big") % (341 - 304 + 1) + 304 

		elif packet['functionCode'] == 2:

			packet['functionData1'] = int.from_bytes(func_data1,"big") % (473 - 452 + 1) + 452

		elif packet['functionCode'] == 3:
			
			packet['functionData1'] = int.from_bytes(func_data1,"big") % (387 - 352  + 1) + 352
		
		elif packet['functionCode'] == 5:
			
			packet['functionData1'] = int.from_bytes(func_data1,"big") % (341 - 304 + 1) + 304 

		elif packet['functionCode'] == 6:
			
			packet['functionData1'] = int.from_bytes(func_data1,"big") % (383 - 352 + 1) + 352



	def formPacket(self, fields_dict):

		self.logger.debug("formPacket")

		packet = {}
		for key in fields_dict.keys():
			packet[key] = fields_dict[key][random.randint(0, 9)]

		#tmp_packet
		#packet = {'transID1': 122, 'transID2': 24, 'protoID1': 0, 'protoID2': 0, 'length1': 0, 'length2': 6, 'unitID': 1, 'functionCode': 4, 'functionData1': 0xC8, 'functionData2': 0}

		print("[*] Initial Packet: ",packet)

		sock = self.create_connection(self.dest_port)
		
		while(1):
		 	self.mutate_modbus_radamsa(packet)
		 	self.send_packet(packet,sock)