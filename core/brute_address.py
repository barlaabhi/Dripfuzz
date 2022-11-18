import time
import socket,struct,os,sys 
import subprocess

class Brute:

	def __init__(self):

		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    
		self.sock.settimeout(0.5)
		self.port = 1502
		

		self.functionCode_exceptionCode = { 5:133,
							  6:134,
							  1:129,
							  2:130,
							  3:131,
							  4:132} 
		if os.fork()==0:
			
			subprocess.run(["pkill", "-9","server"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
			subprocess.run(["/home/abhishek/Desktop/Dripfuzz/server/server"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
			sys.exit(0)
		
		time.sleep(1)
		self.sock.connect(('127.0.0.1', self.port))


	def get_address_range(self):
							  
		valid_address = {}

		for fn_code in self.functionCode_exceptionCode:

			arr = []

			base_packet = b'\x00\x01\x00\x00\x00'
			pack_len = b'\x06'
			unit_addr = b'\x00' 

			base_packet += pack_len + unit_addr
			function_code = struct.pack(">B",fn_code)

			if fn_code == 5 or fn_code ==6:
				count = b'\x00\x00'
			else:
				count = b'\x00\x11'

			for addr in range(0xffff):
				base_addr = struct.pack(">H",addr)
				ModbusPacket = base_packet+function_code+base_addr+count

				try:

					self.sock.send(ModbusPacket)
					RespPacket = self.sock.recv(1024)

					if (self.functionCode_exceptionCode[fn_code] !=  RespPacket[7]):
						arr.append(struct.unpack(">H",ModbusPacket[8:10])[0])

				except:

					continue

			if len(arr) > 1:
				arr = [(min(arr)-5)%0xffff,(max(arr)+5)%0xffff] # range can be changed
			else:
				arr = [0x0000,0xff00]

			valid_address[fn_code] = arr

		# since function codes 23,16 are reading and writing to registers (same as function code 6)
		valid_address[23] = valid_address[6] 
		valid_address[16] = valid_address[6]

		self.sock.close()
		
		os.system("pkill -9 server")
		print("[*] Extracted Mapping Address range")
		print(valid_address)
		return valid_address

