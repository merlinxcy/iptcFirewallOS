# -*- coding: utf-8 -*-
#5/13 
#when we start the firewall,this module must start(important)
from netfilterqueue import NetfilterQueue
from scapy.all import *
import sys
import os
import socket
import dpkt
import re
import mongolib
class Judge_modbus:
	debug='False'
	afterdecode=''
	payload_len=''
	package=''
	modbus_func_code={
		"dispersed_and_input": "02",
		"read_coil":"01",
		"write_single_coil":"05",
		"write_multiple_coil":"0f",
		"read_input_register":"04",
		"read_multiple_register":"03",
		"write_single_register":"06",
		"write_multiple_register":"10",
		"read_write_multiple_register":"17",
		"cannot_write_register":"16",
		"read_file_record":"14",
		"write_file_record":"15",
		"read_recognize":"2b",
	}
	mongodb=''
	def __init__(self,debug=False):
		self.debug=debug
		self.mongodb=mongolib.mongodb()
	def start(self,package):
		self.package=package
		data = self.package.get_payload()
		ip_info = dpkt.ip.IP(data)
		tcp_info= dpkt.tcp.TCP(data)
		print socket.inet_ntoa(ip_info.src)+" to "+socket.inet_ntoa(ip_info.dst)
		self.mongodb.log_collect(ipsrc=str(socket.inet_ntoa(ip_info.src)),ipdst=str(socket.inet_ntoa(ip_info.dst)))
		data_16 = dpkt.hexdump(str(data), 16) 
		#print data_16
		temp=re.findall(r'  [0-9][0-9][0-9][0-9]:  (.*?)  ',data_16)
		package_after_decode=''
		for i in temp:
			package_after_decode+=i
		package_after_decode=package_after_decode.replace('  ',' ')
		package_after_decode=package_after_decode.replace(' ','')
		self.afterdecode=package_after_decode
		#print self.afterdecode
		
		if not(self.judge_tcp_attack()):#judge tcp attack
			self.package.drop()
		if not(self.judge_modbus_attack()):
			self.package.drop()
		self.package.accept()
		print ("---------------------------------------------------------")
		self.mongodb.log_input()
		self.mongodb.log_bufc()
	'''
	def judge_udp_attack(self):(thought l want to judge UDP,the dhcp use it,it's difficult)
		if(self.afterdecode[18:20]=='11'):
			print("this is udp package")
			return True
	'''
	def judge_tcp_attack(self):
		if(self.afterdecode[66:68]=='03'):#syn and find can't be 1 together
			print ("this is syn/fin attack")
			#record in mongodb
			self.mongodb.log_collect(msg='this is syn/fin attack')
			return False
		elif(self.afterdecode[66:68]=='00'):#all flags can't be 0 together
			print ("this is flag='0x00' attack")
			return False
			self.mongodb.log_collect(msg='this is flag=\'0x00\' attack')
			#record in mongodb
		elif(self.afterdecode[66:68]=='01'):
			print ("this is fin attack")
			return False
			self.mongodb.log_collect("this is fin attack")
			#record in mongodb
		else:
			print 'there is no tcp flag attack'
			return True
	def judge_modbus_attack(self):	
		if(self.afterdecode[44:48]=='01f6' and self.afterdecode[85:87]!='00' and self.afterdecode[67]<'8' and self.afterdecode[19]=='6'):#44-47 is hex(port 502),85-86 is hex protocol id of modbus package) and 67 must <8 because 'push' must be '0' and 19 is tcp
			print "This is handshake between modbus/tcp communication "
			self.mongodb.log_collect(msg='This is handshake between modbus/tcp communication')
			return True
		elif(self.afterdecode[44:48]=='01f6' and self.afterdecode[85:87]=='00' and self.afterdecode[67]>='8' and self.afterdecode[19]=='6'):
			self.payload_len=self.package.get_payload_len()
			print "this is modbus package"
			self.mongodb.log_collect(msg='this is modbus package')
			#record in mongodb
			if(self.afterdecode[87:89]>'00fe'):#modbus frame must <=260bytes
				print "This modbus package's length is illegal"
				#record in mongodb
				self.mongodb.log_collect(msg='This modbus package\'s length is illegal')
				return False
			else:#then we go on judging the modbus package which has legal length
				for name in self.modbus_func_code:#judge function code
					if(self.afterdecode[94:96]==self.modbus_func_code[name]):
						break
					elif(name!="read_recognize"):
						continue
					else:
						print ("function code illegal")
						self.mongodb.log_collect(msg='function code illegal')		
						#record in mongodb
						return False
				print "this modbus package's length is legal and function code is legal"
				print ("this modbus package is safe")
				self.mongodb.log_collect(msg='this modbus package\'s length is legal and function code is legal')
				self.mongodb.log_collect(msg='this modbus package is safe')
				return True
		else:
			print("this is not modbus package and handshake package")
			#record in mongodb
			self.mongodb.log_collect(msg='this is not modbus package and handshake package')
			return False
					
if __name__=='__main__':
	judge=Judge_modbus(debug=True)
	nfqueue=NetfilterQueue()
	nfqueue.bind(0,judge.start)
	try:
		nfqueue.run()
	except KeyboardInterrupt:
		print ('')
	nfqueue.unbind()
