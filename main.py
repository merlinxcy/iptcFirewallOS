# -*- coding: utf-8 -*-
#5/13 
#when we start the firewall,this module must start(important)
import nfqueue
from scapy.all import *
import sys
import os
import socket
import dpkt
import re
#import mongolib
class PacketFilter:
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
	init_mms_fingerprint=list()
	iec61850_mms_func=['status','getNameList','identify','rename','read','write','getVariableAccessAttributes','defineNamedVariable','defineScatteredAccess','getScatteredAccessAttributes','deleteVariableAccess','defineNamedVariableList','getNamedVariableListAttributes','deleteNamedVariableList','defineNamedType','getNamedTypeAttributes','deleteNamedType','input','output','takeControl','relinquishControl','defineSemaphore','deleteSemaphore','reportSemphoreStauts','reportPoolSemaphoreStatus','reportSemaphoreEntryStatus','initiateDownloadSequence','downloadSegment','terminateDownloadSequence','initiateUploadSequence','uploadSegment','terminateUploadSequence','requestDomainDownload','requestDomainUpload','loadDomainContent','storeDomainContent','deleteDomain','getDomainAttributes','createProgramInvocation','deleteProgramInvocation','start','stop','resume','reset','kill','getProgramInvocationAttributes','obtainFile','defineEventCondition','deleteEventCondition','getEventConditionAttributes','reportEventCondiditionStauts','alterEventConditionMoitoring','triggerEvent','defineEventAction','deleteEventAction','getEventActionAttributes','reportActionStatus','defineEventEnrollment','deleteEventEnrollment','alterEventEnrollmemt','reportEventEnrollmentAttributes','getEventEnrollmentAttributes','acknowledgeEventnotification','getAlarmSummary','getAlarmEnrollmentSummary','readJournal','writeJournal','initializeJournal','reportJournalStatus','createJournal','deleteJournal','getCapabilityList','fileOpen','fileRead','fileClose','fileRename','fileDelete','fileDirectory','unsolicitedStatus','informationReport','eventNotification','attachToEventCondition','attachToSemaphore','conclude','cancel']
	iec61850_mms_func_code={
		"read":"a4",#
		"write":"a5",#
		"getNameList":"a1",#77
		"fileDirectory":"4d",#78
		"fileOpen":"48",
		"fileRead":"49",
	}

	#mongodb=''
	def __init__(self,debug=False):
		self.debug=debug
		self.count=0
		os.system('iptables -A OUTPUT -j NFQUEUE')
		#self.mongodb=mongolib.mongodb()
	def start(self,package):
		self.package=package
		#data = self.package.get_payload()
		data = self.package.get_data()
		ip_info = dpkt.ip.IP(data)
		tcp_info= dpkt.tcp.TCP(data)
		print socket.inet_ntoa(ip_info.src)+" to "+socket.inet_ntoa(ip_info.dst)
		#mongodb.log_collect(ipsrc=str(socket.inet_ntoa(ip_info.src)),ipdst=str(socket.inet_ntoa(ip_info.dst)))
		data_16 = dpkt.hexdump(str(data), 16)
		self.count+=1
		print "----------------"+str(self.count)+"---------------------"
		print data_16
		##--
		print dpkt.tcp.TCP(data).__class__.__name__ 
		temp=re.findall(r'  [0-9][0-9][0-9][0-9]:  (.*?)  ',data_16)
		package_after_decode=''
		for i in temp:
			package_after_decode+=i
		package_after_decode=package_after_decode.replace('  ',' ')
		package_after_decode=package_after_decode.replace(' ','')
		self.afterdecode=package_after_decode
		##
		#print self.afterdecode
		self.judge_iec61850_mms()
		package.set_verdict(nfqueue.NF_ACCEPT)
		##
		'''
		print "-------------------------------------"
		if not(self.judge_tcp_attack()):#judge tcp attack
			package.set_verdict(nfqueue.NF_DROP)
		if not(self.judge_modbus_attack()):
			package.set_verdict(nfqueue.NF_DROP)
		package.set_verdict(nfqueue.NF_ACCEPT)
		print ("---------------------------------------------------------")
		'''
		#mongodb.log_input()
		#mongodb.bufc()
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
			#mongodb.log_collect(msg='this is syn/fin attack')
			return False
		elif(self.afterdecode[66:68]=='00'):#all flags can't be 0 together
			print ("this is flag='0x00' attack")
			return False
			#mongodb.log_collect(msg='this is flag=\'0x00\' attack')
			#record in mongodb
		elif(self.afterdecode[66:68]=='01'):
			print ("this is fin attack")
			return False
			#mongodb.log_collect("this is fin attack")
			#record in mongodb
		else:
			print 'there is no tcp flag attack'
			return True
	def judge_modbus_attack(self):	
		if(self.afterdecode[44:48]=='01f6' and self.afterdecode[85:87]!='00' and self.afterdecode[67]<'8' and self.afterdecode[19]=='6'):#44-47 is hex(port 502),85-86 is hex protocol id of modbus package) and 67 must <8 because 'push' must be '0' and 19 is tcp
			print "This is handshake between modbus/tcp communication "
			#mongodb.log_collect(msg='This is handshake between modbus/tcp communication')
			return True
		elif(self.afterdecode[44:48]=='01f6' and self.afterdecode[85:87]=='00' and self.afterdecode[67]>='8' and self.afterdecode[19]=='6'):
			self.payload_len=self.package.get_payload_len()
			print "this is modbus package"
			#mongodb.log_collect(msg='this is modbus package')
			#record in mongodb
			if(self.afterdecode[87:89]>'00fe'):#modbus frame must <=260bytes
				print "This modbus package's length is illegal"
				#record in mongodb
				#mongodb.log_collect(msg='This modbus package\'s length is illegal')
				return False
			else:#then we go on judging the modbus package which has legal length
				for name in self.modbus_func_code:#judge function code
					if(self.afterdecode[94:96]==self.modbus_func_code[name]):
						break
					elif(name!="read_recognize"):
						continue
					else:
						print ("function code illegal")
						mongodb.log_collect(msg='function code illegal')		
						#record in mongodb
						return False
				print "this modbus package's length is legal and function code is legal"
				print ("this modbus package is safe")
				#mongodb.log_collect(msg='this modbus package\'s length is legal and function code is legal')
				#mongodb.log_collect(msg='this modbus package is safe')
				return True
		else:
			print("this is not modbus package and handshake package")
			#record in mongodb
			#mongodb.log_collect(msg='this is not modbus package and handshake package')
			return False

	def judge_iec61850_goose(self):
		pass

	def judge_iec61850_sv(self):
		pass


	def judge_iec61850_mms(self):
		#print self.afterdecode[44:48]
		#print self.afterdecode[114:116]
		#print self.afterdecode[118:127]
		#print self.afterdecode[138:140]
		if(len(self.afterdecode)>156):##判断afterdecode大小防止溢出
			if(self.afterdecode[44:48]=='0066' and self.afterdecode[114:116]=='f0'):#位置57数值f0PDU type:DT Data(0x0f)
				if(self.afterdecode[118:126]=='01000100'):#ISO 8327-1 OSI Session Protocol长度固定以01开头
					if(self.afterdecode[138:140]=='03'):
						print "!!@2$^&%!!this is request/response mms"
						tmpfun=''
						for name in self.iec61850_mms_func_code:
							if(self.afterdecode[154:156]==self.iec61850_mms_func_code[name]):
								print "confirmedservicerequest:"+name
								tmpfun=name
							if (self.afterdecode[156:158]==self.iec61850_mms_func_code[name]):
								print "confirmedservicerequest:"+name
								tmpfun=name
						#下面是检测该报文是够和init mms中支持的功能符合
						
						data = self.package.get_data()
						ip_info = dpkt.ip.IP(data)
						tcp_info= dpkt.tcp.TCP(data)
						if self.init_mms_fingerprint==[]:
							print "[-]No init mms has been created"
							return False
						else:
							#print "1"'
							location=-1
						 	init_mms_fingerprint_length=len(self.init_mms_fingerprint)
							for i in range(0,init_mms_fingerprint_length-1):
								if self.init_mms_fingerprint[i]['ip_source']==ip_info.src and self.init_mms_fingerprint[i]['tcp_sport']==tcp_info.sport and self.init_mms_fingerprint[i]['tcp_dport']==tcp_info.dport:
									location=i
									break
								else:
									if i==init_mms_fingerprint_length-1:
										location=-1
							if location!=-1:
								for t in self.init_mms_fingerprint[location]['init_mms_support_service']:
									if t==self.iec61850_mms_func:
										print "[+]Identify"
										return True

							return False#最后都没找到return False



		
		if(len(self.afterdecode)>475):##判断afterdecode大小防止溢出
			print self.afterdecode[298:230]
			print self.afterdecode[316:326]
			if(self.afterdecode[44:48]=='0066' and self.afterdecode[114:116]=='f0'):#位置57数值f0PDU type:DT Data(0x0f)
				if(self.afterdecode[118:120]=='0d'):#SPDU Type:(CONNECT(CN)SPDU(13))会话层init标签
					if(self.afterdecode[298:300]=='01'):#PDV-LIST presentation-context-identifier:1context-list item id-as-acse
						if(self.afterdecode[316:326]=='28ca220203'):#iso association control service1.0.9506.2.3(mms)
							print "!!@2$^&%!!this is mms init "
							##这边加一个对服务器支持服务的判别，可以用来过滤上下文的请求数据包,可能存在问题
							data = self.package.get_data()
							ip_info = dpkt.ip.IP(data)
							tcp_info= dpkt.tcp.TCP(data)
							tmp_funcode=self.afterdecode[456:478]#取出init报文的服务器支持功能码以供上下文判断
							tmp_funcode_bin=''
							#计算出服务开启的二进制位
							for i in range(0,len(tmp_funcode)/2-1):
								t=tmp_funcode[2*i]+tmp_funcode[i+1]
								t=str(bin(int(t,16)))[2:]
								print t
								tmp_funcode_bin+=t
							#匹配服务
							init_mms_support_service=list()
							for i in range(0,len(self.iec61850_mms_func)-1):
								if tmp_funcode_bin=='1':
									init_mms_support_service.append(self.iec61850_mms_func[i])
							mms_finger={
							"ip_source":str(ip_info.src),
							"tcp_sport":str(tcp_info.sport),
							"tcp_dport":str(tcp_info.dport),
							"init_mms_support_service":init_mms_support_service
							}
							self.init_mms_fingerprint.append(mms_finger)
							#到这里为止init mms中支持的服务已经被记录，以供来检查后续报文的合法性





		#if(len(self.))



	def run(self):
		q=nfqueue.queue()
		q.open()
		q.bind(socket.AF_INET)
		print "ok"
		q.set_callback(self.start)
		print "ok"
		q.create_queue(0)
		print "ok"
		try:
			print "ook"
			q.try_run()
			print "ook"
		except KeyboardInterrupt:
			print "ook"
			q.unbind(socket.AF_INET)
			q.close()
			os.system('iptables -F')
			os.system('iptables -X')
					
if __name__=='__main__':
	print 123
	judge=PacketFilter(debug=True)
	judge.run()
