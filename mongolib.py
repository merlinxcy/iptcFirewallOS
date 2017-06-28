from pymongo import MongoClient
import pymongo
class mongodb:
	mongo=''
	db=''
	collection=''
	log=''
	ipsrc=''
	ipdst=''
	macsrc=''
	macdst=''
	level=''
	id=0
	def __init__(self):
		self.mongo=MongoClient('mongodb://localhost:27017/')
		self.db=self.mongo['firewall']
		self.collection=self.db['log_cache']

	def log_collect(self,msg='',ipsrc='',ipdst='',macsrc='',macdst='',level=''):
		if msg!='':
			self.log+=msg
			self.log+="\n"
		if ipsrc!='' and ipdst!='':
			self.ipsrc=ipsrc
			self.ipdst=ipdst
		if macsrc!='' and macdst!='':
			self.macsrc=macsrc
			self.macdst=macdst
		if level!='':
			self.level=level

	def log_input(self):
		self.id+=1
		selfie={
		'id':self.id,
		'macsrc':self.macsrc,
		'macdst':self.macdst,
		'ipsrc':self.ipsrc,
		'ipdst':self.ipdst,
		'level':self.level,
		'log':self.log
		}
		print selfie
		#print selfie['log']
		results=self.collection.insert(selfie)
	def log_bufc(self):
		self.log=''
		self.ipsrc=''
		self.ipdst=''
		self.macsrc=''
		self.macdst=''

	def log_output(self):
		query={}
		cursor=self.collection.find()
		for doc in cursor:
			print doc
			print '-----------------------------'

	def log_clear(self):
		query={}
		cursor=self.collection.remove()







if __name__=='__main__':
	a=mongodb()
	a.log_collect(msg='1gaejiusfuadaifuagusuifhiau afdu gaudf uisg uagsi gaug asyaigasydg aug iug ')
	a.log_collect(msg='2')
	a.log_input()
	a.log_output()
