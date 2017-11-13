from matplotlib import pyplot
import mongolib
class pieplot():
	def __init__(self):
		self.figure=pyplot.figure(figsize=(6,9))
		self.label={'init mms','mms resquest/respond','modbus','normol tcp'}
		self.size=[60,30,10,1]
		self.color=['red','yellowgreen','lightskyblue','white']
		self.explode=(0.05,0,0,0)

	def set_size(self,size):
		self.size=size

	def make_pie(self):
		self.patches,l_text,p_text=pyplot.pie(self.size,explode=\
			self.explode,labels=self.label,colors=self.color,\
			labeldistance=1.1,autopct='%3.1f%%',shadow=False,\
			startangle=90,pctdistance=0.6)
		for t in l_text:
			t.set_size=(30)

		for t in p_text:
			t.set_size=(20)

		pyplot.axis('equal')
		pyplot.legend()

	def show_pie(self):
		pyplot.show()



if __name__=='__main__':
	a=pieplot()
	a.make_pie()
	a.show_pie()

