#!-*-coding:utf-8-*-
#!author:xeldax
#试试看能不能输入中文
import wx
from  tkinter import  *
import hashlib

def encode(passwd):
	enc=hashlib.md5()
	enc.update(passwd)
	return enc.hexdigest()
class Login(wx.Frame):
	def __init__(self,UpdateUI):
		self.UpdateUI=UpdateUI
		wx.Frame.__init__(self,None,-1,"Login",size=(300,300),pos=(500,300))
		panel=wx.Panel(self,-1)
		wx.StaticText(panel,-1,"Login       System",pos=(100,40))
		wx.StaticText(panel,-1,"Username: ",pos=(40,90))
		self.username=wx.TextCtrl(panel,-1,"",pos=(120,85))
		wx.StaticText(panel,-1,"Password: ",pos=(40,140))
		self.password=wx.TextCtrl(panel,-1,"",pos=(120,135),style=wx.TE_PASSWORD)
		confirm=wx.Button(panel,label="login",pos=(60,200),size=(50,50))
		exit=wx.Button(panel,label="exit",pos=(180,200),size=(50,50))
		self.Bind(wx.EVT_BUTTON,self.OnButtonClick,confirm)
		self.Bind(wx.EVT_BUTTON,self.Exit,exit)
	
	def OnButtonClick(self,event):
		u=self.username.GetValue()
		p=self.password.GetValue()
		if u=='a' and p=='a':
			self.UpdateUI(1)

	def Exit(self,event):
		self.Close()

class Content(wx.Frame):
	def __init__(self,UpdateUI):
		wx.Frame.__init__(self,None,-1,"Firewall OS",size=(600,600),pos=(200,200))
		#c_x,c_y,c_w,c_h=wx.ClientDisplayRect()
		menubar=wx.MenuBar()
		self.InitGui()

	def InitGui(self):
		self.InitMenu()
		self.InitButton()
		self.InitContent()
		self.InitStatusBar()

	def InitMenu(self):
		menubar=wx.MenuBar()
		##file menu
		menu1=wx.Menu()
		menu1.Append(-1,"Open File","")
		menu1.AppendSeparator()
		menu1.Append(-1,"Import from hex dump","")
		menu1.Append(-1,"Save File","")
		menu1.AppendSeparator()
		menu1.Append(-1,"Recent File...","")
		menubar.Append(menu1,"File")
		##Go menu
		menu2=wx.Menu()
		menu2.Append(-1,"Start firewall","")
		menu2.Append(-1,"Stop firewall","")
		menubar.Append(menu2,"Go")
		##analysis menu
		menu3=wx.Menu()
		menu3.Append(-1,"Analysis Graph")
		menubar.Append(menu3,"Analysis")
		##setting menu
		menu4=wx.Menu()
		menu4.Append(-1,"Firewall Setting","")
		menubar.Append(menu4,"Setting")
		##help menu
		menu5=wx.Menu()
		menu5.Append(-1,"Help","")
		about=menu5.Append(-1,"About us","")
		menubar.Append(menu5,"About")
		##exit menu
		menu6=wx.Menu()
		exit=menu6.Append(-1,"Exit","")
		menubar.Append(menu6,"Exit")
		self.Bind(wx.EVT_MENU,lambda event:self.Close(),exit)
		self.Bind(wx.EVT_MENU,self.OnShowGroup,about)
		##
		self.SetMenuBar(menubar)

	def InitButton(self):
		self.panel=wx.Panel(self,-1)
		self.panel.SetBackgroundColour('White')
		wx.Button(self.panel,label="Startup Firewall OS ",pos=(10,10))
		wx.Button(self.panel,label="Stop Firewall OS",pos=(155,10))
	
	def InitContent(self):
		packetlist=["1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1"]
		listbox=wx.ListBox(self.panel,-1,(8,50),(585,200),packetlist,style=(wx.LB_SINGLE))
		#listbox.SetSelection(1)
		text=wx.TextCtrl(self.panel,-1,"11",size=(585,220),pos=(8,260),style=(wx.TE_MULTILINE | wx.TE_AUTO_SCROLL | wx.TE_DONTWRAP))
		text.SetBackgroundColour('White')
		text.SetValue("1223")
	def InitStatusBar(self):
		statusbar=self.CreateStatusBar()
	##event process
	def OnShowGroup(self,event):
		wx.MessageBox("Author:            \nXeldax\nwang123321\nxuying_zhu\nkalafinaglll")

	##
	


class App(wx.App):
	global switch
	def OnInit(self):
		self.frame=Login(UpdateUI=self.UpdateUI)
		self.frame.Show()
		return True

	def UpdateUI(self,type):
		if type==1:
			self.frame.Close()
			self.frame=Content(UpdateUI=self.UpdateUI)
			self.frame.Show()
		if type==0:
			self.frame.Close()
			self.frame=Login(UpdateUI=self.UpdateUI)
			self.frame.Show()
		return True


if __name__=='__main__':
	app=App()
	app.MainLoop()