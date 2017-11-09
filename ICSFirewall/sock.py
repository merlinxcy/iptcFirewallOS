import socket
import binascii


a2="6a0100000006030500630000"





a1="000c2954455954271e4ca7f20800450000341a72400040069eebc0a80005c0a80011e1a801f6ffaa6748c5a898c2501810ea070000006a0100000006030500630000"

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("192.168.0.17",502))
t=binascii.a2b_hex(a2)
s.send(t)
print s.recv(1024)
s.close()
