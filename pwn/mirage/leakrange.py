import socket,sys,concurrent.futures
H=('0.cloud.chals.io',23023)
def one(i):
 try:
  s=socket.create_connection(H,timeout=2);s.settimeout(.25);s.recv(10)
  s.sendall(f'SS%{i}$sEE\n'.encode()); o=b''
  while len(o)<65536:
   try:d=s.recv(65536)
   except:break
   if not d:break
   o+=d
   if o.endswith(b'> '):break
  s.close();return i,o
 except Exception as e:return i,b''
a,b=map(int,sys.argv[1:])
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
 rs=sorted(ex.map(one,range(a,b)))
for i,o in rs:
 if o:print(i,repr(o[:2000]))
