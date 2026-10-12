from scapy.all import rdpcap,UDP,IP
from aioquic.quic.crypto import CryptoContext
from aioquic.tls import CipherSuite
from aioquic.quic.packet import QuicProtocolVersion
import json
cr='bfa624226cf1fb3c6ddb66639bfed65bf632cbb1454daf32af69c66f6a781555'
sec={}
for l in open('secret'):
 a,b,c=l.split()
 if b==cr:sec[a]=bytes.fromhex(c)
ctx={}
for who in ['CLIENT','SERVER']:
 c=CryptoContext();c.setup(cipher_suite=CipherSuite.AES_128_GCM_SHA256,secret=sec[who+'_TRAFFIC_SECRET_0'],version=QuicProtocolVersion.VERSION_1);ctx[who]=c
base={'CLIENT':275740,'SERVER':58259}

def vi(b,p):
 n=1<<(b[p]>>6); return int.from_bytes(b[p:p+n],'big')&((1<<(n*8-2))-1),p+n

def frames(b):
 p=0; out=[]
 while p<len(b):
  st=p; t,p=vi(b,p)
  if t==0: # collapse padding
   while p<len(b) and b[p]==0:p+=1
   out.append((st,t,{'count':p-st}));continue
  if t==1:out.append((st,t,{}));continue
  if t in (2,3):
   # largest, delay, ranges, first range, then gap/range; ECN 3 ctrs
   vals=[]
   for _ in range(4):x,p=vi(b,p);vals.append(x)
   for _ in range(vals[2]):
    x,p=vi(b,p);y,p=vi(b,p);vals.extend([x,y])
   if t==3:
    for _ in range(3):x,p=vi(b,p);vals.append(x)
   out.append((st,t,{'ack':vals}));continue
  if t==4:
   sid,p=vi(b,p);err,p=vi(b,p);fs,p=vi(b,p);out.append((st,t,{'stream':sid,'err':err,'final':fs}));continue
  if t==5:
   sid,p=vi(b,p);err,p=vi(b,p);out.append((st,t,{'stream':sid,'err':err}));continue
  if t==6:
   off,p=vi(b,p);ln,p=vi(b,p);d=b[p:p+ln];p+=ln;out.append((st,t,{'off':off,'data':d}));continue
  if t==7:
   ln,p=vi(b,p);d=b[p:p+ln];p+=ln;out.append((st,t,{'data':d}));continue
  if 8<=t<=15:
   sid,p=vi(b,p);off=0
   if t&4:off,p=vi(b,p)
   if t&2:ln,p=vi(b,p)
   else:ln=len(b)-p
   d=b[p:p+ln];p+=ln
   out.append((st,t,{'stream':sid,'off':off,'fin':bool(t&1),'data':d}));continue
  if t in (16,18,19):
   x,p=vi(b,p);out.append((st,t,{'value':x}));continue
  if t==17:
   sid,p=vi(b,p);mx,p=vi(b,p);out.append((st,t,{'stream':sid,'max':mx}));continue
  if t in (20,22,23):
   x,p=vi(b,p);out.append((st,t,{'value':x}));continue
  if t==21:
   sid,p=vi(b,p);mx,p=vi(b,p);out.append((st,t,{'stream':sid,'max':mx}));continue
  if t==24:
   seq,p=vi(b,p);ret,p=vi(b,p);cl=b[p];p+=1;cid=b[p:p+cl];p+=cl;tok=b[p:p+16];p+=16;out.append((st,t,{'seq':seq,'retire':ret,'cid':cid,'token':tok}));continue
  if t==25:
   seq,p=vi(b,p);out.append((st,t,{'seq':seq}));continue
  if t in (26,27):
   d=b[p:p+8];p+=8;out.append((st,t,{'data':d}));continue
  if t in (28,29):
   err,p=vi(b,p)
   if t==28:ft,p=vi(b,p)
   ln,p=vi(b,p);reason=b[p:p+ln];p+=ln;out.append((st,t,{'err':err,'reason':reason}));continue
  if t==30:out.append((st,t,{}));continue
  if t in (48,49):
   if t&1: ln,p=vi(b,p)
   else:ln=len(b)-p
   d=b[p:p+ln];p+=ln;out.append((st,t,{'data':d}));continue
  raise ValueError(f'unknown frame {t:#x} at {st}/{len(b)} tail {b[st:st+30].hex()}')
 return out

P=rdpcap('capture.pcapng')
records=[];streams={}
for i,x in enumerate(P,1):
 if UDP not in x:continue
 # target tuple port58379
 if 58379 not in (x[UDP].sport,x[UDP].dport):continue
 who='CLIENT' if x[UDP].sport!=443 else 'SERVER';dat=bytes(x[UDP].payload)
 try:hdr,pl,pn,upd=ctx[who].decrypt_packet(dat,9,base[who]+1)
 except Exception as e:
  print('MISS',i,who,len(dat),dat[:20].hex(),e);continue
 try:fs=frames(pl)
 except Exception as e:
  print('PARSEERR',i,who,pn,pl.hex(),e);continue
 print(f'PKT {i} {who} pn={pn} h={hdr.hex()} payloadlen={len(pl)}')
 for pos,t,z in fs:
  if 'data' in z:
   d=z['data'];zz={**z,'data':f'{len(d)}B {d[:80]!r} hex={d[:50].hex()}'}
  else:zz=z
  print(f'  @{pos} frame={t:#x} {zz}')
  if 8<=t<=15:
   key=(who,z['stream']);streams.setdefault(key,[]).append((z['off'],z['data'],z['fin'],i,pn))
 records.append((i,who,pn,hdr,pl,fs))
print('\nSTREAMS')
for k,ch in streams.items():
 n=max(o+len(d) for o,d,*_ in ch);buf=bytearray(n);seen=bytearray(n)
 for o,d,*_ in ch:
  for j,v in enumerate(d):
   if seen[o+j] and buf[o+j]!=v:print('CONFLICT',k,o+j)
   buf[o+j]=v;seen[o+j]=1
 print(k,'chunks',len(ch),'range',n,'seen',sum(seen),'holes',[(i,j) for i in range(n) if not seen[i] for j in []], 'finends',[o+len(d) for o,d,f,*_ in ch if f])
 # compact holes
 hs=[i for i,v in enumerate(seen) if not v];rs=[]
 for x in hs:
  if rs and x==rs[-1][1]+1:rs[-1][1]=x
  else:rs.append([x,x])
 print(' holes',rs)
 print(' repr',repr(bytes(buf[:500])))
 open(f'stream_{k[0]}_{k[1]}.bin','wb').write(buf)
