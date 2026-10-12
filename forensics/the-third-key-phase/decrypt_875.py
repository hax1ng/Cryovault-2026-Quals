from scapy.all import rdpcap,UDP,IP
from aioquic.quic.crypto import CryptoContext,next_key_phase
from aioquic.tls import CipherSuite,hkdf_expand_label,cipher_suite_hash
from aioquic.quic.packet import QuicProtocolVersion
cr='87566bdc267eee5e8a8a7d0251033ec0ce2aef613ef35623cf1e6dc5fc1310d3'
secs={}
for l in open('secret'):
 a,b,c=l.split()
 if b==cr:secs[a]=bytes.fromhex(c)
ctx={}
for who in ['CLIENT','SERVER']:
 secret=secs[who+'_TRAFFIC_SECRET_0']; alg=cipher_suite_hash(CipherSuite.CHACHA20_POLY1305_SHA256)
 for gen in range(8):
  if gen:secret=hkdf_expand_label(alg,secret,b'quicv2 ku',b'',alg.digest_size)
  x=CryptoContext(gen&1);x.setup(cipher_suite=CipherSuite.CHACHA20_POLY1305_SHA256,secret=secret,version=QuicProtocolVersion.VERSION_2)
  ctx[who,gen]=x
base={'CLIENT':1087631,'SERVER':5982}
P=rdpcap('capture.pcapng')

def trydec(dat,who,dl):
 out=[]
 # header protection key does not change on QUIC key update
 try:h,tr=ctx[who,0].hp.remove(dat,1+dl)
 except:return out
 if h[0]&0x18:return out
 nl=(h[0]&3)+1; mod=1<<(8*nl)
 pn0=base[who]+1+(tr-(base[who]+1))%mod
 for gen in range(8):
  if ((h[0]>>2)&1)!=(gen&1):continue
  c=ctx[who,gen];pn=pn0
  while pn<=base[who]+1000000:
   try:p=c.aead.decrypt(dat[len(h):],h,pn);out.append((gen,pn,h,p))
   except:pass
   pn+=mod
 return out


for i,x in enumerate(P,1):
 if UDP not in x:continue
 # only logical conn IP .20 server and client .10:57949 or .37
 u=x[UDP]
 if not ((u.sport==57949 or u.dport==57949 or u.sport==37187 or u.dport==37187) and ('198.51.100.20' in (x[IP].src,x[IP].dst))):continue
 who='CLIENT' if u.sport!=443 else 'SERVER';dat=bytes(u.payload)
 if who=='CLIENT':dl=8 if u.sport==57949 else 12
 else:
  if u.dport==57949:dl=8
  else:dl=5 if dat[1:6] in (bytes.fromhex('07cae0fa5b'),bytes.fromhex('668f0b926e')) else 8
 hits=trydec(dat,who,dl)
 if not hits:print('MISS',i,who,dl,len(dat),dat[:20].hex())
 else:
  for gen,pn,h,p in hits:print('HIT',i,who,dl,len(dat),'gen',gen,'pn',pn,'h',h.hex(),'pl',p.hex())
