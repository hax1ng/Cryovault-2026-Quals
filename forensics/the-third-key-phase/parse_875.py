# import parser definitions without executing analysis
src=open('analyze_target.py').read(); exec(src[src.index('def vi'):src.index("P=rdpcap")])
streams={}
for line in open('dec875.txt'):
 z=line.split();i=int(z[1]);who=z[2];gen=int(z[6]);pn=int(z[8]);pl=bytes.fromhex(z[12])
 try:fs=frames(pl)
 except Exception as e:
  print('PARSEERR',i,who,gen,pn,e,pl.hex());continue
 print('PKT',i,who,'gen',gen,'pn',pn,'len',len(pl))
 for pos,t,d in fs:
  if 'data' in d: print(' ',hex(t),{**d,'data':repr(d['data'][:100]),'len':len(d['data'])})
  else: print(' ',hex(t),d)
  if 8<=t<=15:
   streams.setdefault((who,d['stream']),[]).append((d['off'],d['data'],d['fin'],i,pn,gen))
print('\nSTREAMS')
for k,ch in streams.items():
 n=max(o+len(d) for o,d,*_ in ch);b=bytearray(n);seen=bytearray(n);conf=0
 for o,d,*_ in ch:
  for j,v in enumerate(d):
   if seen[o+j] and b[o+j]!=v:conf+=1
   b[o+j]=v;seen[o+j]=1
 hs=[i for i,v in enumerate(seen) if not v];rs=[]
 for x in hs:
  if rs and x==rs[-1][1]+1:rs[-1][1]=x
  else:rs.append([x,x])
 print(k,'chunks',len(ch),'range',n,'seen',sum(seen),'holes',rs,'conf',conf,'finends',[o+len(d) for o,d,f,*_ in ch if f], 'repr',repr(bytes(b[:150])))
 open(f'875_stream_{k[0]}_{k[1]}.bin','wb').write(b)
