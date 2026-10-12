#!/usr/bin/env python3
"""Forge first policy chunk while preserving its CRC32C and whole-file Adler32."""
import sys,json,zlib,itertools,time
class CRC32C:
    tab=[]
    for i in range(256):
        c=i
        for _ in range(8): c=(c>>1)^0x82F63B78 if c&1 else c>>1
        tab.append(c)
    @classmethod
    def calc(cls,data):
        c=0xffffffff
        for b in data:c=cls.tab[(c^b)&255]^(c>>8)
        return c^0xffffffff

def main():
    if len(sys.argv)<4: raise SystemExit(f'usage: {sys.argv[0]} POLICY TARGET_ID FIRST_CHUNK_LEN [OUTPUT] [COUNT]')
    fn,target,n0=sys.argv[1],sys.argv[2].encode(),int(sys.argv[3]);outfn=sys.argv[4] if len(sys.argv)>4 else 'forged0.bin'
    want=int(sys.argv[5]) if len(sys.argv)>5 else 1
    orig=bytearray(open(fn,'rb').read()); N=len(orig); doc=json.loads(orig)
    old=doc['release']['to'][0]['id'].encode(); needle=b'"id": "'+old
    pos=orig.find(needle,orig.find(b'"release"'))+len(b'"id": "')
    assert pos>=len(b'"id": "') and len(old)==len(target), (old,target,pos)
    base=bytearray(orig);base[pos:pos+len(target)]=target
    ranges=[]
    for key in (b'"vault": "',b'"issued_by": "',b'"issued": "'):
        a=orig.find(key)+len(key);b=orig.find(b'"',a);ranges.append((a,b))
    varpos=[i for a,b in ranges for i in range(a,b)]
    # Compensate the ID edit's two Adler deltas using two harmless string bytes.
    reqA=-sum(base[i]-orig[i] for i in range(N))
    reqB=-sum((N-i)*(base[i]-orig[i]) for i in range(N))
    pair=None
    for p in varpos:
      for q in varpos:
        if p==q:continue
        den=q-p;num=reqB-(N-q)*reqA
        if num%den:continue
        dp=num//den;dq=reqA-dp;vp=orig[p]+dp;vq=orig[q]+dq
        if all(0x20<=v<=0x7e and v not in (0x22,0x5c) for v in (vp,vq)):
            pair=(p,dp,q,dq);break
      if pair:break
    if not pair:raise RuntimeError('no two-byte exact Adler compensation found')
    p,dp,q,dq=pair;base[p]+=dp;base[q]+=dq
    assert zlib.adler32(base)==zlib.adler32(orig)
    # Independent second-difference transforms [t,-2t,t] on adjacent triples
    # preserve both halves of Adler32 exactly.
    groups=[]
    for a,b in ranges:
      for p in range(a,b-2,3):
        ps=(p,p+1,p+2);valid=[]
        for t in range(-127,128):
          vals=(base[p]+t,base[p+1]-2*t,base[p+2]+t)
          if all(0x20<=v<=0x7e and v not in (0x22,0x5c) for v in vals):valid.append(t)
        # Spread 8 choices across the interval, always retaining zero.
        chosen=[]
        for k in range(8):
          x=valid[round(k*(len(valid)-1)/7)]
          if x not in chosen:chosen.append(x)
        if 0 not in chosen:chosen[len(chosen)//2]=0
        chosen=list(dict.fromkeys(chosen))
        for x in valid:
          if len(chosen)>=8:break
          if x not in chosen:chosen.append(x)
        assert len(chosen)>=8
        groups.append((ps,chosen[:8]))
    assert len(groups)>=14,len(groups)
    groups=groups[:14]
    crc0=CRC32C.calc(base[:n0]);goal=CRC32C.calc(orig[:n0])^crc0
    effects=[]
    for ps,opts in groups:
      es=[]
      for t in opts:
        z=bytearray(base[:n0]);z[ps[0]]+=t;z[ps[1]]-=2*t;z[ps[2]]+=t
        es.append(CRC32C.calc(z)^crc0)
      effects.append(es)
    print('old/target/idpos:',old.decode(),target.decode(),pos)
    print('N/chunk/ranges:',N,n0,ranges)
    print('Adler pair:',pair,'baseline',hex(zlib.adler32(base)&0xffffffff))
    print('CRC original/baseline/goal:',hex(CRC32C.calc(orig[:n0])),hex(crc0),hex(goal),flush=True)
    left=effects[:7];right=effects[7:14]
    tab={};started=time.time()
    for inds in itertools.product(range(8),repeat=7):
      x=0;code=0
      for j,k in enumerate(inds):x^=left[j][k];code|=k<<(3*j)
      tab.setdefault(x,code)
    print('left table',len(tab),'in',time.time()-started,'sec',flush=True)
    found=[]
    for inds in itertools.product(range(8),repeat=7):
      x=0
      for j,k in enumerate(inds):x^=right[j][k]
      code=tab.get(goal^x)
      if code is not None:
        li=[(code>>(3*j))&7 for j in range(7)];found.append(li+list(inds))
        if len(found)>=want:break
    if not found:raise RuntimeError('no collision with selected transforms; change option selection')
    for num,choice in enumerate(found):
      forged=bytearray(base)
      for ((ps,opts),k) in zip(groups,choice):
        t=opts[k];forged[ps[0]]+=t;forged[ps[1]]-=2*t;forged[ps[2]]+=t
      assert CRC32C.calc(forged[:n0])==CRC32C.calc(orig[:n0])
      assert zlib.adler32(forged)==zlib.adler32(orig)
      assert target.decode() in [x['id'] for x in json.loads(forged)['release']['to']]
      name=outfn if want==1 else f'{outfn}.{num:03d}'
      open(name,'wb').write(forged[:n0]);open(name+'.full','wb').write(forged)
    forged=bytearray(base)
    choice=found[0]
    for ((ps,opts),k) in zip(groups,choice):
      t=opts[k];forged[ps[0]]+=t;forged[ps[1]]-=2*t;forged[ps[2]]+=t
    print('found',len(found),'choices after',time.time()-started,'sec')
    print('wrote',outfn + ('' if want==1 else '.NNN'), '(and full files)')
    print('CRC32C',hex(CRC32C.calc(forged[:n0])),'Adler32',hex(zlib.adler32(forged)&0xffffffff))
    print(forged[:n0].decode())
if __name__=='__main__':main()
