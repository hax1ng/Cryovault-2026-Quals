#!/usr/bin/env python3
import solve
from meter_solve import MeterSolver,NOP

def fast_residue(s):
    poss=set(range(s.q))
    while len(poss)>1:
        best=None
        for pad in range(0,2*s.q+1):
            C=s.h+1+pad
            groups={}
            for r in poss: groups.setdefault((r+C)//s.q,0);groups[(r+C)//s.q]+=1
            score=max(groups.values())
            if best is None or score<best[0]:best=(score,pad,C)
        _,pad,C=best
        old=s.M
        z,m=s.raw([NOP]*pad+[0])
        if not z.startswith('SETTLED '):raise RuntimeError(z)
        d=m-old
        new=set()
        for r in poss:
            if (r+C)//s.q==d:new.add((r+C)%s.q)
        if not new:raise RuntimeError(f'residue recovery inconsistent poss={poss} C={C} d={d}')
        poss=new
    s.r=next(iter(poss))

def fill_then_restore(value, known_addrs, known_bytes, pad=0, range_words=None):
    p=solve.Program()
    p.emit(solve.ldi(1,(value<<8)|value))
    if range_words is None:
        start,count=0,16384
    else:start,count=range_words
    p.emit(solve.ldi(2,2*start));p.emit(solve.ldi(3,count))
    p.label('F');p.emit(solve.stw(1,2,0));p.emit(solve.alui(2,2,'ADD',2));p.emit_djnz(3,'F')
    for a,b in zip(known_addrs,known_bytes):p.emit(solve.ldi(1,b));p.emit(solve.stb(1,0,a))
    p.emit(solve.ldi(4,0x8000));p.emit(solve.seal(4))
    for _ in range(pad):p.emit(NOP)
    p.emit(0);return p.patch()

def byte_then_restore(addr,value,known_addrs,known_bytes,pad=0):
    w=[solve.ldi(1,value),solve.stb(1,0,addr)]
    for a,b in zip(known_addrs,known_bytes):w += [solve.ldi(1,b),solve.stb(1,0,a)]
    w += [solve.ldi(4,0x8000),solve.seal(4)]+[NOP]*pad+[0]
    return w

def locate_next(s,pk,addrs,prefix):
    k=len(prefix) # prior prefix count; locating P[k]
    lo,hi=0,16384
    while hi-lo>1:
        mid=(lo+hi)//2;count=mid-lo
        # Nonzero: put correct value in lower half; hit iff source is lower.
        # Zero: default RAM is correct, poison lower half; hit iff source is upper.
        val=pk if pk else 1
        retired=3*count+2*k+6
        hit=s.probe(lambda pad,lo=lo,count=count,val=val:
                    fill_then_restore(val,addrs,prefix,pad,(lo,count)),retired,k,
                    f'loc P{k} words [{lo:#x},{mid:#x})')
        if hit:fast_residue(s)
        in_lower=hit if pk else not hit
        if in_lower:hi=mid
        else:lo=mid
    even=2*lo
    val=pk if pk else 1
    retired=2+2*k+3
    hit=s.probe(lambda pad:byte_then_restore(even,val,addrs,prefix,pad),retired,k,
                f'loc P{k} parity')
    if hit:fast_residue(s)
    is_even=hit if pk else not hit
    addr=even if is_even else even+1
    print(f'SRC[{k:02d}]={addr:#06x}',flush=True)
    return addr

def gate_candidate_plan(g,addrs,prefix):
    p=solve.Program();p.emit(solve.ldi(1,(g<<8)|g));p.emit(solve.ldi(2,0));p.emit(solve.ldi(3,16384));p.label('F');p.emit(solve.stw(1,2,0));p.emit(solve.alui(2,2,'ADD',2));p.emit_djnz(3,'F')
    for a,b in zip(addrs,prefix):p.emit(solve.ldi(1,b));p.emit(solve.stb(1,0,a))
    p.emit(solve.ldi(4,0x8000));p.emit(solve.seal(4))
    ci=p.emit(0);p.emit(solve.stw(15,0,0x8200));p.emit(0);priv=len(p.words);p.emit(solve.att(3,0,0));p.emit(0);p.words[ci]=solve.ldi(15,0x8000|priv)
    return p.patch()

def final_program(addrs,gate_profile,fold_profile,table=0x1000):
    profile=fold_profile
    # Get the already-patched privileged fold tail from the validated generator.
    orig=solve.thaw_program(0x8000,profile,profile_addr=table)
    priv_tail=orig[37:]
    p=solve.Program();g=gate_profile[31]
    p.emit(solve.ldi(1,(g<<8)|g));p.emit(solve.ldi(2,0));p.emit(solve.ldi(3,16384));p.label('F');p.emit(solve.stw(1,2,0));p.emit(solve.alui(2,2,'ADD',2));p.emit_djnz(3,'F')
    for a,b in zip(addrs,gate_profile[:31]):p.emit(solve.ldi(1,b));p.emit(solve.stb(1,0,a))
    p.emit(solve.ldi(4,0x8000));p.emit(solve.seal(4))
    # Materialize contiguous K only after SEAL so it cannot disturb the scatter source.
    for i in range(16):p.emit(solve.ldi(1,int.from_bytes(profile[2*i:2*i+2],'big')));p.emit(solve.stw(1,0,table+2*i))
    ci=p.emit(0);p.emit(solve.stw(15,0,0x8200));p.emit(0);priv=len(p.words)
    p.words[ci]=solve.ldi(15,0x8000|priv)
    p.words.extend(priv_tail)
    out=p.patch()
    print('final words',len(out),'priv',priv,flush=True)
    return out

def main():
 while True:
  try:
   s=MeterSolver();s.calibrate();p0=s.recover_first()
   if p0:break
  except Exception as e:print('SESSION RETRY',repr(e),flush=True)
 A=s.locate_source(p0)
 prefix=bytearray([p0]);addrs=[A]
 print('START',prefix.hex(),[hex(x) for x in addrs],'plans',s.plans,flush=True)
 for k in range(1,31):
  found=None
  for g in range(256):
   retired=49158+2*k
   hit=s.probe(lambda pad,g=g:fill_then_restore(g,addrs,prefix,pad),retired,k,f'P{k}={g:02x}')
   if hit:
    found=g;prefix.append(g);print(f'P[{k:02d}]={g:02x} prefix={prefix.hex()} plans={s.plans}',flush=True);fast_residue(s);break
  if found is None:raise RuntimeError(f'no candidate for P{k}')
  # locate with prior prefix only (exclude newly found byte/address)
  addr=locate_next(s,found,addrs,bytes(prefix[:-1]));addrs.append(addr)
  print('ADDRS',' '.join(f'{x:04x}' for x in addrs),'plans',s.plans,flush=True)
 # Last comparison has no timing distinction; all-RAM fill + restored first 31 gives gate oracle.
 print('BRUTE FINAL BYTE',flush=True)
 for g in range(256):
  z,m=s.raw(gate_candidate_plan(g,addrs,bytes(prefix)))
  if z.startswith('SETTLED '):
   prefix.append(g);print(f'P[31]={g:02x} PROFILE={prefix.hex()} plans={s.plans}',flush=True);break
  if not z.startswith('FAULT '):print('weird final',g,z,flush=True)
 else:raise RuntimeError('no final byte gated')
 # Find the last shuffled source address using the now-known final byte and the gate.
 p31=prefix[31]
 def gate_range(val,start,count):
  p=solve.Program();p.emit(solve.ldi(1,(val<<8)|val));p.emit(solve.ldi(2,2*start));p.emit(solve.ldi(3,count));p.label('F');p.emit(solve.stw(1,2,0));p.emit(solve.alui(2,2,'ADD',2));p.emit_djnz(3,'F')
  for a,b in zip(addrs,prefix[:31]):p.emit(solve.ldi(1,b));p.emit(solve.stb(1,0,a))
  p.emit(solve.ldi(4,0x8000));p.emit(solve.seal(4));ci=p.emit(0);p.emit(solve.stw(15,0,0x8200));p.emit(0);pr=len(p.words);p.emit(solve.att(3,0,0));p.emit(0);p.words[ci]=solve.ldi(15,0x8000|pr);return p.patch()
 def gate_byte(addr,val):
  w=[solve.ldi(1,val),solve.stb(1,0,addr)]
  for a,b in zip(addrs,prefix[:31]):w += [solve.ldi(1,b),solve.stb(1,0,a)]
  w += [solve.ldi(4,0x8000),solve.seal(4)];ci=len(w);w += [solve.ldi(15,0),solve.stw(15,0,0x8200),0];pr=len(w);w += [solve.att(3,0,0),0];w[ci]=solve.ldi(15,0x8000|pr);return w
 lo,hi=0,16384
 while hi-lo>1:
  mid=(lo+hi)//2
  z,m=s.raw(gate_range(p31 if p31 else 1,lo,mid-lo));opened=z.startswith('SETTLED ')
  in_lower=opened if p31 else not opened
  if in_lower:hi=mid
  else:lo=mid
 even=2*lo
 z,m=s.raw(gate_byte(even,p31 if p31 else 1));opened=z.startswith('SETTLED ')
 is_even=opened if p31 else not opened
 last_addr=even if is_even else even+1
 all_addrs=addrs+[last_addr]
 pairs=sorted(zip(all_addrs,prefix))
 if len(set(all_addrs))!=32 or pairs[-1][0]-pairs[0][0]!=31:
  raise RuntimeError(f'source permutation is not a 32-byte block: {all_addrs}')
 fold_profile=bytes(v for a,v in pairs)
 print(f'SRC[31]={last_addr:#06x} FOLD_PROFILE={fold_profile.hex()}',flush=True)
 z,m=s.raw(final_program(addrs,bytes(prefix),fold_profile))
 print('FINAL',z,flush=True)
 if not z.startswith('THAWED '):raise RuntimeError('did not thaw')

if __name__=='__main__':main()
