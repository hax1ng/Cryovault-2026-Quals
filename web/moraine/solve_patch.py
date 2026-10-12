#!/usr/bin/env python3
import z3,zlib
class Crc32C:
    tab=[]
    for i in range(256):
        c=i
        for _ in range(8): c=(c>>1)^0x82F63B78 if c&1 else c>>1
        tab.append(c)
    @classmethod
    def calc(cls,data):
        c=0xffffffff
        for b in data: c=cls.tab[(c^b)&255]^(c>>8)
        return c^0xffffffff
orig=bytearray(open('policy.bin','rb').read())
N=len(orig); n0=225
target_id=b'op-wwkeyq'
assert len(target_id)==9
base=bytearray(orig)
pos=orig.find(b'kp-pthyvv',150,225);assert pos==211
base[pos:pos+9]=target_id
# Identify mutable bytes within non-security-critical string values
ranges=[]
for key in [b'"vault": "',b'"issued_by": "',b'"issued": "']:
 s=orig.find(key)+len(key); e=orig.find(b'"',s);ranges.append((s,e))
varpos=[p for s,e in ranges for p in range(s,e)]
print('ranges',ranges,'vars',len(varpos),'fixed id',pos)
crc_base=Crc32C.calc(base[:n0]); crc_target=Crc32C.calc(orig[:n0]); need=crc_base^crc_target
print('crc base/target/need',hex(crc_base),hex(crc_target),hex(need))
xs={p:z3.BitVec(f'x{p}',8) for p in varpos}
s=z3.Solver()
# Conservative JSON-safe printable ASCII. Keep slash/dashes etc allowed; any printable except quote and backslash.
for p,x in xs.items():
 s.add(z3.UGE(x,0x20),z3.ULE(x,0x7e),x!=ord('"'),x!=ord('\\'))
# Ensure some minimally plausible schema string syntax/values aren't blank (covered by printable)
# CRC difference is XOR-linear over flipped input bits.
effects={}
for p in varpos:
 for bit in range(8):
  t=bytearray(base[:n0]);t[p]^=1<<bit
  effects[p,bit]=Crc32C.calc(t)^crc_base
terms=[]
for p,x in xs.items():
 for bit in range(8):
  oldbit=(base[p]>>bit)&1
  flip=(z3.Extract(bit,bit,x) != z3.BitVecVal(oldbit,1))
  terms.append(z3.If(flip,z3.BitVecVal(effects[p,bit],32),z3.BitVecVal(0,32)))
expr=terms[0]
for t in terms[1:]:expr=expr^t
s.add(expr==z3.BitVecVal(need,32))
# Adler-32 invariants over whole file. A delta sum; B weighted delta sum.
# Include all fixed baseline changes and symbolic mutable positions.
dA=0;dB=0
varset=set(varpos)
for p in range(N):
 if p in varset:
  delta=z3.BV2Int(xs[p])-orig[p]
 else:
  delta=base[p]-orig[p]
 dA+=delta;dB+=(N-p)*delta
s.add(dA % 65521 == 0,dB % 65521 == 0)
print('checking')
print(s.check())
m=s.model();out=bytearray(base)
for p,x in xs.items():out[p]=m[x].as_long()
open('forged0.bin','wb').write(out[:n0]);open('forged_policy.bin','wb').write(out)
print('orig crc',hex(Crc32C.calc(orig[:n0])),'new',hex(Crc32C.calc(out[:n0])))
print('orig adler',hex(zlib.adler32(orig)&0xffffffff),'new',hex(zlib.adler32(out)&0xffffffff))
print(out[:n0].decode())
import json
print('release ids',[x['id'] for x in json.loads(out)['release']['to']])
