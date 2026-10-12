from pypdf import PdfReader
import re, math, json, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def diffmap(F):
 d=F['/Encoding']['/Differences']; out={}; c=None
 for v in d:
  if isinstance(v,int): c=v
  else: out[c]=str(v); c+=1
 return out

def glyph_cells(data, unit):
 toks=re.findall(r'[-+]?(?:\d*\.\d+|\d+)|[A-Za-z*]+', data.decode('latin1'))
 stack=[]; matrix=(1,0,0,1,0,0); path=[]; painted=set()
 def num(x): return float(x)
 for t in toks:
  if re.fullmatch(r'[-+]?(?:\d*\.\d+|\d+)',t): stack.append(num(t)); continue
  if t=='cm':
   matrix=tuple(stack[-6:]); stack=[]
  elif t=='re':
   path.append(tuple(stack[-4:])); stack=[]
  elif t in ('f','f*'):
   # Enumerate unit-cell centers in bounding range and calculate nonzero/evenodd fill.
   if path:
    xmin=min(min(x,x+w) for x,y,w,h in path); xmax=max(max(x,x+w) for x,y,w,h in path)
    ymin=min(min(y,y+h) for x,y,w,h in path); ymax=max(max(y,y+h) for x,y,w,h in path)
    for ix in range(math.floor(xmin/unit)-2,math.ceil(xmax/unit)+2):
     for iy in range(math.floor(ymin/unit)-2,math.ceil(ymax/unit)+2):
      px=(ix+.5)*unit; py=(iy+.5)*unit
      inside=[]
      for x,y,w,h in path:
       if min(x,x+w)<px<max(x,x+w) and min(y,y+h)<py<max(y,y+h):
        inside.append(1 if w*h>0 else -1)
      fill=(len(inside)%2==1) if t=='f*' else (sum(inside)!=0)
      if fill:
       a,b,c,d,e,f=matrix
       X=(a*px+c*py+e)/unit; Y=(b*px+d*py+f)/unit
       painted.add((round(X,5),round(Y,5)))
   path=[];stack=[]
  else:
   stack=[]
 # normalize: coordinates differ by offsets incl .25, so min zero
 minx=min(x for x,y in painted); miny=min(y for x,y in painted)
 return frozenset((round(x-minx,5),round(y-miny,5)) for x,y in painted)

def rotations(cells):
 res=[]; cur=cells
 for _ in range(4):
  minx=min(x for x,y in cur);miny=min(y for x,y in cur)
  cur=frozenset((round(x-minx,5),round(y-miny,5)) for x,y in cur)
  res.append(cur)
  cur=frozenset((-y,x) for x,y in cur)
 return res

def fp(cells):
 return min(tuple(sorted(x)) for x in rotations(cells))

# Reference symbols left-to-right map to stated digits.
r=PdfReader('reference.pdf'); p=r.pages[0]; R=p['/Resources']['/Font']['/R0'].get_object(); dm=diffmap(R)
content=p['/Contents'].get_object().get_data()
codes=[int(x,16) for x in re.findall(rb'<([0-9a-fA-F]{2})>\s*Tj',content)]
digits='8bd4e257f916c30a'
ref={}
print('REFERENCE')
for code,digit in zip(codes,digits):
 name=dm[code]; data=R['/CharProcs'][name].get_object().get_data(); c=glyph_cells(data,25)
 F=fp(c); print(hex(code),name,digit,len(c),sorted(c));
 if F in ref: print('DUP SHAPE',digit,ref[F])
 ref[F]=digit

# Target repaired chain.
r=PdfReader('repaired.pdf'); p=r.pages[0]; form=p['/Resources']['/XObject']['/X0'].get_object(); fonts=form['/Resources']['/Font']
print('\nTARGET MAP')
code_digit={}
for fontname,fref in fonts.items():
 F=fref.get_object(); dm=diffmap(F); unit=100 if fontname=='/F0' else 1
 for code,name in dm.items():
  if name=='/.notdef' or name not in F['/CharProcs']: continue
  c=glyph_cells(F['/CharProcs'][name].get_object().get_data(),unit); sig=fp(c)
  digit=ref.get(sig)
  # closest if no exact
  print(fontname,hex(code),name,'cells',len(c),'->',digit)
  if digit is None:
   for rfp,d in ref.items():
    if len(rfp)==len(sig):
     print('  same len',d,'diff',len(set(rfp)^set(sig)))
  code_digit[(fontname,code)]=digit

# parse the grid's form content in text-state order; each Tm gives baseline
s=form.get_data().decode('latin1')
font=None; entries=[]
pat=re.compile(r'/(F[01])\s+[\d.]+\s+Tf|1\s+0\s+0\s+1\s+(-?[\d.]+)\s+(-?[\d.]+)\s+Tm\s+<([0-9a-fA-F]{2})>\s+Tj')
for m in pat.finditer(s):
 if m.group(1): font='/'+m.group(1)
 else:
  x,y,hh=float(m.group(2)),float(m.group(3)),int(m.group(4),16)
  entries.append((x,y,font,hh,code_digit[(font,hh)]))
print('entries',len(entries),'unknowns',sum(e[-1] is None for e in entries))
entries.sort(key=lambda e:(-e[1],e[0]))
grid=''.join(e[-1] or '?' for e in entries)
print('GRID',grid)
for i in range(0,256,16): print(grid[i:i+16])

caseid='9697624543591457a15dc6d9a4797c45'
evidence=[caseid,grid]
E=json.dumps(evidence,ensure_ascii=True,separators=(',',':')).encode('ascii')
key=hashlib.scrypt(b'isfcr-forensics\x00'+E,salt=bytes.fromhex('8a251a8101ffa67ed383a445a05e77f2'),n=131072,r=8,p=1,maxmem=2**28,dklen=32)
ct=bytes.fromhex('27b4469da3cc30f3ec487d60be3053aa2d5aa00c9f4da69fe54e7d51da8463883b4aa1b0a10a69c45c4e974171133f')
flag=AESGCM(key).decrypt(bytes.fromhex('cf5d90d20b821db4c5bf1b73'),ct,b'the-alphabet-that-wasnt-there')
print('FLAG',flag.decode())
