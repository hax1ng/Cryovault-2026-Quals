import json,numpy as np
from collections import defaultdict
from scipy.optimize import milp, Bounds, LinearConstraint
D=json.load(open('data.json')); c=D['contract']; d=c['dimension']; p=c['permutation']; center=np.array(c['center']); scale=np.array(c['scale'])
def feat(raw): return (np.array(raw,dtype=float)[p]-center)/scale
by=defaultdict(list)
for z in D['queries']:by[z['snapshot_id']].append(z)
pairs=[(i,j) for i in range(d) for j in range(i,d)]
# known exact sigma squared inferred dyadic values
sigs={'snapshot-9ccbadef83c2':35/16,'snapshot-2ee90f53b5c2':31/16,
'snapshot-d1f54facd170':55/32,'snapshot-e385b6f3720a':75/64,'snapshot-80794d4ee21c':153/64}
Hs={};ths={};bs={}
for sid,zs in by.items():
 X=np.array([feat(z['raw']) for z in zs]); y=np.array([float(z['mean']) for z in zs]); v=np.array([float(z['predictive_variance']) for z in zs])
 th=np.linalg.lstsq(X,y,rcond=None)[0]
 # quadratic terms direct, solve C in v-sigma=q'Cq. Scale cols
 Phi=np.column_stack([(X[:,i]*X[:,j]*(2 if i!=j else 1)) for i,j in pairs])
 cs=np.sqrt(np.mean(Phi*Phi,axis=0)); P=Phi/cs
 # weighted by v because multiplicative noise
 co=np.linalg.lstsq(P/v[:,None],(v-sigs[sid])/v,rcond=None)[0]/cs
 C=np.zeros((d,d))
 for a,(i,j) in zip(co,pairs):C[i,j]=C[j,i]=a
 H=sigs[sid]*np.linalg.inv(C)
 Hs[sid]=H; ths[sid]=th;bs[sid]=H@th
 print(sid,'H round max',np.max(abs(H-np.round(H*16)/16)))
# deletion was 9 ->2, ingest10
s9='snapshot-9ccbadef83c2';s2='snapshot-2ee90f53b5c2'
b10=next(b for b in D['ingest'] if len(b['records'])==10)
G10=sum((lambda x:np.outer(x,x))(feat(r['raw'])) for r in b10['records'])
T=G10-(Hs[s2]-Hs[s9])
# invariant vector: offdiagonals + diagonal contrasts cancel unknown ridge
idx=[(i,j) for i in range(d) for j in range(i+1,d)]
def vec(G):return np.array([G[i,j] for i,j in idx]+[G[i,i]-G[-1,-1] for i in range(d-1)])
t=vec(T)
A=np.column_stack([vec(np.outer(feat(r['raw']),feat(r['raw']))) for r in D['candidates']])
# Normalize rows to around unity; true measurement uncertainty roughly constant absolute H units, so uniform 1e5 global is appropriate
norm=1e5
As=A/norm; ts=t/norm
n=A.shape[1];m=A.shape[0]
# x binary plus absolute error z>=0; minimize L1 errors + truly negligible record count tiebreak
obj=np.r_[np.full(n,1e-10),np.ones(m)]
# -z <= A x-t <= z
M=np.block([[As,-np.eye(m)],[-As,-np.eye(m)]])
ub=np.r_[ts,-ts]
print('MIP',m,n)
res=milp(obj,integrality=np.r_[np.ones(n),np.zeros(m)],bounds=Bounds(np.zeros(n+m),np.r_[np.ones(n),np.full(m,np.inf)]),constraints=LinearConstraint(M,-np.inf,ub),options={'time_limit':300,'mip_rel_gap':0})
print(res.message,res.fun,res.mip_gap)
x=np.rint(res.x[:n]).astype(int)
print('chosen count',x.sum())
for yes,r in zip(x,D['candidates']):
 if yes:print(r['id'])
err=A@x-t
print('resid l1 max rms',sum(abs(err)),max(abs(err)),np.sqrt(np.mean(err**2)))
np.savez('mip_out.npz',x=x,H9=Hs[s9],H2=Hs[s2],th9=ths[s9],th2=ths[s2],b9=bs[s9],b2=bs[s2],T=T,A=A,t=t,err=err)
