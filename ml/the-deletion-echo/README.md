# The Deletion Echo

**Category:** ml · **Points:** 50 · **Solves:** 116 · **Flag:** `isfcr{763c8479fac095a9e471ad3d}`

## Challenge

> **The Deletion Echo**
> A regression service says a deletion request was fulfilled by exact retraining. Recover the deleted records and their private labels.
>
> Submit one `record-id:label` string per deleted record, sorted as ASCII strings, as a JSON list. Then run:
> ```bash
> python3 unlock.py '["record-...:0", "record-...:3", ...]'
> ```
>
> Flag format: `isfcr{}`

Author: `d3va`. We are given a single `data.json` and an `unlock.py` that decrypts the flag once we hand it the correct answer list.

This is a *machine unlearning* challenge. A service deleted some records "by exact retraining." Our task is to prove that the deletion still leaks: recover **which** candidate records were deleted and **what private label** (`0`–`3`) each one carried.

## Initial Analysis

`data.json` describes a ridge-regression service. The relevant pieces:

- **5 unordered model snapshots** — we are never told their chronological order.
- **240 queries per snapshot** — each query gives a raw record, a returned **prediction mean**, and a returned **predictive variance**.
- **140 candidate records** that might have been deleted.
- **3 known ingest batches** of 12, 10, and 9 records (records + raw features, labels hidden).
- A **12-dimensional feature transform** and labels restricted to `{0,1,2,3}`.

Raw records become feature vectors via a fixed permutation, centering, and scaling:

```text
x[j] = (raw[permutation[j]] - center[j]) / scale[j]
```

The model is ridge regression with no intercept:

```text
H     = sum(x x^T) + ridge * I
theta = H^-1 sum(x y)
```

and for a query `q` the API returns approximately:

```text
mean     = q^T theta
variance = sigma2 * (1 + q^T H^-1 q)
```

There is Gaussian response noise, but only at the `~1e-9` level — negligible against 240 equations per snapshot. **The mean leaks `theta`; the variance leaks `H^-1`.** That combination is the whole ballgame.

## Vulnerability / Core Concept

The core weakness is that **predictive variance exposes a quadratic form in the inverse training matrix**. Each training record contributes an outer product `x x^T` to `H`, so `H` is effectively a fingerprint of the training set. Differencing two snapshots cancels everything shared and leaves only the records that were **added or removed** between them:

```text
H_after - H_before = sum(added x x^T) - sum(deleted x x^T) + delta_ridge * I
```

That residual is the "deletion echo": even after the records are gone, their combined geometric footprint survives in the gap between the before/after models. Because the deleted records must come from a known 140-record candidate list, recovering the exact deletion set becomes a **binary linear-algebra problem**, not guesswork. The same trick on the un-ridged vector `b = H·theta = sum(x y)` then recovers labels.

## Exploitation

The full record-recovery pipeline is in [`solve_mip.py`](solve_mip.py). It runs in five steps.

### Step 1 — Rebuild each snapshot's `theta`

The mean is linear in `q`, so stack all 240 query vectors into `Q` with their means and least-squares solve:

```python
theta = np.linalg.lstsq(Q, means, rcond=None)[0]
```

12 unknowns vs. 240 observations — the `1e-9` noise averages out; residuals land around `2e-9`.

### Step 2 — Recover `H` from the variance leak

The variance is quadratic: `v(q) = sigma2 + q^T C q` with `C = sigma2 * H^-1`. A symmetric 12×12 matrix has 78 free entries; plus `sigma2` that's 79 unknowns against 240 observations — another linear least-squares fit. Build one column per `q[i]^2` and one per `2·q[i]·q[j]` (`i<j`):

```python
Phi = np.column_stack([(X[:,i]*X[:,j]*(2 if i!=j else 1)) for i,j in pairs])
co  = np.linalg.lstsq(Phi/v[:,None], (v - sigma2)/v, rcond=None)[0]
```

The recovered `sigma2` values snapped cleanly onto dyadic fractions, which let us pin them exactly before refitting:

| Snapshot | Recovered `sigma2` |
|---|---:|
| `snapshot-9ccbadef83c2` | `35/16` |
| `snapshot-2ee90f53b5c2` | `31/16` |
| `snapshot-d1f54facd170` | `55/32` |
| `snapshot-e385b6f3720a` | `75/64` |
| `snapshot-80794d4ee21c` | `153/64` |

Then reconstruct `H = sigma2 * inv(C)` (relative fit error ~`1.5e-9`).

### Step 3 — Order the unordered snapshots

Each ingest batch has a known Gram contribution `G = X^T X`. Matching those against every pairwise snapshot difference recovers the history:

```text
snapshot-2ee9 --(add 12-record batch)--> snapshot-d1f5 / snapshot-8079
                --(add 10-record batch + DELETION)--> snapshot-e385
                --(add 9-record batch)--> snapshot-9ccb
```

(`d1f5` and `8079` share the same training data — they differ only by a ridge/redeploy diagonal, so averaging their ridge-invariant parts reduces noise.) The transition that contains the deletion is `d1f5/8079 → e385`.

### Step 4 — Find the deleted records (the MIP)

For the mixed release, with `G10` the Gram of the 10-record ingest batch:

```text
G_deleted = G10 - (H_after - H_before) + delta_ridge * I
```

The unknown ridge change only touches the diagonal, so project it away: keep all 66 off-diagonal entries plus 11 diagonal **contrasts** `M[i,i] - M[11,11]` — 77 ridge-independent measurements. Then solve for binary `z_i` over the 140 candidates:

```text
sum(z_i · P(x_i x_i^T)) = P(G_deleted),   z_i in {0,1}
```

`scipy.optimize.milp` with slack variables absorbs the residual float noise. The correct subset had a max matrix residual of ~`0.53` — negligible against entries in the tens of thousands — and selected **26 records**.

### Step 5 — Recover the private labels

Use the un-ridged vector `b = H·theta = sum(x y)` (no ridge term, so no diagonal nuisance):

```text
b_before - b_after = sum(deleted_x · deleted_label) - sum(ingest_x · ingest_label)
```

The 10 ingest labels are also unknown, giving 36 label variables total (26 deleted + 10 ingest), each in `{0,1,2,3}`. Multiplying each row by its published `scale` turns the system into exact integers `A·y = t`. Rather than a generic solver, substitute `u = 2y - 3` (so `u[i] ∈ {-3,-1,1,3}`) and build a lattice whose shortest vector is exactly the solution — the big `N`-scaled coordinates cancel when the labels are right:

```python
u_target = 2*t - 3*A*vector(ZZ, [1]*n)
rows = [ vector(ZZ, [1 if j==i else 0 for j in range(n)] + [0] + [N*A[j,i] for j in range(A.nrows())]) for i in range(n) ]
rows.append(vector(ZZ, [0]*n + [1] + list(N*u_target)))
reduced = matrix(ZZ, rows).LLL(delta=0.999)
```

LLL finds `[u | -1 | 0...0]` immediately:

```text
Deleted labels: [2,1,2,0,2,1,2,0,1,3,3,0,0,2,1,0,1,1,1,2,3,0,2,2,0,1]
Ingest labels:  [2,0,1,3,0,2,2,2,2,2]
```

### Assemble and unlock

Pair the 26 labels with their record IDs, sort the `record-id:label` strings as ASCII, and feed to `unlock.py`:

```bash
python3 unlock.py '["record-0730706150:0","record-28c0bbf813:2","record-2e6662ecc6:3","record-3de105d25d:3","record-3ee76f33c8:2","record-46126dd779:0","record-473e486afd:0","record-49aa7c51a4:2","record-507645d5d9:2","record-58fad90382:2","record-5bc7d8554c:1","record-66f65f5026:0","record-71fb3e266c:2","record-7796490f27:1","record-77a4509144:1","record-8f4b4073f9:1","record-90769aad7a:1","record-978b124800:1","record-9cddf7a4fb:0","record-9cfdc74744:3","record-b9e67b6811:2","record-cf44aec78a:2","record-cf4fee237a:0","record-d32fd7d5d5:1","record-ebfb2ad09e:0","record-ee9e7ec4d8:1"]'
# -> isfcr{763c8479fac095a9e471ad3d}
```

`unlock.py` derives an scrypt key from the exact JSON of the answer list and AES-GCM-decrypts the sealed flag — so the answer must be byte-perfect.

## Flag

```
isfcr{763c8479fac095a9e471ad3d}
```

## Key Takeaways

- **Predictive variance is a model leak.** `variance = sigma2·(1 + q^T H^-1 q)` is a quadratic form in `H^-1`; enough queries reconstruct it exactly, and `H` is the training set's fingerprint.
- **"Deletion by retraining" doesn't erase the echo.** Differencing before/after model matrices (`H` and the un-ridged `b = H·theta`) exposes the aggregate outer products of inserted and deleted records — the heart of machine-unlearning membership attacks.
- **Snap noisy reconstructions to exact structure.** Recovered `sigma2` values were dyadic fractions and the scaled label system was integer — pinning those turned a noisy fit into an exact algebra problem.
- **Lattice tricks beat generic solvers for small bounded-integer systems.** The `u = 2y-3` embedding makes the correct label assignment the unique shortest vector, solved instantly by LLL.

## Files

- [`solve_mip.py`](solve_mip.py) — Steps 1–4: reconstruct `theta`/`H` per snapshot, order snapshots, and recover the deleted record set via MILP.
- [`unlock.py`](unlock.py) — challenge-provided flag unsealer (scrypt + AES-GCM over the answer JSON).
- [`data.json`](data.json) — challenge data: contract, 5 snapshots, 1200 queries, 140 candidates, 3 ingest batches.
