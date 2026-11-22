"""Severity-parameter uncertainty (review v7.1, issue 3).
Bootstrap the 61 VCDB financial-sector losses B = 200 times, re-fit the lognormal (ML, location 0) each time,
and recompute baseline and shocked aggregate VaR and the capital gap at 99, 99.5 and 99.9% (M = 1.56; frequency
only and with severity effects). Each bootstrap uses the same 500,000 simulated years (common random numbers), so the
spread across bootstraps is parameter uncertainty; Monte Carlo error is reported separately (Table 12b; Table 7).
Checkpointed to results/sev_bootstrap_ckpt.jsonl so an interrupted run resumes."""
import json, os, sys, numpy as np
from scipy import stats
sys.path.insert(0, 'scripts'); from vcdb_io import records
import core_sim as cs
fin = np.array([r['amount'] for r in records('data') if r['amount'] and 0 < r['amount'] < 1e10 and r['industry'].startswith('52')]) / 1e6
assert len(fin) == 61
B, NY = 200, 500_000
dr = cs.Draws(n=NY, kmax=24, seed=cs.SEED)
a = 1.56 ** 2 - 1; Q = (0.99, 0.995, 0.999)
SPEC = {'freq_only': dict(eta=0.0, zeta=0.0), 'freq_sev': dict(eta=0.3, zeta=0.0)}
CK = 'results/sev_bootstrap_ckpt.jsonl'; done = set()
if os.path.exists(CK): done = {json.loads(l)['b'] for l in open(CK)}
rng = np.random.default_rng(20261122)
fits = []
for b in range(B + 1):
    x = fin if b == 0 else rng.choice(fin, len(fin))
    s, loc, sc = stats.lognorm.fit(x, floc=0); fits.append((float(s), float(sc)))
for b, (s, sc) in enumerate(fits):
    if b in done: continue
    cs.FIT['lognormal'] = dict(sigma=s, scale=sc)
    row = dict(b=b, sigma=s, scale=sc)
    for sp, kw in SPEC.items():
        p = dict(cs.BASE); p.update(kw)
        r = cs.run(dr, p, a, qs=Q)
        row[sp] = {str(q): dict(var0=r[q]['var0'], var1=r[q]['var1'], gap=r[q]['gap'], orc_up=r[q]['orc_up']) for q in Q}
    with open(CK, 'a') as fh: fh.write(json.dumps(row) + '\n')
    if b % 20 == 0: print(b, round(s, 3), round(row['freq_only']['0.999']['gap'] * 100, 1), flush=True)
rows = sorted((json.loads(l) for l in open(CK)), key=lambda r: r['b'])
out = {'n_losses': 61, 'B': B, 'years': NY, 'point': rows[0], 'sigma_ci': list(np.percentile([r['sigma'] for r in rows[1:]], [2.5, 97.5]))}
for sp in SPEC:
    for q in map(str, Q):
        for k in ('var0', 'var1', 'gap'):
            v = np.array([r[sp][q][k] for r in rows[1:]])
            out[f'{sp}|{q}|{k}'] = dict(median=float(np.median(v)), ci=[float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))])
json.dump(out, open('results/sev_bootstrap.json', 'w'), indent=1)
print(json.dumps({k: v for k, v in out.items() if 'gap' in k}, indent=1))
