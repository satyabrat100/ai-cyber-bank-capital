"""Section 8.5: placebo and alternative break dates, PoC-in-GitHub 30-day count, from data/monthly_panel.csv."""
import csv, json, numpy as np, statsmodels.api as sm, warnings
from statsmodels.discrete.discrete_model import NegativeBinomial
warnings.filterwarnings('ignore')
rows = [x for x in csv.DictReader(open('data/monthly_panel.csv')) if x['month'] <= '2026-09']
def irr(sample, brk, col='poc_30d', quad=False):
    y = np.array([float(x[col]) for x in sample]); t = np.arange(len(sample), dtype=float)
    d = np.array([x['month'] >= brk for x in sample], float)
    X = sm.add_constant(np.column_stack([t, t ** 2, d] if quad else [t, d]))
    r = NegativeBinomial(y, X, loglike_method='nb2').fit(disp=0, maxiter=500, cov_type='HC1')
    j = 3 if quad else 2
    return float(np.exp(r.params[j])), [float(np.exp(v)) for v in r.conf_int()[j]]
pre = [x for x in rows if x['month'] < '2026-05']
plac = {m: irr(pre, m) for m in [f'{y}-{k:02d}' for y in (2024, 2025) for k in range(1, 13)]}
alt = {m: irr(rows, m) for m in ['2026-02', '2026-03', '2026-04', '2026-05', '2026-06']}
out = dict(placebo=plac, alt=alt, quad=irr(rows, '2026-05', quad=True))
v = [a for a, _ in plac.values()]
print('placebo range', round(min(v), 2), round(max(v), 2), 'n sig>1', sum(c[0] > 1 for _, c in plac.values()))
print('alt', {k: round(a, 2) for k, (a, _) in alt.items()}, 'quad', round(out['quad'][0], 2), [round(z, 2) for z in out['quad'][1]])
for m, (a, c) in plac.items():
    if c[0] > 1: print('  sig placebo', m, round(a, 2), [round(z, 2) for z in c])
json.dump(out, open('results/placebo_panel.json', 'w'), indent=1)
