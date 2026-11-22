import json, sys
import numpy as np, statsmodels.api as sm
base = sys.argv[1]
m = json.load(open(base + '/poc_results.json'))['monthly_fast30']
months = list(m); y = np.array(list(m.values())); t = np.arange(len(y))
def fit(yy, tt, pp, robust=True):
    r = sm.GLM(yy, sm.add_constant(np.column_stack([tt, pp])), family=sm.families.NegativeBinomial(alpha=0.1)).fit(cov_type='HC1' if robust else 'nonrobust')
    return float(np.exp(r.params[2])), float(r.pvalues[2])
out = {}
pre_n = months.index('2026-04') + 1
out['placebo'] = [fit(y[:pre_n], t[:pre_n], (t[:pre_n] >= b).astype(float))[0] for b in range(12, pre_n - 4)]
out['alt'] = {lab: fit(y, t, np.array([x >= lab for x in months], float)) for lab in ['2026-03', '2026-04', '2026-05', '2026-06']}
# quadratic trend
r = sm.GLM(y, sm.add_constant(np.column_stack([t, t ** 2, np.array([x >= '2026-05' for x in months], float)])), family=sm.families.NegativeBinomial(alpha=0.1)).fit(cov_type='HC1')
out['quad_trend'] = [float(np.exp(r.params[3])), float(r.pvalues[3])]
print({'placebo_min': min(out['placebo']), 'placebo_max': max(out['placebo']), 'n_placebo': len(out['placebo'])}, out['alt'], out['quad_trend'])
json.dump(out, open(base + '/poc_robust.json', 'w'), indent=1)
