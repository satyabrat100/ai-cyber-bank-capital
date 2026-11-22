"""Loss-tail estimation: alternative distributions, bootstrap CIs, all-sector comparison (VCDB)."""
import json, glob, sys
import numpy as np
from scipy import stats
base = sys.argv[1]
fin, allx = [], []
import os; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); from vcdb_io import records
for o in records(base):
    a = o['amount']
    if not isinstance(a, (int, float)) or a <= 0 or a >= 1e10: continue  # one US$1 trillion record is a coding error
    allx.append(a)
    if o['industry'].startswith('52'): fin.append(a)
fin, allx = np.array(fin, float), np.array(allx, float)
rng = np.random.default_rng(11)
def hill(x, k):
    x = np.sort(x)[::-1]; return 1 / np.mean(np.log(x[:k] / x[k]))
out = {'n_fin': len(fin), 'n_all': len(allx)}
for lab, x in [('fin', fin), ('all', allx)]:
    lx = np.log(x)
    bs = [np.log(rng.choice(x, len(x))).std(ddof=1) for _ in range(2000)]
    k10 = max(5, len(x) // 10); k20 = max(5, len(x) // 5)
    bh = [hill(rng.choice(x, len(x)), k20) for _ in range(2000)]
    out[lab] = dict(log_sd=float(lx.std(ddof=1)), log_sd_ci=[float(np.percentile(bs, 2.5)), float(np.percentile(bs, 97.5))],
                    hill10=float(hill(x, k10)), hill20=float(hill(x, k20)),
                    hill20_ci=[float(np.percentile(bh, 2.5)), float(np.percentile(bh, 97.5))],
                    shapiro_log_p=float(stats.shapiro(lx).pvalue))
    # Alternative distributions on log-scaled data (fit on x/1e6 for stability)
    y = x / 1e6; fits = {}
    for name, dist, kw in [('lognormal', stats.lognorm, dict(floc=0)), ('weibull', stats.weibull_min, dict(floc=0)),
                           ('loglogistic', stats.fisk, dict(floc=0)), ('gamma', stats.gamma, dict(floc=0))]:
        p = dist.fit(y, **kw); ll = np.sum(dist.logpdf(y, *p)); k = len(p) - 1
        ks = stats.kstest(y, dist.cdf, args=p).pvalue
        fits[name] = dict(params=[float(v) for v in p], loglik=float(ll), aic=float(2 * k - 2 * ll), ks_p=float(ks))
    # GPD on exceedances above the 75th percentile
    u = np.quantile(y, 0.75); ex = y[y > u] - u
    p = stats.genpareto.fit(ex, floc=0)
    fits['gpd_tail_above_p75'] = dict(xi=float(p[0]), scale=float(p[2]), n_exceed=int(len(ex)), threshold_musd=float(u))
    out[lab]['fits'] = fits
json.dump(out, open(base + '/tail_results.json', 'w'), indent=1)
print(json.dumps(out, indent=1))
