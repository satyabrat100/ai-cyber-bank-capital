import json, sys, collections
import numpy as np, statsmodels.api as sm
base = sys.argv[1]
kev = json.load(open(base + '/kev/known_exploited_vulnerabilities.json'))['vulnerabilities']
lags = {r['cve']: r['lag'] for r in json.load(open(base + '/kev_lags.json'))}
months = [f'{y}-{m:02d}' for y in (2023, 2024, 2025, 2026) for m in range(1, 13)]
months = [m for m in months if m <= '2026-10']          # last full month
allc = collections.Counter(x['dateAdded'][:7] for x in kev)
fresh = collections.Counter(x['dateAdded'][:7] for x in kev
                            if x['cveID'] in lags and lags[x['cveID']] <= 30)
t = np.arange(len(months)); post = np.array([m >= '2026-05' for m in months], float)
X = sm.add_constant(np.column_stack([t, post]))
out = {}
for name, c in [('all', allc), ('fresh', fresh)]:
    y = np.array([c[m] for m in months])
    res = sm.GLM(y, X, family=sm.families.NegativeBinomial(alpha=0.1)).fit(cov_type='HC1')
    pre = y[post == 0].mean(); po = y[post == 1].mean()
    out[name] = dict(pre_mean=pre, post_mean=po, ratio=po/pre,
                     irr_post=float(np.exp(res.params[2])),
                     irr_ci=[float(np.exp(res.conf_int()[2][0])), float(np.exp(res.conf_int()[2][1]))],
                     p_post=float(res.pvalues[2]), trend_pct_per_year=float((np.exp(12*res.params[1])-1)*100),
                     p_trend=float(res.pvalues[1]), n_months=len(y))
    print(name, {k: (round(v, 3) if isinstance(v, float) else v) for k, v in out[name].items()})
# speed: logit P(lag<=30) on post dummy, for additions 2023-01..2026-11
rows = json.load(open(base + '/kev_lags.json'))
yy = np.array([r['lag'] <= 30 for r in rows], float)
pp = np.array([r['added'] >= '2026-05-01' for r in rows], float)
tt = np.array([(int(r['added'][:4]) - 2023) * 12 + int(r['added'][5:7]) for r in rows], float)
res = sm.Logit(yy, sm.add_constant(np.column_stack([tt, pp]))).fit(disp=0, cov_type='HC1')
out['speed'] = dict(share_pre=float(yy[pp == 0].mean()), share_post=float(yy[pp == 1].mean()),
                    odds_ratio_post=float(np.exp(res.params[2])), p_post=float(res.pvalues[2]),
                    n=len(yy), median_lag_pre=float(np.median([r['lag'] for r in rows if r['added'] < '2026-05-01'])),
                    median_lag_post=float(np.median([r['lag'] for r in rows if r['added'] >= '2026-05-01'])))
print('speed', out['speed'])
json.dump(out, open(base + '/kev_results.json', 'w'), indent=1)
json.dump({'months': months, 'all': [allc[m] for m in months], 'fresh': [fresh[m] for m in months]},
          open(base + '/kev_monthly.json', 'w'))
