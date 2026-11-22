"""Full negative-binomial (NB2) output with estimated dispersion (item 6). Optional offset = log(CVEs published)."""
import json, sys, collections, os
import numpy as np, statsmodels.api as sm
from statsmodels.discrete.discrete_model import NegativeBinomial, Poisson
base = sys.argv[1]
poc = json.load(open(base + '/poc_lags.json'))
kev = json.load(open(base + '/kev/known_exploited_vulnerabilities.json'))['vulnerabilities']
kl = {r['cve']: r['lag'] for r in json.load(open(base + '/kev_lags.json'))}
den = json.load(open(base + '/cve_monthly_published.json')) if os.path.exists(base + '/cve_monthly_published.json') else None
months = [f'{y}-{m:02d}' for y in (2023, 2024, 2025, 2026) for m in range(1, 13) if f'{y}-{m:02d}' <= '2026-10']
series = {
    'exploit_code_30d': collections.Counter(r['pub'][:7] for r in poc if r['lag'] <= 30),
    'exploit_code_7d': collections.Counter(r['pub'][:7] for r in poc if r['lag'] <= 7),
    'exploit_code_30d_starred': collections.Counter(r['pub'][:7] for r in poc if r['lag_star'] is not None and r['lag_star'] <= 30),
    'kev_inclusion_30d': collections.Counter(x['dateAdded'][:7] for x in kev if x['cveID'] in kl and kl[x['cveID']] <= 30),
}
if os.path.exists(base + '/msf_counts.json'):
    series['metasploit_module_30d'] = collections.Counter(json.load(open(base + '/msf_counts.json'))['fast30'])
    series['metasploit_module_90d'] = collections.Counter(json.load(open(base + '/msf_counts.json'))['fast90'])
t = np.arange(len(months), dtype=float); post = np.array([m >= '2026-05' for m in months], float)
X = sm.add_constant(np.column_stack([t, post]))
out = {}
for name, c in series.items():
    mm = [m for m in months if m <= ('2026-08' if name.startswith('metasploit') else '2026-10')]
    k = len(mm); tt = np.arange(k, dtype=float); pp = np.array([m >= '2026-05' for m in mm], float)
    X = sm.add_constant(np.column_stack([tt, pp]))
    y = np.array([c[m] for m in mm], float)
    for spec in (['count', 'rate'] if den else ['count']):
        if name.startswith('kev') and spec == 'rate': continue
        off = np.log(np.array([den[m] for m in mm], float)) if spec == 'rate' else None
        nb = NegativeBinomial(y, X, offset=off, loglike_method='nb2').fit(disp=0, maxiter=500, cov_type='HC1')
        po = Poisson(y, X, offset=off).fit(disp=0)
        mu = nb.predict(X, offset=off) if off is not None else nb.predict(X)
        alpha = float(nb.params[-1])
        pearson = float(np.sum((y - mu) ** 2 / (mu + alpha * mu ** 2)) / (len(y) - 4))
        names = ['const', 'trend', 'post', 'alpha']
        out[f'{name}|{spec}'] = dict(
            n=len(y), coef={k: float(v) for k, v in zip(names, nb.params)}, se={k: float(v) for k, v in zip(names, nb.bse)},
            ci={k: [float(a), float(b)] for k, (a, b) in zip(names, nb.conf_int())}, p={k: float(v) for k, v in zip(names, nb.pvalues)},
            irr_post=float(np.exp(nb.params[2])), irr_ci=[float(np.exp(nb.conf_int()[2][0])), float(np.exp(nb.conf_int()[2][1]))],
            loglik=float(nb.llf), aic=float(nb.aic), bic=float(nb.bic), pseudo_r2=float(nb.prsquared),
            pearson_chi2_df=pearson, lr_alpha_vs_poisson=float(2 * (nb.llf - po.llf)))
        r = out[f'{name}|{spec}']
        print(f"{name:28s} {spec:5s} IRR {r['irr_post']:.2f} [{r['irr_ci'][0]:.2f},{r['irr_ci'][1]:.2f}] p={r['p']['post']:.4f} "
              f"trend {r['coef']['trend']:.4f}({r['se']['trend']:.4f}) alpha {alpha:.3f}({r['se']['alpha']:.3f}) "
              f"LL {r['loglik']:.1f} AIC {r['aic']:.1f} pR2 {r['pseudo_r2']:.3f} Pearson/df {pearson:.2f} LR(a=0) {r['lr_alpha_vs_poisson']:.1f}")
json.dump(out, open(base + '/nb_full.json', 'w'), indent=1)
