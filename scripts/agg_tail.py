"""Aggregate annual loss under capped single-loss severities (item 1).
Compound Poisson Monte Carlo: annual loss = sum of capped single losses, so annual totals can exceed the cap.
The cap is a fixed US$ ceiling on each single loss, applied AFTER any AI severity scaling."""
import json, sys
import numpy as np
from scipy import stats
from scipy.optimize import brentq
base = sys.argv[1]
T = json.load(open(base + '/tail_results.json'))['fin']['fits']
LAM0, KAPPA, NS = 25.0, 100.0, 400_000
QS = (0.99, 0.995, 0.999)
def ilm(lc, bic): return np.log(np.e - 1 + (lc / bic) ** 0.8)
def sev_usd(kind):
    if kind == 'lognormal':
        s, sc = T['lognormal']['params'][0], T['lognormal']['params'][2]
        return lambda r, n: sc * np.exp(s * r.standard_normal(n))
    if kind == 'loglogistic':
        c, sc = T['loglogistic']['params'][0], T['loglogistic']['params'][2]
        return lambda r, n: stats.fisk.ppf(r.random(n), c, scale=sc)
    if kind == 'weibull':
        c, sc = T['weibull']['params'][0], T['weibull']['params'][2]
        return lambda r, n: stats.weibull_min.ppf(r.random(n), c, scale=sc)
def simulate(kind, cap, M, S, seed=5):
    """Return annual losses in US$ m for baseline frequency x M and severity x S (cap applied after scaling)."""
    A = M * S                                   # unprotected expected loss relative to baseline
    v = 1 / np.sqrt(A * KAPPA)                  # breach share after optimal security (beta = 1), baseline v0 = 0.1
    lam = LAM0 * M * v
    r = np.random.default_rng(seed); n = r.poisson(lam, NS)
    x = np.minimum(S * sev_usd(kind)(r, n.sum()), cap)
    L = np.bincount(np.repeat(np.arange(NS), n), weights=x, minlength=NS)
    ncap = np.bincount(np.repeat(np.arange(NS), n), weights=(x >= cap).astype(float), minlength=NS)
    return L, lam, ncap, np.sqrt(A / KAPPA)
def gap_table(kind, cap, M, S):
    L0, lam0, nc0, el0r = simulate(kind, cap, 1.0, 1.0)
    L1, lam1, nc1, el1r = simulate(kind, cap, M, S)
    mean0, mean1 = L0.mean(), L1.mean()             # expected annual loss, used for the ILM loss component
    res = dict(lam0=lam0, lam1=lam1, p_any_cap0=float((nc0 >= 1).mean()), p_two_cap0=float((nc0 >= 2).mean()),
               p_any_cap1=float((nc1 >= 1).mean()), p_two_cap1=float((nc1 >= 2).mean()),
               share_years_above_cap1=float((L1 > cap).mean()), max_annual1=float(L1.max()))
    for q in QS:
        v0, v1 = np.quantile(L0, q), np.quantile(L1, q)
        bic = brentq(lambda b: b * ilm(15 * mean0, b) - v0, 1e-9, 1e9)
        o0, o1 = bic * ilm(15 * mean0, bic), bic * ilm(15 * mean1, bic)
        res[str(q)] = dict(var0_usdm=float(v0), var1_usdm=float(v1), var_up=float(v1 / v0 - 1),
                           orc_up=float(o1 / o0 - 1), gap=float(v1 / o1 - 1))
    return res
out = {}
S_eta = (1.56 ** 2) ** 0.3
for kind in ['lognormal', 'loglogistic', 'weibull']:
    for cap in [2500.0, 5000.0, 25000.0, np.inf]:
        for lab, S in [('freq_only', 1.0), ('freq_sev', S_eta)]:
            key = f'{kind}|cap={cap:g}|{lab}'
            out[key] = gap_table(kind, cap, 1.56, S)
            r = out[key]
            print(key, 'lam %.2f->%.2f' % (r['lam0'], r['lam1']), 'P(>=1 cap) %.4f->%.4f' % (r['p_any_cap0'], r['p_any_cap1']),
                  'P(>=2 cap) %.5f' % r['p_two_cap1'], 'yrs>cap %.5f' % r['share_years_above_cap1'],
                  ' | '.join(f"q{q}: VaR {r[str(q)]['var0_usdm']:.0f}->{r[str(q)]['var1_usdm']:.0f} gap {r[str(q)]['gap']*100:.0f}%" for q in QS))
json.dump(out, open(base + '/agg_tail.json', 'w'), indent=1)
