"""Capital gap under alternative severity distributions, quantile levels, sigma uncertainty,
and an assumption-light scenario (only the observed frequency change; no severity or tail change)."""
import json, sys
import numpy as np
from scipy import stats
from scipy.optimize import brentq
base = sys.argv[1]
T = json.load(open(base + '/tail_results.json'))
LAM0, KAPPA, NS = 25.0, 100.0, 200_000
CAP_MUSD = 5000.0   # truncate severities at USD 5bn (2x the IMF 2024 extreme-loss estimate)
def ilm(lc, bic): return np.log(np.e - 1 + (lc / bic) ** 0.8)
def make_sampler(kind, **p):
    def draw(rng, n):
        if kind == 'lognormal': z = np.exp(p['sigma'] * rng.standard_normal(n))
        elif kind == 'loglogistic': z = stats.fisk.ppf(rng.random(n), p['c'], scale=p['scale'])
        elif kind == 'weibull': z = stats.weibull_min.ppf(rng.random(n), p['c'], scale=p['scale'])
        return np.minimum(z, p.get('cap', np.inf))
    return draw
def run(draw, M, S, qs=(0.999,), seed=5):
    r0 = np.random.default_rng(99); mZ = draw(r0, 4_000_000).mean()
    c = 1.0 / (LAM0 * mZ)                       # baseline unprotected EL A0 = 1 -> EL0* = 0.1
    def sim(Mf, Sf):
        A = Mf * Sf                              # unprotected EL relative to baseline (A0 = 1)
        one = np.sqrt(A * KAPPA); v = 1 / one; el = np.sqrt(A / KAPPA)
        lam = LAM0 * Mf * v
        r = np.random.default_rng(seed); n = r.poisson(lam, NS)
        x = c * Sf * draw(r, n.sum())
        L = np.bincount(np.repeat(np.arange(NS), n), weights=x, minlength=NS)
        return el, {q: np.quantile(L, q) for q in qs}
    el0, v0 = sim(1.0, 1.0); el1, v1 = sim(M, S)
    res = {}
    for q in qs:
        bic = brentq(lambda b: b * ilm(15 * el0, b) - v0[q], 1e-6, 1e6)
        orc0 = bic * ilm(15 * el0, bic); orc1 = bic * ilm(15 * el1, bic)
        res[q] = dict(var_up=v1[q] / v0[q] - 1, orc_up=orc1 / orc0 - 1, gap=v1[q] / orc1 - 1, gap_fixed=v1[q] / orc0 - 1)
    return res
fin = T['fin']['fits']
out = {}
M_list = {'PoC 1.56': 1.56, 'GTIG 1.71': 1.71, 'KEV 1.76': 1.76}
eta_S = lambda M: (M ** 2) ** 0.3    # theta=0.5, eta=0.3: S = (1+a)^eta with (1+a)=M^2
LN = make_sampler('lognormal', sigma=3.09, cap=CAP_MUSD / np.exp(np.log(T['fin']['fits']['lognormal']['params'][2])))
# 1. Assumption-light: frequency only
out['freq_only'] = {k: run(make_sampler('lognormal', sigma=3.09), M, 1.0, qs=(0.99, 0.995, 0.999)) for k, M in M_list.items()}
# 2. Frequency + severity (eta = 0.3)
out['freq_sev'] = {k: run(make_sampler('lognormal', sigma=3.09), M, eta_S(M), qs=(0.99, 0.995, 0.999)) for k, M in M_list.items()}
# 3. Alternative severity families (fitted to the 61 financial-sector losses, in USD m, truncated at USD 5bn)
fam = {'lognormal': make_sampler('lognormal', sigma=fin['lognormal']['params'][0], cap=CAP_MUSD / fin['lognormal']['params'][2]),
       'loglogistic': make_sampler('loglogistic', c=fin['loglogistic']['params'][0], scale=fin['loglogistic']['params'][2], cap=CAP_MUSD),
       'weibull': make_sampler('weibull', c=fin['weibull']['params'][0], scale=fin['weibull']['params'][2], cap=CAP_MUSD)}
out['families'] = {k: {'freq_only': run(d, 1.56, 1.0)[0.999], 'freq_sev': run(d, 1.56, eta_S(1.56))[0.999]} for k, d in fam.items()}
# 4. Sigma uncertainty: gap as a function of sigma, mapped through the bootstrap CI
grid = [2.5, 2.8, 3.09, 3.3, 3.57]
out['sigma_grid'] = {s: run(make_sampler('lognormal', sigma=s), 1.56, 1.0)[0.999]['gap'] for s in grid}
def clean(o):
    if isinstance(o, dict): return {str(k): clean(v) for k, v in o.items()}
    if isinstance(o, (np.floating,)): return float(o)
    return o
json.dump(clean(out), open(base + '/robust_gap.json', 'w'), indent=1)
for k in ['freq_only', 'freq_sev']:
    for m, r in out[k].items():
        print(k, m, {q: f"VaR+{v['var_up']*100:.0f}% ORC+{v['orc_up']*100:.1f}% gap {v['gap']*100:.0f}%" for q, v in r.items()})
for f, r in out['families'].items():
    print(f, {k: f"VaR+{v['var_up']*100:.0f}% ORC+{v['orc_up']*100:.1f}% gap {v['gap']*100:.0f}%" for k, v in r.items()})
print('sigma grid', {s: f"{g*100:.0f}%" for s, g in out['sigma_grid'].items()})
