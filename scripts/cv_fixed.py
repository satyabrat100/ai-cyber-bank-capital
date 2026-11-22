"""Review v7.1, issue 6: common-vendor model with FIXED event severity.
Baseline: a share c of each bank's baseline expected loss comes from one common-vendor event with probability p0 and
mean size S0 = c * EL0_total / p0. Shock: probability rises to p0 * M while the size distribution is UNCHANGED, so the
expected common loss rises by the factor M (variant 'fixed_size'). For comparison, variant 'fixed_el' keeps the common
share of the shocked expected loss fixed (the paper's earlier assumption), so the event becomes smaller as it becomes
more frequent. Idiosyncratic losses follow the bank model. 300,000 years; M = 1.56; sigma_c = 1."""
import json, sys, os
import numpy as np
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
import core_sim as cs
NY = 300_000; p = dict(cs.BASE); M = 1.56; out = {}
for NB in [6, 12, 24, 48]:
    sizes = np.sort(np.random.default_rng(3).lognormal(0, 0.8, NB))[::-1]; sizes = sizes / sizes.sum() * NB
    L = {}; EL = {}
    for m in (1.0, M):
        b = cs.bank_response(p, m ** 2 - 1, 0.0, 'lognormal', np.inf)
        L[m] = np.array([cs.annual_losses(cs.Draws(n=NY, kmax=16, seed=1000 + i), b['lam'], 'lognormal', np.inf, b['sig'], b['S']) * sizes[i] for i in range(NB)])
        EL[m] = b['el'] * sizes.sum()
    for p0 in ([0.01, 0.02, 0.05] if NB == 12 else [0.02]):
        for c in [0.0, 0.25, 0.5]:
            r = np.random.default_rng(77); u = r.random(NY); z = np.exp(r.standard_normal(NY) - 0.5)
            S0 = c * EL[1.0] / p0
            res = {}
            for var in ('fixed_size', 'fixed_el'):
                def system(m):
                    pc = min(1.0, p0 * m)
                    size = S0 if (var == 'fixed_size' or m == 1.0) else c * EL[m] / pc
                    common = (u < pc) * z * size
                    banks = L[m] * (1 - c) + np.outer(sizes / NB, common)
                    s = banks.sum(axis=0)
                    return np.quantile(s, 0.999), sum(np.quantile(x, 0.999) for x in banks), s.mean()
                (s0, sum0, m0), (s1, sum1, m1) = system(1.0), system(M)
                res[var] = dict(ratio_base=float(s0 / sum0), ratio_shock=float(s1 / sum1), system_var_rise=float(s1 / s0 - 1), system_el_rise=float(m1 / m0 - 1))
            out[f'{NB}|{p0}|{c}'] = res
            print(NB, p0, c, {v: (round(100 * x['system_var_rise'], 1), round(100 * x['system_el_rise'], 1), round(x['ratio_shock'], 2)) for v, x in res.items()}, flush=True)
json.dump(out, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'results', 'cv_fixed.json'), 'w'), indent=1)
