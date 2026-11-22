"""Common-vendor block: sensitivity to event probability p0 and event-size spread sigma_c (items 17, 23).
N banks; a share c of each bank's expected loss is moved to one common-vendor event with annual
probability p_c = p0 * M; the common loss is allocated by bank size. Total expected loss is unchanged."""
import json, sys, os
import numpy as np
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
import core_sim as cs
NY, NB = 300_000, 12
sizes = np.sort(np.random.default_rng(3).lognormal(0, 0.8, NB))[::-1]; sizes = sizes / sizes.sum() * NB
p = dict(cs.BASE)
idio = {}
for M in [1.0, 1.56]:
    b = cs.bank_response(p, M ** 2 - 1, 0.0, 'lognormal', np.inf)
    L = []
    for i in range(NB):
        dr = cs.Draws(n=NY, kmax=16, seed=1000 + i)
        L.append(cs.annual_losses(dr, b['lam'], 'lognormal', np.inf, b['sig'], b['S']) * sizes[i])
    idio[M] = (np.array(L), b['el'] * sizes)
out = {}
for M in [1.0, 1.56]:
    Lb, elb = idio[M]
    for p0 in [0.01, 0.02, 0.05, 0.10]:
        for sc in [0.5, 1.0, 2.0]:
            for share in [0.10, 0.25, 0.50]:
                pc = min(1.0, p0 * M)
                r = np.random.default_rng(77)
                hit = r.random(NY) < pc
                z = np.exp(sc * r.standard_normal(NY) - sc ** 2 / 2)
                common = hit * z * share * elb.sum() / pc
                banks = Lb * (1 - share) + np.outer(sizes / NB, common)
                sysL = banks.sum(axis=0)
                ratio = np.quantile(sysL, 0.999) / sum(np.quantile(x, 0.999) for x in banks)
                ratio0 = np.quantile(Lb.sum(axis=0), 0.999) / sum(np.quantile(x, 0.999) for x in Lb)
                out[f'{M}|{p0}|{sc}|{share}'] = dict(ratio=float(ratio), ratio_no_common=float(ratio0))
        print(M, p0, {f'sc{sc}|c{s}': round(out[f'{M}|{p0}|{sc}|{s}']['ratio'], 2) for sc in [0.5, 1.0, 2.0] for s in [0.10, 0.25, 0.50]},
              'no common', round(out[f'{M}|{p0}|1.0|0.1']['ratio_no_common'], 2), flush=True)
json.dump(out, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'results_cv_sens.json'), 'w'), indent=1)
