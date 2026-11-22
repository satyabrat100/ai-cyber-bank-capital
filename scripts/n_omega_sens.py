"""Point 20: sensitivity to system size N (number of banks) and to the operational-risk share of RWA (omega)."""
import json, sys, os
import numpy as np
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
import core_sim as cs
NY = 300_000; p = dict(cs.BASE); out = {'N': {}, 'omega': {}}
for NB in [6, 12, 24, 48]:
    sizes = np.sort(np.random.default_rng(3).lognormal(0, 0.8, NB))[::-1]; sizes = sizes / sizes.sum() * NB
    res = {}
    for M in [1.0, 1.56]:
        b = cs.bank_response(p, M ** 2 - 1, 0.0, 'lognormal', np.inf)
        Lb = np.array([cs.annual_losses(cs.Draws(n=NY, kmax=16, seed=1000 + i), b['lam'], 'lognormal', np.inf, b['sig'], b['S']) * sizes[i] for i in range(NB)])
        elb = b['el'] * sizes
        for share in [0.0, 0.25, 0.5]:
            pc = min(1.0, 0.02 * M); r = np.random.default_rng(77)
            hit = r.random(NY) < pc; z = np.exp(r.standard_normal(NY) - 0.5)
            common = hit * z * share * elb.sum() / pc
            banks = Lb * (1 - share) + np.outer(sizes / NB, common)
            sysL = banks.sum(axis=0)
            res[(M, share)] = (np.quantile(sysL, 0.999), sum(np.quantile(x, 0.999) for x in banks))
    for share in [0.0, 0.25, 0.5]:
        s0, sum0 = res[(1.0, share)]; s1, sum1 = res[(1.56, share)]
        out['N'][f'{NB}|{share}'] = dict(ratio_base=float(s0 / sum0), ratio_shock=float(s1 / sum1), system_var_rise=float(s1 / s0 - 1))
    print('N', NB, {s: (round(out['N'][f'{NB}|{s}']['ratio_shock'], 2), round(100 * out['N'][f'{NB}|{s}']['system_var_rise'], 1)) for s in [0.0, 0.25, 0.5]}, flush=True)
# omega: a Pillar 2 add-on equal to the gap raises op-risk RWA by the gap; CRAR' = CRAR / (1 + omega * gap)
gaps = {'M=1.56 frequency only': 0.187, 'M=1.56 with severity': 0.363, 'M=1.76 with severity': 0.487}
for w in [0.05, 0.075, 0.10, 0.125, 0.15, 0.20]:
    out['omega'][str(w)] = {k: dict(crar_after=17.7 / (1 + w * g), fall_pp=17.7 - 17.7 / (1 + w * g)) for k, g in gaps.items()}
    print('omega', w, {k: round(v['fall_pp'], 2) for k, v in out['omega'][str(w)].items()})
json.dump(out, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'results', 'n_omega_sens.json'), 'w'), indent=1)
