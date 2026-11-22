"""Items 1, 14, 20: capped-event probabilities, beta x kappa grid with implied security spending,
and one-at-a-time sensitivity of every assumed or calibrated simulation parameter. M = 1.56 throughout."""
import json, time, numpy as np, core_sim as cs
from scipy import stats
dr = cs.Draws(); T0 = time.time(); out = {}
def p_of(**kw): p = dict(cs.BASE); p.update(kw); return p
SPEC = {'freq_only': dict(eta=0.0, zeta=0.0), 'freq_sev': dict(eta=0.3, zeta=0.0)}
a = 1.56 ** 2 - 1
def log(*x): print(f'[{time.time() - T0:7.0f}s]', *x, flush=True)
def brief(r): return {q: dict(gap=r[q]['gap'], se=r[q]['gap_se'], var_up=r[q]['var_up'], orc_up=r[q]['orc_up']) for q in (0.99, 0.995, 0.999)}

# 1. capped aggregate: probabilities of capped events per simulated year (item 1)
out['capped'] = {}
for fam, caps in [('lognormal', [2500, 5000, 25000]), ('loglogistic', [2500, 5000, 25000]), ('weibull', [2500])]:
    for cap in caps:
        for sp in SPEC:
            p = p_of(**SPEC[sp]); r = cs.run(dr, p, a, family=fam, cap=cap)
            row = brief(r)
            for lab, aa in (('base', 0.0), ('shock', a)):
                b = cs.bank_response(p, aa, 0.0, fam, cap)
                n = np.minimum(stats.poisson.ppf(dr.u_n, b['lam']).astype(int), cs.KMAX)
                ncap = np.zeros(dr.n, int)
                for k in range(cs.KMAX):
                    idx = n > k
                    if not idx.any(): break
                    ncap[idx] += cs.sev_ppf(fam, dr.u_x[idx, k].astype(np.float64), b['sig'], b['S']) >= cap
                row[f'p_ge1_{lab}'] = float(np.mean(ncap >= 1)); row[f'p_ge2_{lab}'] = float(np.mean(ncap >= 2))
                row[f'p_n_gt_kmax_{lab}'] = float(stats.poisson.sf(cs.KMAX, b['lam']))
            out['capped'][f'{fam}|{cap}|{sp}'] = row
            log('cap', fam, cap, sp, {k: round(v * 100, 3) for k, v in row.items() if isinstance(k, str) and k.startswith('p_')}, round(row[0.99]['gap'] * 100, 1), round(row[0.999]['gap'] * 100, 1))

# 2. beta x kappa grid with implied security spending (item 14)
out['beta_kappa'] = {}
for beta in [0.25, 0.5, 1.0, 2.0, 4.0]:
    for kt in [10.0, 25.0, 100.0, 400.0, 1000.0]:
        row = {}
        for sp in SPEC:
            p = p_of(beta=beta, kappa_t=kt, **SPEC[sp]); r = cs.run(dr, p, a, qs=(0.99, 0.999))
            b0 = cs.bank_response(p, 0.0, 0.0, 'lognormal', np.inf)
            row[sp] = dict(gap99=r[0.99]['gap'], gap999=r[0.999]['gap'], se999=r[0.999]['gap_se'],
                           spend_over_unprotected=b0['s'] / b0['A'], spend_over_residual=b0['s'] / b0['el'], residual_share=b0['el'] / b0['A'])
        out['beta_kappa'][f'{beta}|{kt}'] = row
        log('bk', beta, kt, {sp: (round(v['gap999'] * 100, 1), round(v['spend_over_unprotected'], 3), round(v['residual_share'], 3)) for sp, v in row.items()})

# 3. one-at-a-time sensitivity (item 20)
out['oat'] = {}
def oat(name, val, fam='lognormal', **kw):
    row = {}
    for sp in SPEC:
        p = p_of(**{**SPEC[sp], **kw}); r = cs.run(dr, p, a, family=fam, qs=(0.99, 0.999))
        row[sp] = dict(gap99=r[0.99]['gap'], gap999=r[0.999]['gap'], se999=r[0.999]['gap_se'])
    out['oat'][f'{name}|{val}'] = row
    log('oat', name, val, {sp: round(v['gap999'] * 100, 1) for sp, v in row.items()})
oat('base', 'central')
for l in [10.0, 50.0, 100.0]: oat('lam0', l, lam0=l)
s0 = cs.FIT['lognormal']['sigma']
for s in [2.50, 3.57]:
    cs.FIT['lognormal']['sigma'] = s; oat('sigma0', s)
cs.FIT['lognormal']['sigma'] = s0
for e in [0.15, 0.5]:
    p = p_of(eta=e); r = cs.run(dr, p, a, qs=(0.99, 0.999))
    out['oat'][f'eta|{e}'] = {'freq_sev': dict(gap99=r[0.99]['gap'], gap999=r[0.999]['gap'], se999=r[0.999]['gap_se'])}; log('oat eta', e, round(r[0.999]['gap'] * 100, 1))
for z in [0.075, 0.15, 0.3]:
    p = p_of(eta=0.3, zeta=z); r = cs.run(dr, p, a, qs=(0.99, 0.999))
    out['oat'][f'zeta|{z}'] = {'freq_sev': dict(gap99=r[0.99]['gap'], gap999=r[0.999]['gap'], se999=r[0.999]['gap_se'])}; log('oat zeta', z, round(r[0.999]['gap'] * 100, 1))
json.dump(out, open('results/results_sens_v5.json' if __import__('os').path.isdir('results') else 'results_sens_v5.json', 'w'), indent=1, default=float)
log('done')
