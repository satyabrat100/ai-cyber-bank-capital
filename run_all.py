"""Recompute every simulation table of the revised paper with core_sim (2,000,000 years, CRN, batch SEs)."""
import json, time, sys
import numpy as np
import core_sim as cs

t0 = time.time()
dr = cs.Draws()
P = dict(cs.BASE)
SPEC = {'freq_only': dict(eta=0.0, zeta=0.0), 'freq_sev': dict(eta=0.3, zeta=0.0), 'freq_sev_tail': dict(eta=0.3, zeta=0.15)}
def p_of(**kw):
    q = dict(P); q.update(kw); return q
def a_of(M, theta=0.5):
    return M ** (1 / theta) - 1
def log(*x):
    print(f'[{time.time()-t0:6.0f}s]', *x, flush=True)
out = {}

# 1. Main table: frequency multiplier for bank incidents M (mapping test, item 13), three specifications, three quantiles
out['main'] = {}
for M in [1.10, 1.25, 1.56, 1.76, 2.0, 3.16]:
    for sp, kw in SPEC.items():
        r = cs.run(dr, p_of(**kw), a_of(M))
        out['main'][f'{M}|{sp}'] = r
        log('main', M, sp, ' '.join(f"q{q}: gap {r[q]['gap']*100:.1f}% (se {r[q]['gap_se']*100:.1f}) VaR+{r[q]['var_up']*100:.0f}% ORC+{r[q]['orc_up']*100:.1f}%" for q in (0.99, 0.995, 0.999)))

# 2. Capped single losses, three families (items 1, 3)
out['capped'] = {}
for fam in ['lognormal', 'loglogistic', 'weibull']:
    for cap in [2500.0, 5000.0, 25000.0, np.inf]:
        if fam == 'weibull' and cap != np.inf and cap != 2500.0: continue
        for sp in ['freq_only', 'freq_sev']:
            r = cs.run(dr, p_of(**SPEC[sp]), a_of(1.56), family=fam, cap=cap)
            out['capped'][f'{fam}|{cap:g}|{sp}'] = r
            log('capped', fam, cap, sp, ' '.join(f"q{q}: VaR {r[q]['var0']:.0f}->{r[q]['var1']:.0f} gap {r[q]['gap']*100:.1f}% (se {r[q]['gap_se']*100:.1f})" for q in (0.99, 0.995, 0.999)))

# 3. Theta effect with the observed multiplier held fixed (item 25)
out['theta'] = {}
for th in [0.25, 0.5, 0.75, 1.0]:
    r = cs.run(dr, p_of(theta=th, eta=0.3, zeta=0.0), a_of(1.56, th), qs=(0.999,))
    out['theta'][th] = dict(capability=1 + a_of(1.56, th), sev_mult=(1 + a_of(1.56, th)) ** 0.3, **r[0.999])
    log('theta', th, round(r[0.999]['gap'] * 100, 1))

# 4. Security parameters beta, kappa (item 14)
out['beta_kappa'] = {}
for beta in [0.5, 1.0, 2.0]:
    for kt in [25.0, 100.0, 400.0]:
        res = {}
        for sp in ['freq_only', 'freq_sev']:
            r = cs.run(dr, p_of(beta=beta, kappa_t=kt, **SPEC[sp]), a_of(1.56), qs=(0.999,))
            res[sp] = dict(gap=r[0.999]['gap'], se=r[0.999]['gap_se'], s0=r['s0'], el0=r['el0'])
        out['beta_kappa'][f'{beta}|{kt}'] = res
        log('beta', beta, 'kappa', kt, {k: round(v['gap'] * 100, 1) for k, v in res.items()})

# 5. Defensive AI productivity phi at parity and half pace (item 22); neutrality phi* = (theta+eta)/beta
out['phi'] = {}
for phi in [0.4, 0.6, 0.8, 1.0, 1.2]:
    for M in [1.56, 3.16]:
        a = a_of(M)
        for lab, d in [('parity', a), ('half', a / 2)]:
            r = cs.run(dr, p_of(phi=phi, **SPEC['freq_sev']), a, d=d, qs=(0.999,))
            out['phi'][f'{phi}|{M}|{lab}'] = dict(gap_fixed=r[0.999]['gap_fixed'], se=r[0.999]['gap_se'], el_ratio=r['el1'] / r['el0'])
    log('phi', phi, {k.split('|', 1)[1]: round(v['gap_fixed'] * 100, 1) for k, v in out['phi'].items() if k.startswith(f'{phi}|')})

# 6. Dynamic path: 3-year ramp vs immediate shock; 10-year vs 5-year ILM loss window (item 21)
out['path'] = {}
M_end = 1.56
for sp in ['freq_only', 'freq_sev']:
    p = p_of(**SPEC[sp])
    var_at = {}
    for M in [1.0, 1.56 ** (1 / 3), 1.56 ** (2 / 3), 1.56]:
        var_at[M] = cs.run(dr, p, a_of(M), qs=(0.999,))
    base = var_at[1.0]
    bic = base[0.999]['bic']
    for ramp in ['ramp3', 'immediate']:
        for W in [10, 5]:
            hist = [base['el0']] * W; rows = []
            for t in range(16):
                if ramp == 'ramp3': M = 1.56 ** (min(t, 3) / 3)
                else: M = 1.56 if t >= 1 else 1.0
                key = min(var_at, key=lambda k: abs(k - M))
                r = var_at[key]
                hist = hist[1:] + [r['el1'] if M > 1 else r['el0']]
                orc = bic * cs.ilm(15 * np.mean(hist), bic)
                rows.append(dict(year=t, var=r[0.999]['var1'] / bic, orc=orc / bic))
            out['path'][f'{sp}|{ramp}|W{W}'] = rows
    log('path', sp, [(r['year'], round(r['var'], 3), round(r['orc'], 3)) for r in out['path'][f'{sp}|ramp3|W10']][:5])

json.dump(out, open('results_v5.json', 'w'), indent=1, default=lambda o: float(o) if isinstance(o, (np.floating,)) else str(o))
log('done')
