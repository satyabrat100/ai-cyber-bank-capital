"""Point 1: validation of capped compound Poisson aggregate losses at M = 1.56.
For each severity family x cap x scenario: annual aggregate VaR (US$ m) before and after the shock at 99, 99.5, 99.9%,
with 95% Monte Carlo confidence intervals from 20 independent batches of 100,000 years (t with 19 df);
probability that the ANNUAL AGGREGATE loss exceeds the cap, P(L > c), with a binomial 95% CI;
probability of >=1 and >=2 capped single losses; capital gap with 95% CI."""
import json, time, numpy as np, core_sim as cs
from scipy import stats
dr = cs.Draws(); T0 = time.time(); out = {}
a = 1.56 ** 2 - 1; Q = (0.99, 0.995, 0.999); B = np.array_split(np.arange(dr.n), cs.N_BATCH); tq = stats.t.ppf(0.975, cs.N_BATCH - 1)
SPEC = {'freq_only': dict(eta=0.0, zeta=0.0), 'freq_sev': dict(eta=0.3, zeta=0.0)}
def ci_q(L, q):
    v = np.array([np.quantile(L[i], q) for i in B]); m = v.mean(); h = tq * v.std(ddof=1) / np.sqrt(len(B))
    return float(np.quantile(L, q)), [float(m - h), float(m + h)]
def binci(k, n):
    lo = stats.beta.ppf(0.025, k, n - k + 1) if k > 0 else 0.0; hi = stats.beta.ppf(0.975, k + 1, n - k)
    return [float(lo), float(hi)]
def ncap(b, fam, cap):
    n = np.minimum(stats.poisson.ppf(dr.u_n, b['lam']).astype(int), cs.KMAX); c = np.zeros(dr.n, int)
    for k in range(cs.KMAX):
        idx = n > k
        if not idx.any(): break
        c[idx] += cs.sev_ppf(fam, dr.u_x[idx, k].astype(np.float64), b['sig'], b['S']) >= cap
    return c
rows = [('lognormal', np.inf), ('lognormal', 25000.0), ('lognormal', 5000.0), ('lognormal', 2500.0),
        ('loglogistic', np.inf), ('loglogistic', 25000.0), ('loglogistic', 5000.0), ('loglogistic', 2500.0), ('weibull', 2500.0)]
for fam, cap in rows:
    for sp in SPEC:
        p = dict(cs.BASE); p.update(SPEC[sp])
        b0 = cs.bank_response(p, 0.0, 0.0, fam, cap); b1 = cs.bank_response(p, a, 0.0, fam, cap)
        L0 = cs.annual_losses(dr, b0['lam'], fam, cap, 0.0, 1.0); L1 = cs.annual_losses(dr, b1['lam'], fam, cap, b1['sig'], b1['S'])
        row = dict(lam0=b0['lam'], lam1=b1['lam'])
        for q in Q:
            v0, c0 = ci_q(L0, q); v1, c1 = ci_q(L1, q)
            bic = cs.brentq(lambda x: x * cs.ilm(15 * b0['el'], x) - v0, 1e-9, 1e12)
            o1 = bic * cs.ilm(15 * b1['el'], bic)
            g = np.array([np.quantile(L1[i], q) / o1 - 1 for i in B]); h = tq * g.std(ddof=1) / np.sqrt(len(B))
            row[str(q)] = dict(var0=v0, var0_ci=c0, var1=v1, var1_ci=c1, gap=float(v1 / o1 - 1), gap_ci=[float(g.mean() - h), float(g.mean() + h)])
        if np.isfinite(cap):
            for lab, L, bb in (('base', L0, b0), ('shock', L1, b1)):
                k = int((L > cap).sum()); nc = ncap(bb, fam, cap)
                row[f'p_agg_gt_cap_{lab}'] = k / dr.n; row[f'p_agg_gt_cap_{lab}_ci'] = binci(k, dr.n)
                row[f'p_ge1_capped_{lab}'] = float((nc >= 1).mean()); row[f'p_ge2_capped_{lab}'] = float((nc >= 2).mean())
                row[f'p_ge2_capped_{lab}_ci'] = binci(int((nc >= 2).sum()), dr.n)
        out[f'{fam}|{cap}|{sp}'] = row
        r9 = row['0.999']
        print(f'[{time.time() - T0:5.0f}s] {fam} {cap} {sp} VaR99.9 {r9["var0"]:.0f} [{r9["var0_ci"][0]:.0f},{r9["var0_ci"][1]:.0f}] -> {r9["var1"]:.0f} [{r9["var1_ci"][0]:.0f},{r9["var1_ci"][1]:.0f}] gap {100*r9["gap"]:.1f} [{100*r9["gap_ci"][0]:.1f},{100*r9["gap_ci"][1]:.1f}]',
              ('P(L>c) %.3f%% -> %.3f%%' % (100 * row['p_agg_gt_cap_base'], 100 * row['p_agg_gt_cap_shock'])) if np.isfinite(cap) else '', flush=True)
import os
json.dump(out, open('results/cap_validation.json' if os.path.isdir('results') else 'cap_validation.json', 'w'), indent=1, default=float)
print('done')
