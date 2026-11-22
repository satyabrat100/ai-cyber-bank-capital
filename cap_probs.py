"""Review v7.1, issue 2: three different probabilities for capped scenarios (M = 1.56), kept apart:
  P(L > c)          aggregate annual loss exceeds the cap amount c
  P(max X_k >= c)   at least one single (pre-cap) loss reaches c  [= P(N_c >= 1)]
  P(N_c >= 2)       two or more single losses reach c in the same year
plus P(L > c and N_c = 0): the aggregate exceeds c through ordinary losses only. 2,000,000 years; Clopper-Pearson CIs."""
import json, numpy as np, core_sim as cs
from scipy import stats
dr = cs.Draws(); a = 1.56 ** 2 - 1; n = dr.n
def ci(k): return [float(stats.beta.ppf(0.025, k, n - k + 1)) if k else 0.0, float(stats.beta.ppf(0.975, k + 1, n - k))]
SPEC = {'freq_only': dict(eta=0.0, zeta=0.0), 'freq_sev': dict(eta=0.3, zeta=0.0)}
out = {}
for fam, cap in [('lognormal', 25000.0), ('lognormal', 5000.0), ('lognormal', 2500.0), ('loglogistic', 25000.0), ('loglogistic', 5000.0), ('loglogistic', 2500.0), ('weibull', 2500.0)]:
    for sp in SPEC:
        p = dict(cs.BASE); p.update(SPEC[sp]); row = {}
        for lab, aa in (('base', 0.0), ('shock', a)):
            b = cs.bank_response(p, aa, 0.0, fam, cap)
            N = np.minimum(stats.poisson.ppf(dr.u_n, b['lam']).astype(int), cs.KMAX)
            L = np.zeros(n); Nc = np.zeros(n, int)
            for k in range(cs.KMAX):
                idx = N > k
                if not idx.any(): break
                x = cs.sev_ppf(fam, dr.u_x[idx, k].astype(np.float64), b['sig'], b['S'])
                L[idx] += np.minimum(x, cap); Nc[idx] += x >= cap
            for key, m in (('p_L_gt_c', L > cap), ('p_max_ge_c', Nc >= 1), ('p_Nc_ge2', Nc >= 2), ('p_L_gt_c_no_capped', (L > cap) & (Nc == 0))):
                k_ = int(m.sum()); row[f'{key}_{lab}'] = k_ / n; row[f'{key}_{lab}_ci'] = ci(k_)
        out[f'{fam}|{cap}|{sp}'] = row
        print(fam, cap, sp, {k: round(100 * v, 4) for k, v in row.items() if not k.endswith('ci') and k.endswith('shock')}, flush=True)
json.dump(out, open('results/cap_probs.json', 'w'), indent=1)
