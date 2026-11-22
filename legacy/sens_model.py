"""Model sensitivity: beta, kappa (14); frequency mapping (13); phi (22); common-vendor p0 and size (17, 23);
theta decomposition (25); timing and loss window (21)."""
import json, sys, io, contextlib, runpy, os
import numpy as np
here = os.path.dirname(os.path.abspath(__file__))
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    g = runpy.run_path(os.path.join(here, '..', 'ai_cyber_sim.py'))
P, calibrate, scenario, ilm = g['P'], g['calibrate'], g['scenario'], g['ilm']
M = 1.56; NS = 100_000
def gap(a, d=0.0):
    mu0, bic, b0 = calibrate()
    orc0 = bic * ilm(15 * b0['EL'], bic)
    r = scenario(a, d, mu0, nsim=NS)
    orc = bic * ilm(15 * r['EL'], bic)
    return dict(gap_adj=float(r['VaR'] / orc - 1), gap_fixed=float(r['VaR'] / orc0 - 1), var_up=float(r['VaR'] / b0['VaR'] - 1), orc_up=float(orc / orc0 - 1))
def with_params(**kw):
    old = {k: P[k] for k in kw}; P.update(kw)
    return old
out = {}
a_c = M ** (1 / P['theta']) - 1
# 14. beta and kappa
out['beta_kappa'] = {}
for beta in [0.5, 1.0, 2.0]:
    for kappa in [25.0, 100.0, 400.0]:
        old = with_params(beta=beta, kappa=kappa)
        o1 = with_params(eta=0.0, zeta=0.0); r_f = gap(a_c); P.update(o1)
        r_c = gap(a_c)
        out['beta_kappa'][f'beta={beta},kappa={kappa}'] = dict(freq_only=r_f['gap_adj'], central=r_c['gap_adj'])
        P.update(old)
        print('beta', beta, 'kappa', kappa, {k: round(v * 100, 1) for k, v in out['beta_kappa'][f'beta={beta},kappa={kappa}'].items()})
# 13. mapping from observed exploit-code multiplier to bank incident multiplier: M_bank = M**psi
out['mapping'] = {}
for psi in [0.5, 0.75, 1.0, 1.25]:
    a = M ** (psi / P['theta']) - 1
    o1 = with_params(eta=0.0, zeta=0.0); r_f = gap(a); P.update(o1)
    r_c = gap(a)
    out['mapping'][psi] = dict(bank_multiplier=M ** psi, freq_only=r_f['gap_adj'], central=r_c['gap_adj'])
    print('psi', psi, {k: round(v * 100, 1) if k != 'bank_multiplier' else round(v, 3) for k, v in out['mapping'][psi].items()})
# 22. phi at parity
out['phi_parity'] = {}
for phi in [0.4, 0.6, 0.8, 1.0, 1.2]:
    old = with_params(phi=phi)
    out['phi_parity'][phi] = {lab: gap(a, d=a)['gap_fixed'] for lab, a in [('central', a_c), ('x4', 3.0)]}
    P.update(old)
    print('phi', phi, {k: round(v * 100, 1) for k, v in out['phi_parity'][phi].items()})
# 25. decomposition: frequency, + severity mean, + tail fattening; and theta effect with M fixed
out['decomp'] = {}
for lab, kw in [('frequency only', dict(eta=0.0, zeta=0.0)), ('+ severity mean (eta=0.3)', dict(eta=0.3, zeta=0.0)), ('+ tail (zeta=0.15)', dict(eta=0.3, zeta=0.15))]:
    old = with_params(**kw); out['decomp'][lab] = gap(a_c)['gap_adj']; P.update(old)
    print(lab, round(out['decomp'][lab] * 100, 1))
out['theta_effect'] = {}
for th in [0.25, 0.5, 0.75, 1.0]:
    old = with_params(theta=th); a = M ** (1 / th) - 1
    out['theta_effect'][th] = dict(implied_capability=1 + a, severity_multiplier=(1 + a) ** P['eta'], gap=gap(a)['gap_adj'])
    P.update(old)
    print('theta', th, {k: round(v, 3) for k, v in out['theta_effect'][th].items()})
json.dump({k: {str(kk): vv for kk, vv in v.items()} for k, v in out.items()}, open(os.path.join(here, '..', 'results_sens_model.json'), 'w'), indent=1)
