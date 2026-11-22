"""Numerical verification of Propositions 1-4 against brute-force optimisation and Monte Carlo (items 5, 18, 19)."""
import json, sys, io, contextlib, runpy, os
import numpy as np
from scipy.optimize import minimize_scalar
from scipy.stats import norm
here = os.path.dirname(os.path.abspath(__file__))
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    g = runpy.run_path(os.path.join(here, '..', 'legacy', 'ai_cyber_sim.py'))
P, scenario, mu0, BIC, sev = g['P'], g['scenario'], g['mu0'], g['BIC'], g['severity_params']
out = {}
# Proposition 1: closed form vs numerical minimisation
rows = []
for A in [0.5, 1.0, 4.0, 20.0]:
    for beta in [0.5, 1.0, 2.0]:
        for kappa in [25.0, 100.0, 400.0]:
            f = lambda s: s + A * (1 + kappa * s) ** (-beta)
            num = minimize_scalar(f, bounds=(0, 100), method='bounded', options={'xatol': 1e-12})
            x = A * beta * kappa
            s_cf = max(0.0, (x ** (1 / (1 + beta)) - 1) / kappa)
            rows.append(abs(num.x - s_cf))
out['P1_max_abs_error_s'] = float(max(rows))
# elasticity of EL* to (1+a) by finite difference in the model vs (theta+eta)/(1+beta)
def el_star(a, d=0.0, beta=1.0, phi=None):
    mu, sg = sev(a, mu0)
    A = P['lam0'] * (1 + a) ** P['theta'] * np.exp(mu + sg ** 2 / 2)
    kap = P['kappa'] * (1 + d) ** (P['phi'] if phi is None else phi)
    f = lambda s: s + A * (1 + kap * s) ** (-beta)
    s = minimize_scalar(f, bounds=(0, 50), method='bounded', options={'xatol': 1e-14}).x
    return A * (1 + kap * s) ** (-beta), A * P['lam0'] ** 0, (1 + kap * s) ** (-beta)
h = 1e-4
e_num = (np.log(el_star(np.exp(np.log(2.43) + h) - 1)[0]) - np.log(el_star(np.exp(np.log(2.43) - h) - 1)[0])) / (2 * h)
out['P1_elasticity'] = dict(numeric=float(e_num), formula=(P['theta'] + P['eta']) / (1 + P['beta']))
# Proposition 2: parity neutrality and failure when phi differs
base_el = el_star(0.0)[0]
out['P2'] = {f'phi={phi}': float(el_star(3.0, d=3.0, phi=phi)[0] / base_el) for phi in [0.4, 0.6, 0.8, 1.0, 1.2]}
# Proposition 3: maximum of g(r) on a fine grid, and numeric derivative of ln ORC
r = np.exp(np.linspace(np.log(1e-6), np.log(1e6), 2_000_001))
gr = 0.8 * r / ((np.e - 1 + r) * np.log(np.e - 1 + r))
lc = 0.5; b = 1.0; dl = 1e-6
ilm = lambda LC: np.log(np.e - 1 + (LC / b) ** 0.8)
num_el = (np.log(ilm(lc * np.exp(dl))) - np.log(ilm(lc * np.exp(-dl)))) / (2 * dl)
rr = (lc / b) ** 0.8
out['P3'] = dict(max_g=float(gr.max()), argmax_r=float(r[gr.argmax()]),
                 numeric_elasticity_at_LC_0_5=float(num_el), formula_at_LC_0_5=float(0.8 * rr / ((np.e - 1 + rr) * np.log(np.e - 1 + rr))))
# Proposition 4: SLA vs Monte Carlo VaR, and elasticities, across scenarios
rows = []
grid = [0, 0.5, 1, 1.56 ** 2 - 1, 3, 5, 9]
var_mc = {}
for a in grid:
    s = scenario(a, 0, mu0)
    mu, sg = sev(a, mu0)
    z = norm.ppf(1 - 0.001 / s['lam'])
    sla = np.exp(mu + sg * z)
    var_mc[a] = s['VaR']
    rows.append(dict(mult=1 + a, lam_eff=float(s['lam']), z=float(z), var_mc=float(s['VaR'] / BIC), var_sla=float(sla / BIC),
                     err_pct=float((sla / s['VaR'] - 1) * 100)))
out['P4_SLA_vs_MC'] = rows
# effective-frequency elasticity: numeric vs theta - beta(theta+eta)/(1+beta)
lam = lambda a: scenario(a, 0, mu0, nsim=10)['lam']
e_lam = (np.log(lam(np.exp(np.log(2.43) + 1e-3) - 1)) - np.log(lam(np.exp(np.log(2.43) - 1e-3) - 1))) / 2e-3
out['P4_eff_freq_elasticity'] = dict(numeric=float(e_lam), formula=P['theta'] - P['beta'] * (P['theta'] + P['eta']) / (1 + P['beta']))
# VaR elasticity: MC arc elasticity between 1 and 2.43 vs SLA formula evaluated at the midpoint
a0, a1 = 0.0, 1.56 ** 2 - 1
arc = np.log(var_mc[a1] / var_mc[a0]) / np.log((1 + a1) / (1 + a0))
am = np.sqrt((1 + a0) * (1 + a1)) - 1
mu, sg = sev(am, mu0); lam_m = scenario(am, 0, mu0, nsim=10)['lam']; z = norm.ppf(1 - 0.001 / lam_m)
dz = 0.001 / lam_m / norm.pdf(z)          # dz/dln(lambda)
pred = P['eta'] + P['zeta'] * (z - sg) + sg * dz * out['P4_eff_freq_elasticity']['formula']
out['P4_VaR_elasticity'] = dict(mc_arc=float(arc), sla_formula_midpoint=float(pred))
json.dump(out, open(os.path.join(here, '..', 'results', 'results_verify_props.json'), 'w'), indent=1)
print(json.dumps(out, indent=1))
