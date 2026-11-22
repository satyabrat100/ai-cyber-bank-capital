"""Item 20: sensitivity of the gap to the BIC calibration (baseline SA capital = f x baseline VaR) at M = 1.56, q = 99.9%."""
import json, numpy as np
from scipy.optimize import brentq
d = json.load(open('results/results_main.json'))
ilm = lambda lc, b: np.log(np.e - 1 + (lc / b) ** 0.8)
out = {}
for sp in ['freq_only', 'freq_sev']:
    r = d['main'][f'1.56|{sp}']; q = r['0.999']
    for f in [0.6, 0.8, 1.0, 1.2, 1.5]:
        bic = brentq(lambda b: b * ilm(15 * r['el0'], b) - f * q['var0'], 1e-9, 1e12)
        o0, o1 = bic * ilm(15 * r['el0'], bic), bic * ilm(15 * r['el1'], bic)
        out[f'{sp}|{f}'] = dict(ilm0=float(ilm(15 * r['el0'], bic)), orc_up=float(o1 / o0 - 1), gap_vs_baseline=float(q['var1'] / o1 / (q['var0'] / o0) - 1))
        print(sp, f, {k: round(v, 3) for k, v in out[f'{sp}|{f}'].items()})
json.dump(out, open('results/bic_sens.json', 'w'), indent=1)
