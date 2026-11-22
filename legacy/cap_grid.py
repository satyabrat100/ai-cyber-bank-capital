import json, sys, runpy, io, contextlib
import numpy as np
base = sys.argv[1]
sys.argv = ['x', base]
buf = io.StringIO()
src = open('scripts/robust_gap.py').read().split('# 1. Assumption-light')[0]
g = {}
exec(compile(src, 'robust_gap_head', 'exec'), g)
run, make_sampler, fin, eta_S = g['run'], g['make_sampler'], g['fin'], g['eta_S']
print('max observed financial loss (USD m):', end=' ')
import glob
mx = 0
for f in glob.glob(base + '/vcdb/data/json/validated/*.json'):
    try: o = json.load(open(f))
    except Exception: continue
    a = o.get('impact', {}).get('overall_amount')
    if isinstance(a, (int, float)) and str(o.get('victim', {}).get('industry', '')).startswith('52'): mx = max(mx, a)
print(mx / 1e6)
out = {}
for cap in [2500.0, 5000.0, 25000.0, np.inf]:
    for fam in ['lognormal', 'loglogistic']:
        if fam == 'lognormal':
            d = make_sampler('lognormal', sigma=fin['lognormal']['params'][0], cap=cap / fin['lognormal']['params'][2])
        else:
            d = make_sampler('loglogistic', c=fin['loglogistic']['params'][0], scale=fin['loglogistic']['params'][2], cap=cap)
        for lab, S in [('freq_only', 1.0), ('freq_sev', eta_S(1.56))]:
            r = run(d, 1.56, S, qs=(0.99, 0.995, 0.999))
            key = f'{fam}|cap={cap:g}|{lab}'
            out[key] = {str(q): round(v['gap'] * 100, 1) for q, v in r.items()}
            print(key, out[key])
json.dump(out, open(base + '/cap_grid.json', 'w'), indent=1)
