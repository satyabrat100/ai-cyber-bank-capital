"""Hill estimator at several thresholds with bootstrap CIs and exceedance counts (item 11)."""
import json, glob, sys
import numpy as np
base = sys.argv[1]
fin, allx = [], []
import os; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); from vcdb_io import records
for o in records(base):
    a = o['amount']
    if not isinstance(a, (int, float)) or a <= 0 or a >= 1e10: continue
    allx.append(a)
    if o['industry'].startswith('52'): fin.append(a)
rng = np.random.default_rng(3)
def hill(x, k):
    x = np.sort(x)[::-1]; return 1 / np.mean(np.log(x[:k] / x[k]))
out = {}
for lab, x in [('fin', np.array(fin)), ('all', np.array(allx))]:
    rows = []
    for k in [5, 8, 10, 12, 15, 20, 25, 30, 40, 60, 80, 100]:
        if k >= len(x) - 1: continue
        bs = [hill(rng.choice(x, len(x)), k) for _ in range(2000)]
        rows.append(dict(k=k, share=k / len(x), threshold_usdm=float(np.sort(x)[::-1][k] / 1e6), alpha=float(hill(x, k)),
                         ci=[float(np.percentile(bs, 2.5)), float(np.percentile(bs, 97.5))]))
        print(lab, rows[-1])
    out[lab] = rows
json.dump(out, open(base + '/hill_thresholds.json', 'w'), indent=1)
