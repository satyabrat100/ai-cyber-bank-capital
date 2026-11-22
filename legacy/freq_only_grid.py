import sys, json
src = open('scripts/robust_gap.py').read().split('# 1. Assumption-light')[0]
sys.argv = ['x', sys.argv[1]]
g = {}; exec(compile(src, 'rg', 'exec'), g)
run, ms = g['run'], g['make_sampler']
out = {}
for lab, M in [('CI low 1.27', 1.27), ('central 1.56', 1.56), ('CI high 1.90', 1.90), ('India banking 1.22', 1.223), ('India scanning 1.31', 1.315), ('India all-sector 1.44', 1.442)]:
    r = run(ms('lognormal', sigma=3.09), M, 1.0)[0.999]
    out[lab] = {k: round(float(v) * 100, 1) for k, v in r.items()}
    print(lab, out[lab])
json.dump(out, open(sys.argv[1] + '/freq_only_grid.json', 'w'), indent=1)
