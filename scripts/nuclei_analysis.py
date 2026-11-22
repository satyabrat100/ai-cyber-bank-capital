"""Item 8: verified exploit-check templates. ProjectDiscovery nuclei-templates are reviewed by maintainers
before merge. Date = first commit adding a template file named CVE-*.yaml. Same NB2 count/rate design as Table 2."""
import json, re, os, sys, subprocess, collections, datetime as dt
import numpy as np, statsmodels.api as sm
from statsmodels.discrete.discrete_model import NegativeBinomial
base = 'data'
txt = open(sys.argv[1] if len(sys.argv) > 1 else '/tmp/nuclei_adds.txt').read().splitlines()
first = {}; d = None
for line in txt:
    if line.startswith('@@'): d = line[2:]; continue
    m = re.search(r'(CVE-\d{4}-\d+)\.yaml$', line)
    if m and d:
        c = m.group(1)
        if c not in first or d < first[c]: first[c] = d
pub = {}
for c in first:
    y, n = c.split('-')[1], c.split('-')[2]
    f = f'{base}/cvefull/cves/{y}/{n[:-3]}xxx/{c}.json'
    if os.path.exists(f):
        m = json.load(open(f)).get('cveMetadata', {})
        if m.get('datePublished'): pub[c] = m['datePublished'][:10]
den = json.load(open(f'{base}/cve_monthly_published.json'))
months = [f'{y}-{m:02d}' for y in (2023, 2024, 2025, 2026) for m in range(1, 13) if f'{y}-{m:02d}' <= '2026-10']
out = {'n_templates': len(first), 'matched': len(pub)}
for W in (30, 90):
    mm = [m for m in months if m <= ('2026-10' if W == 30 else '2026-08')]
    cnt = collections.Counter(p[:7] for c, p in pub.items() if 0 <= (dt.date.fromisoformat(first[c]) - dt.date.fromisoformat(p)).days <= W and p <= '2026-10-20')
    t = np.arange(len(mm), dtype=float); post = np.array([m >= '2026-05' for m in mm], float)
    X = sm.add_constant(np.column_stack([t, post])); y = np.array([cnt[m] for m in mm], float)
    for spec in ('count', 'rate'):
        off = np.log(np.array([den[m] for m in mm], float)) if spec == 'rate' else None
        r = NegativeBinomial(y, X, offset=off, loglike_method='nb2').fit(disp=0, maxiter=500, cov_type='HC1')
        ci = r.conf_int()[2]
        out[f'{W}d|{spec}'] = dict(irr=float(np.exp(r.params[2])), ci=[float(np.exp(ci[0])), float(np.exp(ci[1]))], p=float(r.pvalues[2]),
                                   alpha=float(r.params[3]), n=len(mm), pre_mean=float(y[post == 0].mean()), post_mean=float(y[post == 1].mean()))
        print(W, spec, {k: (round(v, 3) if isinstance(v, float) else v) for k, v in out[f'{W}d|{spec}'].items()})
json.dump(out, open(f'{base}/nuclei_results.json', 'w'), indent=1)
print(out['n_templates'], out['matched'])
