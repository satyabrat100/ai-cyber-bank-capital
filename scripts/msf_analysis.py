"""Metasploit exploit modules as a stricter 'working exploit' definition (item 8).
Module date = first commit adding the module file (history since Oct 2022); CVE refs from db/modules_metadata_base.json."""
import json, glob, sys, collections, datetime as dt
base = sys.argv[1]
meta = json.load(open(base + '/msf_meta.json'))
path_cves = {}
for k, v in meta.items():
    p = v.get('path', '').lstrip('/')
    cves = [r for r in v.get('references', []) if r.startswith('CVE-')]
    if p.startswith('modules/exploits/') and cves: path_cves[p] = cves
added = {}; cur = None
for line in open(base + '/msf_adds.txt'):
    line = line.strip()
    if line.startswith('DATE '): cur = line[5:]
    elif line.endswith('.rb') and cur:
        added[line] = min(added.get(line, cur), cur)
first = {}
for p, d in added.items():
    for c in path_cves.get(p, []):
        if c not in first or d < first[c]: first[c] = d
pubdate = {}
for f in glob.glob(base + '/cvefull/cves/*/*/*.json'):
    cid = f.rsplit('/', 1)[1][:-5]
    if cid in first:
        m = json.load(open(f)).get('cveMetadata', {})
        if m.get('datePublished'): pubdate[cid] = m['datePublished'][:10]
rows = []
for c, d in first.items():
    if c not in pubdate: continue
    p = pubdate[c]
    if not ('2023-01-01' <= p <= '2026-08-22'): continue        # full 90-day window
    lag = (dt.date.fromisoformat(d) - dt.date.fromisoformat(p)).days
    rows.append(dict(cve=c, pub=p, module=d, lag=lag))
f30 = collections.Counter(r['pub'][:7] for r in rows if r['lag'] <= 30)
f90 = collections.Counter(r['pub'][:7] for r in rows if r['lag'] <= 90)
print('exploit modules with CVE refs', len(path_cves), 'CVEs with module', len(first), 'matched in window', len(rows))
json.dump(dict(fast30=dict(f30), fast90=dict(f90)), open(base + '/msf_counts.json', 'w'))
pre = [m for m in sorted(set(f90) | set(f30)) if m < '2026-05']
print('per-month fast30 pre/post', sum(f30[m] for m in f30 if m < '2026-05') / 40, sum(f30[m] for m in f30 if m >= '2026-05') / 4)
print('per-month fast90 pre/post', sum(f90[m] for m in f90 if m < '2026-05') / 40, sum(f90[m] for m in f90 if m >= '2026-05') / 4)
import numpy as np, statsmodels.api as sm
from statsmodels.discrete.discrete_model import NegativeBinomial
months = [f'{y}-{m:02d}' for y in (2023, 2024, 2025, 2026) for m in range(1, 13) if f'{y}-{m:02d}' <= '2026-08']
den = json.load(open(base + '/cve_monthly_published.json'))
t = np.arange(len(months), dtype=float); post = np.array([m >= '2026-05' for m in months], float)
X = sm.add_constant(np.column_stack([t, post])); res = {}
for lab, c in [('fast30', f30), ('fast90', f90)]:
    y = np.array([c[m] for m in months], float)
    for spec, off in [('count', None), ('rate', np.log([den[m] for m in months]))]:
        r = NegativeBinomial(y, X, offset=off).fit(disp=0, maxiter=500, cov_type='HC1')
        res[f'{lab}|{spec}'] = dict(irr=float(np.exp(r.params[2])), ci=[float(np.exp(x)) for x in r.conf_int()[2]], p=float(r.pvalues[2]),
                                    alpha=float(r.params[3]), n=len(y))
        print('metasploit', lab, spec, {k: (round(v, 3) if isinstance(v, float) else v) for k, v in res[f'{lab}|{spec}'].items()})
json.dump(res, open(base + '/msf_results.json', 'w'), indent=1)
