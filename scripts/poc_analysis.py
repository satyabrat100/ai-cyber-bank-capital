"""Disclosure-to-first-public-exploit-code lag, from PoC-in-GitHub (independent of CISA)."""
import json, glob, os, sys, datetime as dt, collections
import numpy as np, statsmodels.api as sm
base = sys.argv[1]
AMEN = {'CWE-78','CWE-77','CWE-89','CWE-94','CWE-22','CWE-23','CWE-35','CWE-502','CWE-918','CWE-287','CWE-306','CWE-288','CWE-434','CWE-611','CWE-917','CWE-1336','CWE-74','CWE-95','CWE-98','CWE-639','CWE-862','CWE-863','CWE-284','CWE-285','CWE-352','CWE-79'}
MEM = {'CWE-787','CWE-416','CWE-119','CWE-125','CWE-122','CWE-121','CWE-843','CWE-190','CWE-476','CWE-415','CWE-362','CWE-401','CWE-269','CWE-367'}
def cwes(o):
    out = set()
    conts = [o.get('containers', {}).get('cna', {})] + o.get('containers', {}).get('adp', [])
    for c in conts:
        for pt in c.get('problemTypes', []):
            for d in pt.get('descriptions', []):
                if d.get('cweId'): out.add(d['cweId'])
    return out
rec = {}
for f in glob.glob(base + '/cvelist/cves/*/*/*.json'):
    o = json.load(open(f)); m = o.get('cveMetadata', {})
    if m.get('state') != 'PUBLISHED' or not m.get('datePublished'): continue
    rec[m['cveId']] = (m['datePublished'][:10], cwes(o))
rows = []
for y in ['2023', '2024', '2025', '2026']:
    for f in os.listdir(f'{base}/poc/{y}'):
        cid = f[:-5]
        if cid not in rec: continue
        repos = json.load(open(f'{base}/poc/{y}/{f}'))
        if not repos: continue
        first_all = min(r['created_at'][:10] for r in repos)
        starred = [r['created_at'][:10] for r in repos if r.get('stargazers_count', 0) >= 1]
        pub, cw = rec[cid]
        g = 'amenable' if (cw & AMEN and not cw & MEM) else ('memory' if (cw & MEM and not cw & AMEN) else 'other')
        p = dt.date.fromisoformat(pub)
        rows.append(dict(cve=cid, pub=pub, group=g,
                         lag=(dt.date.fromisoformat(first_all) - p).days,
                         lag_star=(dt.date.fromisoformat(min(starred)) - p).days if starred else None))
rows = [r for r in rows if '2023-01-01' <= r['pub'] <= '2026-10-20']
json.dump(rows, open(base + '/poc_lags.json', 'w'))
print('CVEs with PoC, published 2023-01..2026-10-20:', len(rows))
months = sorted({r['pub'][:7] for r in rows})
t = np.arange(len(months)); post = np.array([m >= '2026-05' for m in months], float)
out = {'n': len(rows)}
def nb(y, X):
    r = sm.GLM(y, X, family=sm.families.NegativeBinomial(alpha=0.1)).fit(cov_type='HC1')
    return r
for lab, key, W in [('fast30_all', 'lag', 30), ('fast7_all', 'lag', 7), ('fast30_starred', 'lag_star', 30)]:
    c = collections.Counter(r['pub'][:7] for r in rows if r[key] is not None and r[key] <= W)
    y = np.array([c[m] for m in months])
    res = nb(y, sm.add_constant(np.column_stack([t, post])))
    out[lab] = dict(pre=float(y[post == 0].mean()), post=float(y[post == 1].mean()),
                    irr=float(np.exp(res.params[2])), ci=[float(np.exp(x)) for x in res.conf_int()[2]],
                    p=float(res.pvalues[2]), trend_pct_yr=float((np.exp(12 * res.params[1]) - 1) * 100))
    if lab == 'fast30_all': out['monthly_fast30'] = dict(zip(months, y.tolist()))
# DiD on monthly counts by group (amenable vs memory), group-specific trends
G = []
for g in ['amenable', 'memory']:
    c = collections.Counter(r['pub'][:7] for r in rows if r['group'] == g and r['lag'] <= 30)
    for i, m in enumerate(months):
        G.append((c[m], i, float(m >= '2026-05'), float(g == 'amenable')))
G = np.array(G)
X = sm.add_constant(np.column_stack([G[:, 1], G[:, 2], G[:, 3], G[:, 1] * G[:, 3], G[:, 2] * G[:, 3]]))
res = nb(G[:, 0], X)
out['did_counts'] = dict(irr_post_memory=float(np.exp(res.params[2])), p_post_memory=float(res.pvalues[2]),
                         irr_extra_amenable=float(np.exp(res.params[5])), ci=[float(np.exp(x)) for x in res.conf_int()[5]],
                         p=float(res.pvalues[5]))
for g in ['amenable', 'memory', 'other']:
    pre = [r for r in rows if r['group'] == g and r['pub'] < '2026-05']
    po = [r for r in rows if r['group'] == g and r['pub'] >= '2026-05']
    f = lambda s: collections.Counter(r['pub'][:7] for r in s if r['lag'] <= 30)
    mp = [m for m in months if m < '2026-05']; mq = [m for m in months if m >= '2026-05']
    out['group_' + g] = dict(fast30_per_month_pre=float(np.mean([f(pre)[m] for m in mp])),
                             fast30_per_month_post=float(np.mean([f(po)[m] for m in mq])))
# Median lag among CVEs with a PoC within 90 days, publication up to 2026-08-22 (full 90-day window)
def med(a, b):
    L = [max(r['lag'], 0) for r in rows if a <= r['pub'] < b and r['lag'] <= 90]
    return float(np.median(L)), len(L)
out['median_lag90'] = {'2023': med('2023-01-01', '2024-01-01'), '2024': med('2024-01-01', '2025-01-01'),
                       '2025': med('2025-01-01', '2026-01-01'), '2026-01..04': med('2026-01-01', '2026-05-01'),
                       '2026-05..08': med('2026-05-01', '2026-08-23')}
json.dump(out, open(base + '/poc_results.json', 'w'), indent=1)
print(json.dumps({k: v for k, v in out.items() if k != 'monthly_fast30'}, indent=1))
print(out['monthly_fast30'])
