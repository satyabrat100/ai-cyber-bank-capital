import json, glob, sys, collections
import numpy as np, statsmodels.api as sm
base = sys.argv[1]
kev = {x['cveID']: x for x in json.load(open(base + '/kev/known_exploited_vulnerabilities.json'))['vulnerabilities']}
rows = json.load(open(base + '/kev_lags.json'))
cve = {}
for f in glob.glob(base + '/cvelist/cves/*/*/*.json'):
    o = json.load(open(f)); cid = o['cveMetadata']['cveId']
    cna = o.get('containers', {}).get('cna', {})
    desc = ' '.join(d.get('value', '') for d in cna.get('descriptions', []) if d.get('lang', '').startswith('en'))
    refs = cna.get('references', [])
    tags = [t for r in refs for t in r.get('tags', [])]
    cve[cid] = dict(desc_len=len(desc.split()), nrefs=len(refs), exploit_ref=int('exploit' in tags))
# AI-amenable: logic/web flaws exploitable from a text description (injection, traversal, auth, deserialization, SSRF, upload)
AMEN = {'CWE-78','CWE-77','CWE-89','CWE-94','CWE-22','CWE-23','CWE-35','CWE-502','CWE-918','CWE-287','CWE-306','CWE-288','CWE-434','CWE-611','CWE-917','CWE-1336','CWE-74','CWE-95','CWE-98','CWE-639','CWE-862','CWE-863','CWE-284','CWE-285','CWE-352','CWE-79'}
MEM = {'CWE-787','CWE-416','CWE-119','CWE-125','CWE-122','CWE-121','CWE-843','CWE-190','CWE-476','CWE-415','CWE-362','CWE-401','CWE-269','CWE-367'}
X, y, grp = [], [], []
for r in rows:
    cw = set(kev[r['cve']].get('cwes', []))
    am = int(bool(cw & AMEN)); me = int(bool(cw & MEM))
    if am == me: g = 'other'
    else: g = 'amenable' if am else 'memory'
    post = int(r['added'] >= '2026-05-01')
    t = (int(r['added'][:4]) - 2023) * 12 + int(r['added'][5:7])
    c = cve.get(r['cve'], {})
    r.update(group=g, post=post, t=t, **c)
out = {}
tab = {}
for g in ['amenable', 'memory', 'other']:
    for p in [0, 1]:
        s = [r for r in rows if r['group'] == g and r['post'] == p]
        tab[f'{g}_{p}'] = dict(n=len(s), share30=float(np.mean([r['lag'] <= 30 for r in s])) if s else None,
                               median_lag=float(np.median([r['lag'] for r in s])) if s else None)
out['table'] = tab
# DiD logit on amenable vs memory
s = [r for r in rows if r['group'] in ('amenable', 'memory')]
yy = np.array([r['lag'] <= 30 for r in s], float)
am = np.array([r['group'] == 'amenable' for r in s], float)
po = np.array([r['post'] for r in s], float); tt = np.array([r['t'] for r in s], float)
Xd = sm.add_constant(np.column_stack([tt, po, am, po * am]))
res = sm.Logit(yy, Xd).fit(disp=0, cov_type='HC1')
out['did'] = dict(n=len(s), or_post=float(np.exp(res.params[2])), p_post=float(res.pvalues[2]),
                  or_inter=float(np.exp(res.params[4])), p_inter=float(res.pvalues[4]),
                  ci_inter=[float(np.exp(res.conf_int()[4][0])), float(np.exp(res.conf_int()[4][1]))])
# Linear probability DiD for readable percentage points
ols = sm.OLS(yy, Xd).fit(cov_type='HC1')
out['did_lpm'] = dict(post_pp=float(ols.params[2] * 100), inter_pp=float(ols.params[4] * 100), p_inter=float(ols.pvalues[4]),
                      ci_inter_pp=[float(ols.conf_int()[4][0] * 100), float(ols.conf_int()[4][1] * 100)])
# Description length interaction (all rows with metadata)
s2 = [r for r in rows if 'desc_len' in r]
yy2 = np.array([r['lag'] <= 30 for r in s2], float)
dl = np.array([np.log1p(r['desc_len']) for r in s2]); dl = (dl - dl.mean()) / dl.std()
po2 = np.array([r['post'] for r in s2], float); tt2 = np.array([r['t'] for r in s2], float)
res2 = sm.Logit(yy2, sm.add_constant(np.column_stack([tt2, po2, dl, po2 * dl]))).fit(disp=0, cov_type='HC1')
out['desc'] = dict(n=len(s2), or_inter_per_sd=float(np.exp(res2.params[4])), p_inter=float(res2.pvalues[4]))
json.dump(out, open(base + '/mechanism_results_narrow.json', 'w'), indent=1)
print(json.dumps(out, indent=1))
