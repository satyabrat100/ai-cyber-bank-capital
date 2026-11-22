"""Item 13: evidence for mapping vulnerability measures to bank incident frequency.
(a) Share s of financial-sector incidents caused by exploiting a vulnerability (VCDB hacking variety 'Exploit vuln');
    incidents caused by other routes (phishing, stolen credentials, insiders, errors) do not scale with CVE counts,
    so M_bank = 1 + s (M_vuln - 1).
(b) Exploit-code counts and rates restricted to enterprise products that banks run (vendor list below)."""
import json, glob, os, collections, datetime as dt
import numpy as np, statsmodels.api as sm
from statsmodels.discrete.discrete_model import NegativeBinomial
base = 'data'
# (a) VCDB
tot = collections.Counter(); ex = collections.Counter()
for f in glob.glob(f'{base}/vcdb/data/json/validated/*.json'):
    o = json.load(open(f))
    ind = [str(v.get('industry', '')) for v in [o.get('victim', {})]] if isinstance(o.get('victim'), dict) else [str(v.get('industry', '')) for v in o.get('victim', [])]
    fin = any(i.startswith('52') for i in ind)
    yr = o.get('timeline', {}).get('incident', {}).get('year')
    hv = o.get('action', {}).get('hacking', {}).get('variety', []) if isinstance(o.get('action', {}).get('hacking'), dict) else []
    vecs = o.get('action', {}).get('hacking', {}).get('vector', []) if isinstance(o.get('action', {}).get('hacking'), dict) else []
    exploit = 'Exploit vuln' in hv or 'Exploit misconfig' in hv and False
    for grp, ok in (('fin', fin), ('all', True)):
        if not ok: continue
        tot[grp] += 1; ex[grp] += exploit
        if yr and yr >= 2015: tot[f'{grp}_2015+'] += 1; ex[f'{grp}_2015+'] += exploit
        if 'hacking' in o.get('action', {}): tot[f'{grp}_hacking'] += 1; ex[f'{grp}_hacking'] += exploit
out = {'vcdb': {k: dict(n=tot[k], exploit=ex[k], share=ex[k] / tot[k]) for k in tot}}
for k, v in out['vcdb'].items(): print('VCDB', k, v)
# (b) enterprise vendors
ENT = ['microsoft', 'cisco', 'fortinet', 'ivanti', 'citrix', 'palo alto', 'paloalto', 'vmware', 'broadcom', 'oracle', 'sap', 'atlassian',
       'f5', 'juniper', 'sonicwall', 'checkpoint', 'check point', 'apache', 'red hat', 'redhat', 'ibm', 'adobe', 'google', 'apple',
       'progress', 'solarwinds', 'veeam', 'zoho', 'manageengine', 'sophos', 'barracuda', 'connectwise', 'jenkins', 'gitlab', 'samba', 'openssl', 'openssh']
poc = json.load(open(f'{base}/poc_lags.json'))
def vendors(c):
    y, n = c.split('-')[1], c.split('-')[2]
    f = f'{base}/cvefull/cves/{y}/{n[:-3]}xxx/{c}.json'
    if not os.path.exists(f): return set()
    o = json.load(open(f)); vs = set()
    for a in o.get('containers', {}).get('cna', {}).get('affected', []):
        vs.add(str(a.get('vendor', '')).lower())
    return vs
ent = {}
for r in poc:
    vs = vendors(r['cve']); ent[r['cve']] = any(any(e in v for e in ENT) for v in vs)
den = json.load(open(f'{base}/cve_monthly_published.json'))
den_ent = json.load(open(f'{base}/ent_monthly_published.json'))
den_oth = {m: den[m] - den_ent.get(m, 0) for m in den}
months = [f'{y}-{m:02d}' for y in (2023, 2024, 2025, 2026) for m in range(1, 13) if f'{y}-{m:02d}' <= '2026-09']
t = np.arange(len(months), dtype=float); post = np.array([m >= '2026-05' for m in months], float)
X = sm.add_constant(np.column_stack([t, post]))
for lab, keep in (('enterprise', True), ('other', False)):
    c = collections.Counter(r['pub'][:7] for r in poc if 0 <= r['lag'] <= 30 and ent[r['cve']] == keep and r['pub'] <= '2026-10-20')
    y = np.array([c[m] for m in months], float)
    for spec in ('count', 'rate'):
        dd = den_ent if keep else den_oth
        off = np.log(np.array([dd[m] for m in months], float)) if spec == 'rate' else None
        res = NegativeBinomial(y, X, offset=off, loglike_method='nb2').fit(disp=0, maxiter=500, cov_type='HC1')
        ci = res.conf_int()[2]
        out[f'{lab}|{spec}'] = dict(irr=float(np.exp(res.params[2])), ci=[float(np.exp(ci[0])), float(np.exp(ci[1]))], p=float(res.pvalues[2]),
                                    pre_mean=float(y[post == 0].mean()), post_mean=float(y[post == 1].mean()))
        print(lab, spec, {k: (round(v, 3) if isinstance(v, float) else [round(z, 2) for z in v] if isinstance(v, list) else v) for k, v in out[f'{lab}|{spec}'].items()})
json.dump(out, open(f'{base}/mapping.json', 'w'), indent=1)
