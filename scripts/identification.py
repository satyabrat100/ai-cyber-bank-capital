"""Stronger empirical identification (tests for an AI-specific effect, Section 5.8).
Three designs, all on CVEs published January 2023 - September 2026 (complete 30-day windows):
 A. Difference-in-differences by exposure to AI code analysis. AI models read source code, so CVEs in open-source
    software (CVE record names a source repository, package or code-host reference, or GitHub is the CNA) are more
    exposed than CVEs in closed-source products. NB2 on group-month counts of CVEs with exploit code within 30 days,
    offset log(CVEs published in the group-month), group effects, group-specific linear trends, and the interaction
    open x post (post = May 2026 onwards). Event study: open x half-year interactions relative to H2 2025.
 B. Direct AI involvement. CVE records whose credits name an AI tool or AI security company (strict list).
    Exploit-code and KEV rates of AI-credited CVEs vs other CVEs published in the same months (July 2025 - September
    2026), with a logit that includes month fixed effects.
 C. Dose-response. Monthly exploit-code counts on the monthly number of AI-credited CVEs, controlling for log CVEs
    published and trend."""
import json, glob, re, os, collections, datetime as dt, warnings
import numpy as np, statsmodels.api as sm
from statsmodels.discrete.discrete_model import NegativeBinomial, Logit
warnings.filterwarnings('ignore')
base = 'data'
AI = re.compile(r'big sleep|xbow|claude|anthropic|openai|\bgpt-?\d|codex|gemini|naptime|\baisle\b|depthfirst|zeropath|vulnhuntr|ai agent|ai-assisted|ai assisted|artificial intelligence|\bllm\b', re.I)
CODEHOST = re.compile(r'github\.com/|gitlab\.com/|bitbucket\.org/|sourceforge\.net/|git\.kernel\.org|pypi\.org|npmjs\.com|crates\.io|rubygems\.org|packagist\.org|pkg\.go\.dev', re.I)
poc = {r['cve']: r['lag'] for r in json.load(open(f'{base}/poc_lags.json'))}
kev = {r['cve']: r['lag'] for r in json.load(open(f'{base}/kev_lags.json'))}
rows = []
cache = f'{base}/cve_flags.json'
if os.path.exists(cache):
    rows = json.load(open(cache))
else:
    for f in glob.glob(f'{base}/cvefull/cves/202[2-6]/*/*.json'):
        o = json.load(open(f)); m = o.get('cveMetadata', {})
        if m.get('state') != 'PUBLISHED' or not m.get('datePublished'): continue
        pub = m['datePublished'][:10]
        if not ('2023-01-01' <= pub <= '2026-09-30'): continue
        cna = o.get('containers', {}).get('cna', {})
        aff = cna.get('affected', [])
        refs = ' '.join(r.get('url', '') for r in cna.get('references', []))
        open_src = (m.get('assignerShortName', '') == 'GitHub_M' or any(a.get('repo') or a.get('collectionURL') or a.get('packageName') for a in aff)
                    or bool(CODEHOST.search(refs)))
        linux = any(str(a.get('vendor', '')).lower() == 'linux' for a in aff)
        credits = ' '.join(str(c.get('value', '')) for c in cna.get('credits', []))
        rows.append(dict(cve=m['cveId'], pub=pub, open=bool(open_src), linux=linux, ai=bool(AI.search(credits))))
    json.dump(rows, open(cache, 'w'))
for r in rows:
    l = poc.get(r['cve']); k = kev.get(r['cve'])
    r['poc30'] = l is not None and 0 <= l <= 30
    r['kev90'] = k is not None and 0 <= k <= 90
months = [f'{y}-{m:02d}' for y in (2023, 2024, 2025, 2026) for m in range(1, 13) if f'{y}-{m:02d}' <= '2026-09']
out = {'n_cves': len(rows), 'share_open': float(np.mean([r['open'] for r in rows])), 'n_ai_credited': int(sum(r['ai'] for r in rows))}
print('CVEs', len(rows), 'open share %.3f' % out['share_open'], 'AI-credited', out['n_ai_credited'])

# ---------- A. DiD open vs closed (Linux kernel excluded: automated CVE assignment, no exploitation per GTIG) ----------
def did(sample_rows, label):
    n = collections.Counter(); y = collections.Counter()
    for r in sample_rows:
        g = 'open' if r['open'] else 'closed'; n[(g, r['pub'][:7])] += 1; y[(g, r['pub'][:7])] += r['poc30']
    Y, X, OFF, keys = [], [], [], []
    for g in ('closed', 'open'):
        for i, mth in enumerate(months):
            if n[(g, mth)] == 0: continue
            o_ = float(g == 'open'); post = float(mth >= '2026-05')
            X.append([1.0, o_, i, i * o_, post, post * o_]); Y.append(y[(g, mth)]); OFF.append(np.log(n[(g, mth)])); keys.append((g, mth))
    res = NegativeBinomial(np.array(Y, float), np.array(X), offset=np.array(OFF), loglike_method='nb2').fit(disp=0, maxiter=1000, cov_type='HC1')
    ci = res.conf_int()
    r = dict(did_irr=float(np.exp(res.params[5])), did_ci=[float(np.exp(ci[5][0])), float(np.exp(ci[5][1]))], did_p=float(res.pvalues[5]),
             closed_post_irr=float(np.exp(res.params[4])), closed_post_ci=[float(np.exp(ci[4][0])), float(np.exp(ci[4][1]))],
             open_post_irr=float(np.exp(res.params[4] + res.params[5])), n_obs=len(Y))
    for g in ('closed', 'open'):
        pre = [mm for mm in months if mm < '2026-05']; pst = [mm for mm in months if mm >= '2026-05']
        r[f'rate_{g}_pre'] = sum(y[(g, mm)] for mm in pre) / max(1, sum(n[(g, mm)] for mm in pre))
        r[f'rate_{g}_post'] = sum(y[(g, mm)] for mm in pst) / max(1, sum(n[(g, mm)] for mm in pst))
        r[f'cves_{g}_pre_pm'] = sum(n[(g, mm)] for mm in pre) / len(pre); r[f'cves_{g}_post_pm'] = sum(n[(g, mm)] for mm in pst) / len(pst)
    print(label, {k: (round(v, 4) if isinstance(v, float) else v) for k, v in r.items()})
    return r, n, y
nolinux = [r for r in rows if not r['linux']]
out['did_rate'], n, y = did(nolinux, 'DiD (rate, excl. Linux kernel)')
out['did_rate_all'], _, _ = did(rows, 'DiD (rate, all CVEs)')
# event study: open x half-year, baseline H2 2025, group-specific trends excluded (pre-trends shown directly)
def half(mth): return f"{mth[:4]}H{1 if int(mth[5:]) <= 6 else 2}"
halves = sorted({half(m) for m in months}); basep = '2025H2'
Y, X, OFF = [], [], []
for g in ('closed', 'open'):
    for i, mth in enumerate(months):
        if n[(g, mth)] == 0: continue
        o_ = float(g == 'open')
        row = [1.0, o_] + [float(half(mth) == h) for h in halves if h != halves[0]] + [o_ * float(half(mth) == h) for h in halves if h != basep]
        X.append(row); Y.append(y[(g, mth)]); OFF.append(np.log(n[(g, mth)]))
res = NegativeBinomial(np.array(Y, float), np.array(X), offset=np.array(OFF), loglike_method='nb2').fit(disp=0, maxiter=2000, cov_type='HC1')
k0 = 2 + len(halves) - 1; ci = res.conf_int(); es = {}
for j, h in enumerate([h for h in halves if h != basep]):
    es[h] = dict(irr=float(np.exp(res.params[k0 + j])), ci=[float(np.exp(ci[k0 + j][0])), float(np.exp(ci[k0 + j][1]))])
out['event_study'] = es
print('event study (open/closed rate ratio relative to 2025H2):', {h: round(v['irr'], 2) for h, v in es.items()})

# ---------- B. AI-credited CVEs ----------
win = [r for r in rows if r['pub'] >= '2025-07-01']
ai = [r for r in win if r['ai']]; oth = [r for r in win if not r['ai']]
def rate_ci(xs, key):
    k = sum(x[key] for x in xs); nn = len(xs); p = k / nn; se = np.sqrt(p * (1 - p) / nn); return dict(k=k, n=nn, rate=p, ci=[max(0, p - 1.96 * se), p + 1.96 * se])
out['ai_credited'] = dict(poc30_ai=rate_ci(ai, 'poc30'), poc30_other=rate_ci(oth, 'poc30'),
                          kev90_ai=rate_ci([r for r in ai if r['pub'] <= '2026-07-31'], 'kev90'), kev90_other=rate_ci([r for r in oth if r['pub'] <= '2026-07-31'], 'kev90'))
mlist = sorted({r['pub'][:7] for r in win})
Xl = np.array([[1.0, float(r['ai'])] + [float(r['pub'][:7] == m) for m in mlist[1:]] for r in win]); Yl = np.array([float(r['poc30']) for r in win])
lg = Logit(Yl, Xl).fit(disp=0, maxiter=200, cov_type='HC1'); cl = lg.conf_int()
out['ai_credited']['logit_or'] = dict(or_=float(np.exp(lg.params[1])), ci=[float(np.exp(cl[1][0])), float(np.exp(cl[1][1]))], p=float(lg.pvalues[1]))
print('AI-credited:', {k: (v if not isinstance(v, dict) else {kk: (round(vv, 4) if isinstance(vv, float) else vv) for kk, vv in v.items()}) for k, v in out['ai_credited'].items()})

# ---------- C. Dose-response ----------
cnt = collections.Counter(r['pub'][:7] for r in rows); aic = collections.Counter(r['pub'][:7] for r in rows if r['ai']); pc = collections.Counter(r['pub'][:7] for r in rows if r['poc30'])
Yd = np.array([pc[m] for m in months], float); t = np.arange(len(months), dtype=float)
Xd = sm.add_constant(np.column_stack([t, np.log(np.array([cnt[m] for m in months], float)), np.log1p(np.array([aic[m] for m in months], float))]))
rd = NegativeBinomial(Yd, Xd, loglike_method='nb2').fit(disp=0, maxiter=500, cov_type='HC1'); cd = rd.conf_int()
out['dose'] = dict(elasticity_ai=float(rd.params[3]), ci=[float(cd[3][0]), float(cd[3][1])], p=float(rd.pvalues[3]),
                   elasticity_cves=float(rd.params[2]), ci_cves=[float(cd[2][0]), float(cd[2][1])])
print('dose-response:', {k: (round(v, 3) if isinstance(v, float) else [round(z, 3) for z in v]) for k, v in out['dose'].items()})
json.dump(out, open('results/identification.json', 'w'), indent=1)
