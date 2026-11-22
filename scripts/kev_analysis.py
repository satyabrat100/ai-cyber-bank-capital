import json, glob, sys, datetime as dt, collections
import numpy as np
base = sys.argv[1]
kev = json.load(open(base + '/kev/known_exploited_vulnerabilities.json'))['vulnerabilities']
pub = {}
for f in glob.glob(base + '/cvelist/cves/*/*/*.json'):
    o = json.load(open(f))
    m = o.get('cveMetadata', {})
    d = m.get('datePublished')
    if d: pub[m['cveId']] = d[:10]
rows = []
for x in kev:
    if x['dateAdded'] < '2023-01-01': continue
    p = pub.get(x['cveID'])
    if not p: continue
    a = dt.date.fromisoformat(x['dateAdded']); q = dt.date.fromisoformat(p)
    rows.append(dict(cve=x['cveID'], added=x['dateAdded'], published=p,
                     lag=(a - q).days, ransom=x['knownRansomwareCampaignUse']))
json.dump(rows, open(base + '/kev_lags.json', 'w'))
print('matched', len(rows))
def half(d): return d[:4] + ('H1' if d[5:7] <= '06' else 'H2')
g = collections.defaultdict(list)
for r in rows: g[half(r['added'])].append(r)
print('period  n  median_lag  share<=7d  share_new(<=30d)')
for k in sorted(g):
    L = np.array([r['lag'] for r in g[k]])
    print(k, len(L), int(np.median(L)), round((L <= 7).mean(), 3), round((L <= 30).mean(), 3))
