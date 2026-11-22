"""Point 8: independent evidence that exploit code is real. For CVEs with PoC-in-GitHub code within 30 days,
the share that (a) also receive a reviewed Metasploit module or nuclei template within 90 days, and
(b) are added to CISA KEV (confirmed exploitation in the wild) within 90 days of publication, before vs after May 2026."""
import json, re, collections, datetime as dt
import numpy as np
base = 'data'
poc = [r for r in json.load(open(f'{base}/poc_lags.json')) if 0 <= r['lag'] <= 30 and r['pub'] <= '2026-08-31']
kev = {r['cve']: r['lag'] for r in json.load(open(f'{base}/kev_lags.json'))}
msf = set(json.load(open(f'{base}/msf_meta.json')).keys()) if False else None
first = {}; d = None
for line in open(f'{base}/nuclei_adds.txt').read().splitlines():
    if line.startswith('@@'): d = line[2:]; continue
    m = re.search(r'(CVE-\d{4}-\d+)\.yaml$', line)
    if m and d and (m.group(1) not in first or d < first[m.group(1)]): first[m.group(1)] = d
import os
if os.path.exists(f'{base}/msf_meta.json'):
    meta = json.load(open(f'{base}/msf_meta.json'))
    red = {v.get('path', ''): [x for x in v.get('references', []) if x.startswith('CVE-')] for v in meta.values()}
else:
    red = json.load(open(f'{base}/msf_module_cves.json'))  # extract of msf_meta.json: module path -> CVE references
path_cves = {p.lstrip('/'): cv for p, cv in red.items() if p.lstrip('/').startswith('modules/exploits/') and cv}
added = {}; cur = None
for line in open(f'{base}/msf_adds.txt'):
    line = line.strip()
    if line.startswith('DATE '): cur = line[5:]
    elif line.endswith('.rb') and cur: added[line] = min(added.get(line, cur), cur)
msf_first = {}
for pth, dd in added.items():
    for c in path_cves.get(pth, []):
        if c not in msf_first or dd < msf_first[c]: msf_first[c] = dd
out = {}
for per, lo, hi in (('pre', '2023-01-01', '2026-04-30'), ('post', '2026-05-01', '2026-07-31')):
    s = [r for r in poc if lo <= r['pub'] <= hi]
    p = lambda r: dt.date.fromisoformat(r['pub'])
    kev90 = [r['cve'] in kev and 0 <= kev[r['cve']] <= 90 for r in s]
    nuc90 = [r['cve'] in first and 0 <= (dt.date.fromisoformat(first[r['cve']]) - p(r)).days <= 90 for r in s]
    msf90 = [r['cve'] in msf_first and 0 <= (dt.date.fromisoformat(msf_first[r['cve']]) - p(r)).days <= 90 for r in s]
    rev = [a or b for a, b in zip(nuc90, msf90)]
    out[per] = dict(n=len(s), kev90=float(np.mean(kev90)), nuclei90=float(np.mean(nuc90)), msf90=float(np.mean(msf90)), reviewed90=float(np.mean(rev)),
                    counts=dict(kev90=int(sum(kev90)), reviewed90=int(sum(rev))))
    print(per, {k: (round(v, 4) if isinstance(v, float) else v) for k, v in out[per].items()})
json.dump(out, open('results/poc_crossval.json', 'w'), indent=1)
