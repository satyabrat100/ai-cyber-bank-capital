"""Item 4/33: write the monthly panel used by every regression in Table 2, Appendix C and Section 8.3,
so all regressions can be re-run without downloading the raw repositories (see scripts/verify_tables.py)."""
import json, collections, re, os, datetime as dt, csv
base = 'data'
months = [f'{y}-{m:02d}' for y in (2023, 2024, 2025, 2026) for m in range(1, 13) if f'{y}-{m:02d}' <= '2026-10']
poc = json.load(open(f'{base}/poc_lags.json'))
kl = json.load(open(f'{base}/kev_lags.json'))
msf = json.load(open(f'{base}/msf_counts.json'))
den = json.load(open(f'{base}/cve_monthly_published.json'))
ent = json.load(open(f'{base}/ent_monthly_published.json'))
first = {}; d = None
for line in open(f'{base}/nuclei_adds.txt').read().splitlines():
    if line.startswith('@@'): d = line[2:]; continue
    m = re.search(r'(CVE-\d{4}-\d+)\.yaml$', line)
    if m and d and (m.group(1) not in first or d < first[m.group(1)]): first[m.group(1)] = d
npub = json.load(open(f'{base}/nuclei_cve_published.json')) if not os.path.isdir(f'{base}/cvefull') else {}
for c in (first if os.path.isdir(f'{base}/cvefull') else []):
    y, n = c.split('-')[1], c.split('-')[2]
    f = f'{base}/cvefull/cves/{y}/{n[:-3]}xxx/{c}.json'
    if os.path.exists(f):
        mm = json.load(open(f)).get('cveMetadata', {})
        if mm.get('datePublished'): npub[c] = mm['datePublished'][:10]
mp = json.load(open(f'{base}/mapping.json')) if False else None
def lagd(c, p): return (dt.date.fromisoformat(first[c]) - dt.date.fromisoformat(p)).days
cols = collections.OrderedDict()
cols['cves_published'] = {m: den.get(m, 0) for m in months}
cols['cves_published_enterprise'] = {m: ent.get(m, 0) for m in months}
cols['poc_30d'] = collections.Counter(r['pub'][:7] for r in poc if 0 <= r['lag'] <= 30 and r['pub'] <= '2026-10-20')
cols['poc_by30_incl_prepub'] = collections.Counter(r['pub'][:7] for r in poc if r['lag'] <= 30 and r['pub'] <= '2026-10-20')
cols['poc_7d'] = collections.Counter(r['pub'][:7] for r in poc if 0 <= r['lag'] <= 7 and r['pub'] <= '2026-10-20')
cols['poc_starred_30d'] = collections.Counter(r['pub'][:7] for r in poc if r['lag_star'] is not None and 0 <= r['lag_star'] <= 30 and r['pub'] <= '2026-10-20')
cols['kev_inclusion_30d_by_added'] = collections.Counter(r['added'][:7] for r in kl if 0 <= r['lag'] <= 30)
cols['metasploit_30d'] = collections.Counter(msf['fast30'])
cols['metasploit_90d'] = collections.Counter(msf['fast90'])
cols['nuclei_30d'] = collections.Counter(p[:7] for c, p in npub.items() if 0 <= lagd(c, p) <= 30 and p <= '2026-10-20')
cols['nuclei_90d'] = collections.Counter(p[:7] for c, p in npub.items() if 0 <= lagd(c, p) <= 90)
with open(f'{base}/monthly_panel.csv', 'w', newline='') as fh:
    w = csv.writer(fh, lineterminator='\n'); w.writerow(['month'] + list(cols))
    for m in months: w.writerow([m] + [cols[k].get(m, 0) for k in cols])
print(open(f'{base}/monthly_panel.csv').read()[:600])
