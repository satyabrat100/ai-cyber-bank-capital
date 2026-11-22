"""Item 9: compare our measures with GTIG on GTIG's own periods (calendar 2025 vs Jan-Aug 2026), monthly averages."""
import json, collections, datetime as dt, re
base = 'data'
poc = json.load(open(f'{base}/poc_lags.json'))
den = json.load(open(f'{base}/cve_monthly_published.json'))
kev = json.load(open(f'{base}/kev/known_exploited_vulnerabilities.json'))['vulnerabilities']
msf = json.load(open(f'{base}/msf_counts.json'))['fast30']
nuc_first = {}; d = None
for line in open('/tmp/nuclei_adds.txt').read().splitlines() if __import__('os').path.exists('/tmp/nuclei_adds.txt') else open(f'{base}/nuclei_adds.txt').read().splitlines():
    if line.startswith('@@'): d = line[2:]; continue
    m = re.search(r'(CVE-\d{4}-\d+)\.yaml$', line)
    if m and d and (m.group(1) not in nuc_first or d < nuc_first[m.group(1)]): nuc_first[m.group(1)] = d
kl = json.load(open(f'{base}/kev_lags.json'))
import os
npub = {}
for c in nuc_first:
    y, n = c.split('-')[1], c.split('-')[2]
    f = f'{base}/cvefull/cves/{y}/{n[:-3]}xxx/{c}.json'
    if y in ('2024', '2025', '2026') and os.path.exists(f):
        mm = json.load(open(f)).get('cveMetadata', {})
        if mm.get('datePublished'): npub[c] = mm['datePublished'][:10]
A = [f'2025-{m:02d}' for m in range(1, 13)]; B = [f'2026-{m:02d}' for m in range(1, 9)]
series = {
    'CVEs published': collections.Counter({k: v for k, v in den.items()}),
    'CVEs with exploit code within 30 days (PoC-in-GitHub)': collections.Counter(r['pub'][:7] for r in poc if 0 <= r['lag'] <= 30),
    'CVEs with starred exploit code within 30 days': collections.Counter(r['pub'][:7] for r in poc if r['lag_star'] is not None and 0 <= r['lag_star'] <= 30),
    'Metasploit modules within 30 days': collections.Counter(msf),
    'KEV additions (all, by date added)': collections.Counter(x['dateAdded'][:7] for x in kev),
    'KEV additions within 30 days of publication (by publication month)': collections.Counter(r['published'][:7] for r in kl if 0 <= r['lag'] <= 30),
    'Nuclei templates within 30 days of publication (by publication month)': collections.Counter(p[:7] for c, p in npub.items() if 0 <= (dt.date.fromisoformat(nuc_first[c]) - dt.date.fromisoformat(p)).days <= 30),
}
out = {}
for k, c in series.items():
    a = sum(c[m] for m in A) / 12; b = sum(c[m] for m in B) / 8
    out[k] = dict(per_month_2025=a, per_month_jan_aug_2026=b, ratio=b / a if a else None)
    print(f'{k:55s} {a:9.1f} {b:9.1f} {b / a if a else float("nan"):6.2f}')
out['GTIG observed exploited vulnerabilities'] = dict(per_month_2025=127 / 12, per_month_jan_aug_2026=141 / 8, ratio=(141 / 8) / (127 / 12))
print('GTIG', round(127 / 12, 1), round(141 / 8, 1), round((141 / 8) / (127 / 12), 2))
json.dump(out, open(f'{base}/gtig_matched.json', 'w'), indent=1)
