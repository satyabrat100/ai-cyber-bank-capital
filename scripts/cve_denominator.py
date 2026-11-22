"""Monthly count of published CVEs (complete CVE List V5, IDs 2022-2026) and exploit-code rates (items 2, 7)."""
import json, glob, sys, collections
base = sys.argv[1]
pub = collections.Counter(); rejected = 0; n = 0
for f in glob.glob(base + '/cvefull/cves/*/*/*.json'):
    n += 1
    try: m = json.load(open(f)).get('cveMetadata', {})
    except Exception: continue
    if m.get('state') != 'PUBLISHED': rejected += 1; continue
    d = m.get('datePublished')
    if d and '2023-01' <= d[:7] <= '2026-10': pub[d[:7]] += 1
months = sorted(pub)
json.dump(dict(pub), open(base + '/cve_monthly_published.json', 'w'), indent=1)
poc = json.load(open(base + '/poc_lags.json'))
f30 = collections.Counter(r['pub'][:7] for r in poc if r['lag'] <= 30)
f7 = collections.Counter(r['pub'][:7] for r in poc if r['lag'] <= 7)
print('files', n, 'rejected', rejected, 'published 2023-01..2026-10', sum(pub.values()))
def period(a, b):
    ms = [m for m in months if a <= m <= b]
    P = sum(pub[m] for m in ms); A = sum(f30[m] for m in ms); B = sum(f7[m] for m in ms)
    return dict(months=len(ms), cves_per_month=P / len(ms), code30_per_month=A / len(ms), code7_per_month=B / len(ms),
                rate30_pct=100 * A / P, rate7_pct=100 * B / P)
res = {'pre (2023-01..2026-04)': period('2023-01', '2026-04'), 'post (2026-05..2026-10)': period('2026-05', '2026-10'),
       '2025': period('2025-01', '2025-12'), '2026-01..04': period('2026-01', '2026-04')}
for k, v in res.items(): print(k, {a: round(b, 3) for a, b in v.items()})
print({m: pub[m] for m in months[-14:]})
json.dump(res, open(base + '/denominator_summary.json', 'w'), indent=1)
