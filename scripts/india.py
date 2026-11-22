"""Table 5: Indian indicators (CERT-In national incidents; RBI CPFIR payment frauds) from data/india.json."""
import json
d = json.load(open('data/india.json'))
c = d['certin_national']
print('CERT-In incidents', c)
print('growth', {y: round(c[y] / c[str(int(y) - 1)] - 1, 3) for y in list(c)[1:]})
m = d['cpfir_monthly']
for fy, (a, z) in {'FY24': ('2023-04', '2024-03'), 'FY25': ('2024-04', '2025-03'), 'FY26': ('2025-04', '2026-03')}.items():
    r = [x for x in m if a <= x[0] <= z]
    print(fy, 'frauds (lakh) %.1f' % sum(x[1] for x in r), 'value (Rs crore) %d' % sum(x[2] for x in r))
