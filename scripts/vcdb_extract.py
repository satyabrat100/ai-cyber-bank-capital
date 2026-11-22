"""Write data/inputs/vcdb_extract.csv from the raw VCDB files (one row per validated incident)."""
import csv, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vcdb_io import records
rs = records('data')
with open('data/inputs/vcdb_extract.csv', 'w', newline='') as fh:
    w = csv.writer(fh, lineterminator='\n'); w.writerow(['file', 'industry', 'year', 'amount', 'hacking', 'exploit_vuln'])
    for r in rs: w.writerow([r['file'], r['industry'], r['year'] or '', '' if r['amount'] is None else r['amount'], int(r['hacking']), int(r['exploit_vuln'])])
print(len(rs))
