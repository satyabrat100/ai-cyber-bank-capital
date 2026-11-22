"""VCDB access: reads the raw validated JSON files if data/vcdb exists, otherwise the extract data/inputs/vcdb_extract.csv
(written by scripts/vcdb_extract.py at VCDB commit 5ce87b92). Returns a list of dicts."""
import csv, glob, json, os
def records(base='data'):
    raw = os.path.join(base, 'vcdb', 'data', 'json', 'validated')
    if os.path.isdir(raw):
        out = []
        for f in sorted(glob.glob(raw + '/*.json')):
            try: o = json.load(open(f))
            except Exception: continue
            v = o.get('victim', {}); v = v if isinstance(v, dict) else (v[0] if v else {})
            h = o.get('action', {}).get('hacking', {}); h = h if isinstance(h, dict) else {}
            amt = o.get('impact', {}).get('overall_amount')
            out.append(dict(file=os.path.basename(f), industry=str(v.get('industry', '')), year=o.get('timeline', {}).get('incident', {}).get('year'),
                            amount=amt if isinstance(amt, (int, float)) else None, hacking='hacking' in o.get('action', {}),
                            exploit_vuln='Exploit vuln' in (h.get('variety') or [])))
        return out
    rows = list(csv.DictReader(open(os.path.join(base, 'inputs', 'vcdb_extract.csv'))))
    for r in rows:
        r['year'] = int(r['year']) if r['year'] else None; r['amount'] = float(r['amount']) if r['amount'] else None
        r['hacking'] = r['hacking'] == '1'; r['exploit_vuln'] = r['exploit_vuln'] == '1'
    return rows
