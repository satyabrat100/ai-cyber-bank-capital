"""Monthly CVEs published whose CNA 'affected' vendor is in the enterprise list (denominator for the enterprise rate)."""
import json, glob, collections, sys
sys.path.insert(0, 'scripts')
ENT = ['microsoft', 'cisco', 'fortinet', 'ivanti', 'citrix', 'palo alto', 'paloalto', 'vmware', 'broadcom', 'oracle', 'sap', 'atlassian',
       'f5', 'juniper', 'sonicwall', 'checkpoint', 'check point', 'apache', 'red hat', 'redhat', 'ibm', 'adobe', 'google', 'apple',
       'progress', 'solarwinds', 'veeam', 'zoho', 'manageengine', 'sophos', 'barracuda', 'connectwise', 'jenkins', 'gitlab', 'samba', 'openssl', 'openssh']
c = collections.Counter()
for f in glob.glob('data/cvefull/cves/202[2-6]/*/*.json'):
    o = json.load(open(f)); m = o.get('cveMetadata', {})
    if m.get('state') != 'PUBLISHED' or not m.get('datePublished'): continue
    vs = [str(a.get('vendor', '')).lower() for a in o.get('containers', {}).get('cna', {}).get('affected', [])]
    if any(any(e in v for e in ENT) for v in vs): c[m['datePublished'][:7]] += 1
json.dump(dict(c), open('data/ent_monthly_published.json', 'w'), indent=1)
print(sum(v for k, v in c.items() if '2023-01' <= k <= '2026-10'))
