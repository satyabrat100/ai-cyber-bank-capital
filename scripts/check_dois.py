"""Item 30: resolve every DOI in the reference list through the Crossref/DataCite APIs and compare titles.
Run on any machine with internet access:  python3 scripts/check_dois.py"""
import json, urllib.request, difflib
REFS = [
 ('10.1257/aer.20130456', 'Systemic risk and stability in financial networks'),
 ('10.1016/j.jfs.2022.100989', 'The drivers of cyber risk'),
 ('10.1086/262109', 'Financial contagion'),
 ('10.1287/isre.1080.0226', "An empirical analysis of software vendors' patch release behavior"),
 ('10.1057/gpp.2014.19', 'Insurability of cyber risk'),
 ('10.1145/2382196.2382284', 'Before we knew it'),
 ('10.5089/9781484360750.001', 'Cyber risk for the financial sector'),
 ('10.1017/S0022109011000500', 'The determinants of operational risk in U.S. financial institutions'),
 ('10.1016/j.jfineco.2022.12.002', 'Pirates without borders'),
 ('10.1016/j.jbankfin.2021.106290', 'Artificial intelligence and systemic risk'),
 ('10.1093/cybsec/tyw003', 'Hype and heavy tails'),
 ('10.1016/j.jfineco.2021.10.007', 'Cyber risk and the U.S. financial system'),
 ('10.1016/j.ejor.2018.07.021', 'What are the actual costs of cyber risk events'),
 ('10.48550/arXiv.2404.08144', 'LLM agents can autonomously exploit one-day vulnerabilities'),
 ('10.1093/rfs/hhac024', 'Cybersecurity risk'),
 ('10.1016/j.jfi.2016.09.005', 'Why bank capital matters for monetary policy'),
 ('10.1145/581271.581274', 'The economics of information security investment'),
 ('10.1214/aos/1176343247', 'A simple general approach to inference about the tail of a distribution'),
 ('10.1016/j.jfineco.2019.05.019', 'Risk management, firm reputation, and the impact of successful cyberattacks'),
 ('10.1257/pandp.20191058', 'Some principles for regulating cyber risk'),
 ('10.1140/epjb/e2010-00120-8', 'Heavy-tailed distribution of cyber-risks'),
 ('10.1140/epjb/e2015-60754-4', 'The extreme risk of personal data breaches'),
]
def title(doi):
    for url in (f'https://api.crossref.org/works/{doi}', f'https://api.datacite.org/dois/{doi}'):
        try:
            d = json.load(urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'check_dois/1.0'}), timeout=20))
            if 'message' in d: return d['message']['title'][0]
            return d['data']['attributes']['titles'][0]['title']
        except Exception:
            continue
    return None
bad = 0
for doi, exp in REFS:
    t = title(doi)
    ok = t is not None and difflib.SequenceMatcher(None, exp.lower(), t.lower()[:len(exp) + 10]).ratio() > 0.8
    bad += not ok
    print(('OK  ' if ok else 'FAIL'), doi, '|', t)
print('failures:', bad)
