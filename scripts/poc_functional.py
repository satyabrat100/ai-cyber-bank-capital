"""Point 8: static functionality check of exploit repositories (nothing is executed).
Same random sample as poc_quality.py (200 pre: Jan 2025-Apr 2026; 200 post drawn from May-Oct 2026; the 26 post CVEs published in October 2026 are dropped below so that the post sample ends in September 2026, like every regression). Each first-qualifying
repository is shallow-cloned into a scratch directory and checked file by file:
  syntax  - parsed without running: Python (ast.parse), shell (bash -n), JavaScript (node --check),
            Ruby (ruby -c), C/C++ (gcc -fsyntax-only), YAML (safe_load; nuclei template structure)
  target  - code that sends input to a target: HTTP/socket/process APIs, nuclei request blocks
  specific- code names the affected vendor or product from the CVE record, or the CVE ID, AND carries a payload
            or request body/path (not only a version banner check)
  suspect - obfuscation or dropper patterns (long base64 blobs, powershell -enc, eval/exec of decoded data,
            downloads of executables)
Levels: 0 no code; 1 code that fails parsing or has no target interaction; 2 valid code that interacts with a target;
3 level 2 plus CVE/product-specific payload ('plausibly functional'). Static checks cannot prove an exploit works."""
import warnings; warnings.filterwarnings('ignore')
import json, os, re, subprocess, shutil, collections, random, sys
import numpy as np, yaml
base = 'data'; work = '/tmp/pocf'; os.makedirs(work, exist_ok=True)
q = json.load(open(f'{base}/poc_quality.json'))
EXT = {'.py': 'py', '.sh': 'sh', '.bash': 'sh', '.js': 'js', '.mjs': 'js', '.rb': 'rb', '.c': 'c', '.cpp': 'c', '.cc': 'c',
       '.yaml': 'yaml', '.yml': 'yaml', '.go': 'go', '.java': 'java', '.php': 'php', '.ps1': 'ps1', '.pl': 'pl', '.rs': 'rs', '.cs': 'cs', '.html': 'html', '.xml': 'xml', '.ts': 'ts'}
NET = re.compile(r'requests\.(get|post|put|request|Session)|urllib|http\.client|httpx|aiohttp|socket\.|pwn\b|remote\(|curl\b|wget\b|fetch\(|axios|net/http|http\.NewRequest|HttpClient|Invoke-WebRequest|Net::HTTP|send_request_cgi|subprocess|os\.system|Runtime\.getRuntime|ldap://|rmi://|smb|paramiko|websocket', re.I)
PAY = re.compile(r'payload|exploit|shell|cmd|command|inject|overflow|rop|gadget|deserial|traversal|\.\./|<script|union\s+select|\$\{jndi|POST\s|/api/|/cgi-bin/|data\s*=|json\s*=|body\s*:', re.I)
SUS = re.compile(r'[A-Za-z0-9+/]{600,}={0,2}|powershell[^\n]{0,40}-e(nc|ncodedcommand)?\s|eval\(\s*(base64|atob|bytes\.fromhex|codecs\.decode)|exec\(\s*(base64|bytes\.fromhex|zlib|marshal)|\.exe["\']|Invoke-Expression|IEX\s*\(', re.I)
def syntax(path, kind):
    try:
        if kind == 'py':
            import ast; ast.parse(open(path, 'rb').read()); return True
        if kind == 'yaml':
            d = yaml.safe_load(open(path, 'rb')); return d is not None
        cmd = {'sh': ['bash', '-n', path], 'js': ['node', '--check', path], 'rb': ['ruby', '-c', path], 'c': ['gcc', '-fsyntax-only', '-w', path]}.get(kind)
        if cmd is None: return None
        return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20).returncode == 0
    except Exception:
        return False
def products(cve):
    y, n = cve.split('-')[1], cve.split('-')[2]
    f = f'{base}/cvefull/cves/{y}/{n[:-3]}xxx/{cve}.json'
    names = set()
    if os.path.exists(f):
        for a in json.load(open(f)).get('containers', {}).get('cna', {}).get('affected', []):
            for k in ('vendor', 'product'):
                v = str(a.get(k, '')).strip().lower()
                if len(v) >= 4 and v not in ('n/a', 'unknown', 'unspecified'): names.add(v)
    return names
out = {}
CK = 'results/poc_functional_checkpoint.jsonl'
done = {}
if os.path.exists(CK):
    for line in open(CK):
        x = json.loads(line); done[(x['per'], x['repo'], x['cve'])] = x
for per in ('pre', 'post'):
    res = []
    for it in q[per]['items']:
        repo, cve = it['repo'], it['cve']
        if (per, repo, cve) in done:
            res.append({k: v for k, v in done[(per, repo, cve)].items() if k != 'per'}); continue
        d = os.path.join(work, repo.replace('/', '__'))
        if not os.path.exists(d):
            subprocess.run(['git', 'clone', '-q', '--depth', '1', '--no-tags', f'https://github.com/{repo}.git', d],
                           env={**os.environ, 'GIT_TERMINAL_PROMPT': '0', 'GIT_LFS_SKIP_SMUDGE': '1'}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
        r = dict(cve=cve, repo=repo, level=0, n_code=0, syntax_ok=0, syntax_fail=0, target=False, specific=False, suspect=False, nuclei=False)
        if os.path.exists(d):
            names = products(cve) | {cve.lower()}
            for dp, dn, fn in os.walk(d):
                if '.git' in dp.split(os.sep): continue
                for f in fn:
                    k = EXT.get(os.path.splitext(f)[1].lower())
                    if not k: continue
                    p = os.path.join(dp, f)
                    if os.path.getsize(p) > 2_000_000: continue
                    txt = open(p, 'rb').read().decode('utf-8', 'ignore')
                    if k == 'yaml':
                        try:
                            y = yaml.safe_load(txt)
                            if isinstance(y, dict) and 'id' in y and 'info' in y and any(x in y for x in ('http', 'requests', 'network', 'tcp', 'javascript', 'code', 'dns', 'headless')):
                                r['nuclei'] = True; r['target'] = True
                            else:
                                continue
                        except Exception:
                            continue
                    r['n_code'] += 1
                    s = syntax(p, k)
                    if s is True: r['syntax_ok'] += 1
                    elif s is False: r['syntax_fail'] += 1
                    low = txt.lower()
                    if NET.search(txt): r['target'] = True
                    if PAY.search(txt) and any(nm in low for nm in names): r['specific'] = True
                    if SUS.search(txt): r['suspect'] = True
            shutil.rmtree(d, ignore_errors=True)
            if r['n_code'] == 0: r['level'] = 0
            elif r['syntax_ok'] == 0 or not r['target']: r['level'] = 1
            elif not r['specific']: r['level'] = 2
            else: r['level'] = 3
        else:
            r['gone'] = True
        res.append(r)
        with open(CK, 'a') as fh: fh.write(json.dumps({**r, 'per': per}) + '\n')
    c = collections.Counter(x['level'] for x in res)
    out[per] = dict(n=len(res), levels={str(k): c.get(k, 0) for k in range(4)}, suspect=sum(x['suspect'] for x in res),
                    nuclei=sum(x['nuclei'] for x in res), gone=sum(bool(x.get('gone')) for x in res), items=res)
    print(per, out[per]['levels'], 'suspect', out[per]['suspect'], 'gone', out[per]['gone'], flush=True)
# Sample ends September 2026: drop post CVEs published in October 2026 (incomplete 30-day window).
_pub = {r['cve']: r['pub'] for r in json.load(open('data/poc_lags.json' if os.path.isdir('data') else f'{base}/poc_lags.json'))}
for per in ('pre', 'post'):
    its = [x for x in out[per]['items'] if _pub.get(x['cve'], '') < '2026-10-01']
    c = collections.Counter(x['level'] for x in its)
    out[per].update(n=len(its), dropped_oct2026=len(out[per]['items']) - len(its), levels={str(k): c.get(k, 0) for k in range(4)},
                    suspect=sum(x['suspect'] for x in its), nuclei=sum(x['nuclei'] for x in its), items=its)
    print(per, 'kept', len(its), out[per]['levels'], flush=True)
b = np.random.default_rng(2)
def sh(items, lv=3): return np.mean([x['level'] >= lv for x in items])
for lv in (2, 3):
    pre, post = out['pre']['items'], out['post']['items']
    rat = [sh([post[i] for i in b.integers(0, len(post), len(post))], lv) / max(1e-9, sh([pre[i] for i in b.integers(0, len(pre), len(pre))], lv)) for _ in range(5000)]
    out[f'level{lv}_plus'] = dict(pre=sh(pre, lv), post=sh(post, lv), ratio=sh(post, lv) / sh(pre, lv), ci=list(np.percentile(rat, [2.5, 97.5])))
    print(f'level>={lv}', out[f'level{lv}_plus'])
json.dump(out, open('results/poc_functional.json' if os.path.isdir('results') else f'{base}/poc_functional.json', 'w'), indent=1)
