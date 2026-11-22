"""Item 8: check exploit-code quality by inspecting the content of the first PoC repository.
Random sample of CVEs with first public exploit code within 30 days of publication: 200 published
Jan 2025-Apr 2026 (pre) and 200 published May-Oct 2026 (post). Each repo is shallow-cloned and only its
file list is read (nothing is executed). Classes:
  code       - at least one source/exploit file (.py .c .cpp .go .rb .sh .js .ts .java .php .ps1 .rs .cs .pl .lua .yaml/.yml template, .html/.xml payload)
  archive    - only archives/binaries (.zip .rar .7z .exe .dll .bin .jar without source)  [suspicious]
  text_only  - only README/LICENSE/images/notes                                            [placeholder]
  gone       - repository deleted or private
"""
import json, os, random, subprocess, datetime as dt, collections, sys, shutil
base = 'data'
CODE = {'.py','.c','.cpp','.cc','.h','.go','.rb','.sh','.js','.ts','.java','.php','.ps1','.rs','.cs','.pl','.lua','.yaml','.yml','.html','.xml','.nse','.kt','.swift','.m','.asm','.s','.vbs','.bat','.json','.sol','.jsp','.aspx','.txt_py'}
ARCH = {'.zip','.rar','.7z','.exe','.dll','.bin','.jar','.msi','.scr','.gz','.tgz','.tar'}
lags = json.load(open(f'{base}/poc_lags.json'))
sel = {'pre': [r for r in lags if '2025-01-01' <= r['pub'] < '2026-05-01' and 0 <= r['lag'] <= 30],
       'post': [r for r in lags if '2026-05-01' <= r['pub'] <= '2026-10-20' and 0 <= r['lag'] <= 30]}
rng = random.Random(20261122)
work = '/tmp/pocq'; os.makedirs(work, exist_ok=True)
out = {}
for per, rows in sel.items():
    samp = rng.sample(rows, min(200, len(rows)))
    res = []
    for r in samp:
        y = r['cve'].split('-')[1]
        repos = json.load(open(f'{base}/poc/{y}/{r["cve"]}.json'))
        p = dt.date.fromisoformat(r['pub'])
        cand = sorted([x for x in repos if 0 <= (dt.date.fromisoformat(x['created_at'][:10]) - p).days <= 30], key=lambda x: x['created_at'])
        x = cand[0]
        d = os.path.join(work, str(x['id']))
        if not os.path.exists(d):
            subprocess.run(['git', 'clone', '-q', '--depth', '1', '--no-tags', x['html_url'] + '.git', d],
                           env={**os.environ, 'GIT_TERMINAL_PROMPT': '0', 'GIT_LFS_SKIP_SMUDGE': '1'},
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
        if not os.path.exists(d):
            cls, nfiles = 'gone', 0
        else:
            files = [os.path.join(dp, f) for dp, dn, fn in os.walk(d) if '.git' not in dp.split(os.sep) for f in fn]
            ext = [os.path.splitext(f)[1].lower() for f in files]
            nfiles = len(files)
            if any(e in CODE - {'.json'} for e in ext) or any(e == '.json' and 'readme' not in f.lower() for e, f in zip(ext, files)) and any(e in CODE for e in ext):
                cls = 'code'
            elif any(e in ARCH for e in ext):
                cls = 'archive'
            else:
                cls = 'text_only'
            shutil.rmtree(d, ignore_errors=True)
        res.append(dict(cve=r['cve'], repo=x['full_name'], stars=x.get('stargazers_count', 0), cls=cls, nfiles=nfiles))
    c = collections.Counter(z['cls'] for z in res)
    out[per] = dict(n=len(res), population=len(rows), counts=dict(c), items=res)
    print(per, len(rows), dict(c), flush=True)
# share with code among all sampled, bootstrap CI of post/pre ratio
import numpy as np
b = np.random.default_rng(1)
def share(items): return np.mean([z['cls'] == 'code' for z in items])
pre, post = out['pre']['items'], out['post']['items']
ratios = []
for _ in range(5000):
    a = [pre[i] for i in b.integers(0, len(pre), len(pre))]; q = [post[i] for i in b.integers(0, len(post), len(post))]
    ratios.append(share(q) / share(a))
out['share_code'] = dict(pre=share(pre), post=share(post), ratio=share(post) / share(pre), ci=list(np.percentile(ratios, [2.5, 97.5])))
# quality-adjusted count IRR (30-day count IRR 1.56, CI 1.28-1.90) x share ratio, by simulation
irr = np.exp(b.normal(np.log(1.56), (np.log(1.90) - np.log(1.28)) / 3.92, 5000))
adj = irr * np.array(ratios)
out['adjusted_count_irr'] = dict(point=1.56 * out['share_code']['ratio'], ci=list(np.percentile(adj, [2.5, 97.5])))
json.dump(out, open(f'{base}/poc_quality.json', 'w'), indent=1)
print(json.dumps({k: out[k] for k in ['share_code', 'adjusted_count_irr']}, indent=1))
