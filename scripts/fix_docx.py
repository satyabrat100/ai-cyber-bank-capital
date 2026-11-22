import json, base64, sys, docx, subprocess, copy, zipfile, re, tempfile
from lxml import etree
src, out = sys.argv[1], sys.argv[2]
o = json.load(open(src))
print('notes', o['data'].get('notes'))
open(out, 'wb').write(base64.b64decode(o['data']['bytes_b64']))
d = docx.Document(out)
M = '{http://schemas.openxmlformats.org/officeDocument/2006/math}'
def omml(tex):
    tmp = tempfile.mkdtemp()
    open(f'{tmp}/a.md', 'w').write('$$' + tex + '$$\n')
    subprocess.run(['pandoc', f'{tmp}/a.md', '-o', f'{tmp}/a.docx'], check=True)
    root = etree.fromstring(zipfile.ZipFile(f'{tmp}/a.docx').read('word/document.xml'))
    return root.find('.//' + M + 'oMathPara')
n = 0
for p in d.paragraphs:
    t = p.text.strip()
    if '\\' in t and re.search(r'\\(frac|sum|lambda|min|text|propto|partial|ln|mathbb)', t):
        el = omml(t)
        if el is None: print('FAIL', t[:60]); continue
        for r in list(p._p):
            if r.tag != docx.oxml.ns.qn('w:pPr'): p._p.remove(r)
        ppr = p._p.pPr
        if ppr is not None:
            for c in list(ppr):
                if c.tag in (docx.oxml.ns.qn('w:pStyle'), docx.oxml.ns.qn('w:shd')): ppr.remove(c)
        p._p.append(copy.deepcopy(el)); n += 1
d.save(out)
words = sum(len(p.text.split()) for p in d.paragraphs) + sum(len(c.text.split()) for t in d.tables for r in t.rows for c in r.cells)
print('equations', n, 'tables', len(d.tables), 'images', len(d.inline_shapes), 'words', words)
