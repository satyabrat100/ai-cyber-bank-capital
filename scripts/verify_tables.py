"""Re-run every NB2 regression of Table 2 / Appendix C from data/monthly_panel.csv alone (no raw downloads)."""
import csv, json, sys, numpy as np, statsmodels.api as sm, warnings
from statsmodels.discrete.discrete_model import NegativeBinomial, Poisson
warnings.filterwarnings('ignore')
rows = list(csv.DictReader(open(sys.argv[1] if len(sys.argv) > 1 else 'data/monthly_panel.csv')))
def fit(col, denom=None, last='2026-10'):
    r = [x for x in rows if x['month'] <= last]
    y = np.array([float(x[col]) for x in r]); t = np.arange(len(r), dtype=float); post = np.array([x['month'] >= '2026-05' for x in r], float)
    X = sm.add_constant(np.column_stack([t, post])); off = np.log([float(x[denom]) for x in r]) if denom else None
    nb = NegativeBinomial(y, X, offset=off, loglike_method='nb2').fit(disp=0, maxiter=500, cov_type='HC1'); po = Poisson(y, X, offset=off).fit(disp=0)
    mu = nb.predict(X, offset=off) if denom else nb.predict(X); a = nb.params[3]
    ci = nb.conf_int()
    pre = y[post == 0]; pst = y[post == 1]; dd = np.array([float(x[denom]) for x in r]) if denom else None
    return dict(n=len(r), const=(nb.params[0], nb.bse[0]), trend=(nb.params[1], nb.bse[1]), post=(nb.params[2], nb.bse[2], nb.pvalues[2]),
                alpha=(a, nb.bse[3]), irr=np.exp(nb.params[2]), irr_ci=(np.exp(ci[2][0]), np.exp(ci[2][1])), ll=nb.llf, aic=nb.aic, bic=nb.bic,
                pr2=nb.prsquared, pre_mean=pre.mean(), post_mean=pst.mean(), pre_share=(pre.sum() / dd[post == 0].sum()) if denom else float('nan'), post_share=(pst.sum() / dd[post == 1].sum()) if denom else float('nan'), pearson=float(np.sum((y - mu) ** 2 / (mu + a * mu ** 2)) / (len(y) - 4)), lr=2 * (nb.llf - po.llf))
# Sample: Jan 2023 to Sep 2026 for 7- and 30-day windows (every window complete by the 20-22 Nov 2026 downloads);
# to Aug 2026 for 90-day windows.
specs = [('poc_30d', None, '2026-09'), ('poc_30d', 'cves_published', '2026-09'), ('poc_by30_incl_prepub', None, '2026-09'), ('poc_by30_incl_prepub', 'cves_published', '2026-09'), ('poc_7d', None, '2026-09'), ('poc_7d', 'cves_published', '2026-09'),
         ('poc_starred_30d', None, '2026-09'), ('poc_starred_30d', 'cves_published', '2026-09'), ('kev_inclusion_30d_by_added', None, '2026-09'),
         ('metasploit_30d', None, '2026-09'), ('metasploit_30d', 'cves_published', '2026-09'), ('metasploit_90d', None, '2026-08'), ('metasploit_90d', 'cves_published', '2026-08'),
         ('nuclei_30d', None, '2026-09'), ('nuclei_30d', 'cves_published', '2026-09'), ('nuclei_90d', None, '2026-08'), ('nuclei_90d', 'cves_published', '2026-08')]
out = {}
for col, den, last in specs:
    r = fit(col, den, last); k = f"{col}|{'rate' if den else 'count'}"; out[k] = {kk: (list(map(float, v)) if isinstance(v, tuple) else float(v)) for kk, v in r.items()}
    print(f"{k:34s} n={r['n']} IRR {r['irr']:.2f} [{r['irr_ci'][0]:.2f},{r['irr_ci'][1]:.2f}] p={r['post'][2]:.4f} alpha {r['alpha'][0]:.3f}")
json.dump(out, open('results/verify_tables.json' if __import__('os').path.isdir('results') else 'data/verify_tables.json', 'w'), indent=1)
