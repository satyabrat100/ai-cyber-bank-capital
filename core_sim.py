"""
Core simulation engine (revision 2).

Annual loss L = sum_{k=1}^{N} min(X_k, cap),  N ~ Poisson(lambda),  compound Poisson Monte Carlo.
Common random numbers: every simulated year has a fixed uniform for its event count and a fixed
vector of uniforms for its severities, so scenarios differ only through parameters, not through draws.
Monte Carlo standard errors are computed from 20 independent batches.

Units: US$ million. Severity family parameters are the maximum-likelihood fits to the 61
financial-sector losses in the VERIS Community Database (see scripts/tail_analysis.py).
"""
import numpy as np
from scipy import stats
from scipy.optimize import brentq

FIT = dict(lognormal=dict(sigma=3.0639, scale=0.42576),
           loglogistic=dict(c=0.57727, scale=0.47464),
           weibull=dict(c=0.35143, scale=1.90493))
BASE = dict(lam0=25.0, kappa_t=100.0, beta=1.0, theta=0.5, eta=0.0, zeta=0.0, phi=0.8)
N_YEARS, N_BATCH, KMAX, SEED = 2_000_000, 20, 24, 20261122


def ilm(lc, bic):
    return np.log(np.e - 1 + (lc / bic) ** 0.8)


class Draws:
    """Fixed uniforms shared by all scenarios (common random numbers)."""
    def __init__(self, n=N_YEARS, kmax=KMAX, seed=SEED):
        r = np.random.default_rng(seed)
        self.u_n = r.random(n)
        self.u_x = r.random((n, kmax)).astype(np.float32)
        self.n = n


def sev_ppf(family, u, sigma_shift=0.0, scale_mult=1.0):
    """Quantile function of the single-loss severity (US$ m), before any cap."""
    if family == 'lognormal':
        s = FIT['lognormal']['sigma'] + sigma_shift
        # keep the MEAN at scale_mult x baseline mean when the shape changes
        mu = np.log(FIT['lognormal']['scale']) + FIT['lognormal']['sigma'] ** 2 / 2 - s ** 2 / 2 + np.log(scale_mult)
        return np.exp(mu + s * stats.norm.ppf(u))
    if family == 'loglogistic':
        return scale_mult * stats.fisk.ppf(u, FIT['loglogistic']['c'], scale=FIT['loglogistic']['scale'])
    if family == 'weibull':
        return scale_mult * stats.weibull_min.ppf(u, FIT['weibull']['c'], scale=FIT['weibull']['scale'])
    raise ValueError(family)


def capped_mean(family, cap, sigma_shift=0.0, scale_mult=1.0, n=400_000):
    """E[min(X, cap)] by numerical integration over quantiles (exact for lognormal when cap is infinite)."""
    if family == 'lognormal' and np.isinf(cap):
        s0 = FIT['lognormal']['sigma']
        return scale_mult * FIT['lognormal']['scale'] * np.exp(s0 ** 2 / 2)
    u = (np.arange(n) + 0.5) / n
    return float(np.mean(np.minimum(sev_ppf(family, u, sigma_shift, scale_mult), cap)))


def bank_response(p, a, d, family, cap):
    """Optimal security spending (Prop. 1) and resulting breach share, frequency and severity scaling."""
    M = (1 + a) ** p['theta']                     # frequency multiplier on attempted incidents
    S = (1 + a) ** p['eta']                       # multiplier on mean single-loss severity
    sig = p['zeta'] * np.log1p(a)                 # tail widening
    m_sev = capped_mean(family, cap, sig, S)
    A = p['lam0'] * M * m_sev                     # unprotected expected annual loss (US$ m)
    A0 = p['lam0'] * capped_mean(family, cap)
    kappa = p['kappa_t'] / A0 * (1 + d) ** p['phi']
    x = A * p['beta'] * kappa
    s = max(0.0, (x ** (1 / (1 + p['beta'])) - 1) / kappa)
    v = (1 + kappa * s) ** (-p['beta'])
    return dict(lam=p['lam0'] * M * v, S=S, sig=sig, s=s, el=A * v, A=A)


def annual_losses(dr, lam, family, cap, sig, S):
    n = stats.poisson.ppf(dr.u_n, lam).astype(int)
    n = np.minimum(n, dr.u_x.shape[1])
    L = np.zeros(dr.n)
    for k in range(dr.u_x.shape[1]):
        idx = n > k
        if not idx.any(): break
        L[idx] += np.minimum(sev_ppf(family, dr.u_x[idx, k].astype(np.float64), sig, S), cap)
    return L


def run(dr, p, a, d=0.0, family='lognormal', cap=np.inf, qs=(0.99, 0.995, 0.999)):
    """Gap of the q-quantile of annual loss against SA capital, with batch standard errors."""
    b0 = bank_response(p, 0.0, 0.0, family, cap)
    b1 = bank_response(p, a, d, family, cap)
    L0 = annual_losses(dr, b0['lam'], family, cap, 0.0, 1.0)
    L1 = annual_losses(dr, b1['lam'], family, cap, b1['sig'], b1['S'])
    out = dict(lam0=b0['lam'], lam1=b1['lam'], el0=b0['el'], el1=b1['el'], s0=b0['s'], s1=b1['s'])
    B = np.array_split(np.arange(dr.n), N_BATCH)
    for q in qs:
        v0, v1 = np.quantile(L0, q), np.quantile(L1, q)
        bic = brentq(lambda b: b * ilm(15 * b0['el'], b) - v0, 1e-9, 1e12)
        o0, o1 = bic * ilm(15 * b0['el'], bic), bic * ilm(15 * b1['el'], bic)
        gb = [np.quantile(L1[i], q) / o1 - 1 for i in B]
        out[q] = dict(var0=float(v0), var1=float(v1), var_up=float(v1 / v0 - 1), orc_up=float(o1 / o0 - 1),
                      gap=float(v1 / o1 - 1), gap_fixed=float(v1 / o0 - 1), gap_se=float(np.std(gb, ddof=1) / np.sqrt(N_BATCH)),
                      bic=float(bic), orc0=float(o0), orc1=float(o1))
    return out
