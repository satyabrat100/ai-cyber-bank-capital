"""
AI-Accelerated Cyber Risk, Bank Capital and Credit Supply
Simulation code for the calibrated model (Sections 5-6).

Author: Satyabrat Maharana
Run:    python3 ai_cyber_sim.py      (seed fixed; results reproducible)

All parameters marked ASSUMED are illustrative and are varied in the
sensitivity analysis. Parameters marked SOURCED come from public documents
cited in the paper.
"""
import numpy as np
from scipy.optimize import brentq
import json

rng = np.random.default_rng(20261121)
NSIM = 200_000          # simulated years per scenario
Q = 0.999               # Basel soundness standard

# ---------------- Parameters ----------------
P = dict(
    lam0=25.0,     # ASSUMED baseline attempted-incident frequency per year
    sigma0=3.09,   # ESTIMATED: log s.d. of US$ losses, VCDB financial sector (n=61)
    theta=0.50,    # ASSUMED elasticity of frequency to attacker AI capability
    eta=0.30,      # ASSUMED elasticity of mean severity to attacker AI
    zeta=0.15,     # ASSUMED tail-fattening: sigma(a) = sigma0 + zeta*ln(1+a)
    beta=1.0,      # ASSUMED Gordon-Loeb productivity exponent
    kappa=100.0,   # ASSUMED security-investment efficiency (model units)
    phi=0.80,      # ASSUMED elasticity of security efficiency to defensive AI
    # Indian system (SOURCED unless noted)
    crar=0.177,    # SOURCED: SCB CRAR end-March 2026, RBI FSR June 2026
    crar_min=0.115,# SOURCED: 9% minimum + 2.5% CCB (RBI Basel III)
    op_share=0.10, # ASSUMED: operational-risk RWA share of total RWA
    xi=0.5,        # ASSUMED: share of capital loss met by cutting credit
    eps=0.2,       # ASSUMED: elasticity of output to bank credit
)

def ilm(lc, bic):
    """Basel III SA Internal Loss Multiplier (BCBS OPE25; RBI MD 2023)."""
    return np.log(np.e - 1 + (lc / bic) ** 0.8)

def severity_params(a, mu0, p=P):
    sigma = p["sigma0"] + p["zeta"] * np.log1p(a)
    # mean severity scales as (1+a)^eta:  mu chosen to hit that mean
    mean0 = np.exp(mu0 + p["sigma0"] ** 2 / 2)
    mean_a = mean0 * (1 + a) ** p["eta"]
    mu = np.log(mean_a) - sigma ** 2 / 2
    return mu, sigma

def optimal_security(A, kappa, beta):
    """min_s s + A(1+kappa s)^-beta  ->  closed form (Prop. 1)."""
    x = A * beta * kappa
    if x <= 1:
        return 0.0, A
    one_ks = x ** (1 / (beta + 1))
    s = (one_ks - 1) / kappa
    el = A * one_ks ** (-beta)
    return s, el

def scenario(a, d, mu0, p=P, nsim=NSIM, seed=7):
    """Return dict of outcomes for attacker capability a, defender AI d."""
    mu, sigma = severity_params(a, mu0, p)
    lam_raw = p["lam0"] * (1 + a) ** p["theta"]
    mean_sev = np.exp(mu + sigma ** 2 / 2)
    A = lam_raw * mean_sev                       # unprotected expected loss
    kappa = p["kappa"] * (1 + d) ** p["phi"]
    s, el = optimal_security(A, kappa, p["beta"])
    v = (1 + kappa * s) ** (-p["beta"])          # breach probability factor
    lam = lam_raw * v
    # common random numbers: same uniforms/normals across scenarios
    r_ = np.random.default_rng(seed)
    n = r_.poisson(lam, nsim)
    tot = n.sum()
    x = np.exp(mu + sigma * r_.standard_normal(tot))
    idx = np.repeat(np.arange(nsim), n)
    L = np.bincount(idx, weights=x, minlength=nsim)
    return dict(a=a, d=d, s=s, EL=el, EL_mc=L.mean(),
                VaR=np.quantile(L, Q), lam=lam, sigma=sigma, losses=L)

# ---------------- Calibration ----------------
# Normalise mu0 so baseline residual expected loss = 0.10 BIC units,
# then choose BIC so that Basel SA capital = VaR99.9 at baseline
# (i.e., we assume regulatory capital is exactly adequate before AI).
def calibrate():
    target_el = 0.10
    def f(mu0):
        mu, sg = severity_params(0, mu0)
        A = P["lam0"] * np.exp(mu + sg ** 2 / 2)
        return optimal_security(A, P["kappa"], P["beta"])[1] - target_el
    mu0 = brentq(f, -20, 5)
    base = scenario(0, 0, mu0)
    lc = 15 * base["EL"]
    g = lambda bic: bic * ilm(lc, bic) - base["VaR"]
    bic = brentq(g, 1e-3, 1e3)
    return mu0, bic, base

mu0, BIC, base = calibrate()
scale = 1 / BIC                       # express everything in BIC units
ORC0 = BIC * ilm(15 * base["EL"], BIC)

out = {"calibration": dict(mu0=mu0, BIC=BIC, ILM0=ilm(15*base["EL"], BIC),
                           EL0=base["EL"]*scale, VaR0=base["VaR"]*scale,
                           s0=base["s"]*scale)}

# ---------------- Exp 1: static capital gap, no defensive AI ----------------
A_OBS = 1.56 ** (1 / P['theta']) - 1   # ESTIMATED: PoC-in-GitHub fast-exploit-code IRR 1.56 (CISA-independent)
grid = [0, 1, A_OBS, 3, 9]           # (1+a) = 1, 2, 3.10 (observed 2026), 4, 10
rows = []
for a in grid:
    r = scenario(a, 0, mu0)
    lc = 15 * r["EL"]
    orc_ilm = BIC * ilm(lc, BIC)      # fully adjusted ILM (10 yrs later)
    orc_bic = BIC                     # ILM = 1 / bucket-1 banks
    rows.append(dict(mult=1+a, s=r["s"]*scale, EL=r["EL"]*scale,
                     VaR=r["VaR"]*scale, ORC_ILM=orc_ilm*scale,
                     gap_ILM=(r["VaR"]-orc_ilm)/orc_ilm*100,
                     gap_ILM_vs_ORC0=(r["VaR"]-orc_ilm)/ORC0*100,
                     gap_fixed=(r["VaR"]-ORC0)/ORC0*100,
                     tail_ratio=r["VaR"]/r["EL"]))
out["exp1"] = rows

# ---------------- Exp 2: arms race (defensive AI) ----------------
rows = []
for a in [A_OBS, 3, 9]:
    for frac in [0, 0.5, 1.0, 2.0]:
        d = frac * a
        r = scenario(a, d, mu0)
        rows.append(dict(mult=1+a, d_mult=1+d, s=r["s"]*scale,
                         EL=r["EL"]*scale, VaR=r["VaR"]*scale,
                         gap_fixed=(r["VaR"]-ORC0)/ORC0*100))
out["exp2"] = rows
# neutrality condition (Prop. 2): phi*beta = theta + eta  (mean channel)
out["neutral_phi"] = (P["theta"] + P["eta"]) / P["beta"]

# ---------------- Exp 3: dynamic path with 10-year loss window -------------
# AI capability ramps linearly from 0 to a_max over 3 years, then stays.
a_max, T = A_OBS, 16
hist_el = [base["EL"]] * 10           # pre-shock 10-year history
path = []
for t in range(T):
    a_t = min(a_max, a_max * t / 3)
    r = scenario(a_t, 0, mu0)
    hist_el = hist_el[1:] + [r["EL"]]
    lc = 15 * np.mean(hist_el)
    orc = BIC * ilm(lc, BIC)
    path.append(dict(year=t, mult=1+a_t, VaR=r["VaR"]*scale,
                     ORC_ILM=orc*scale, ORC_fixed=ORC0*scale))
out["exp3"] = path

# ---------------- Exp 4: common-vendor concentration ----------------
# N banks. A share `share` of each bank's expected loss is moved from
# independent incidents to one common-vendor event (annual prob pc) that
# hits all banks at once, allocated by bank size. Total expected loss is
# held constant, so only the dependence structure changes.
pc0, sig_c, nsys = 0.02, 1.0, 100_000
N = int(__import__("os").environ.get("NBANKS", 12))
sizes = np.sort(np.random.default_rng(3).lognormal(0, 0.8, N))[::-1]
sizes = sizes / sizes.sum() * N        # mean size 1
rows = []
for a in [0, 3]:
    pc = min(1.0, pc0 * (1 + a) ** P["theta"])
    for share in [0.0, 0.10, 0.25, 0.50]:
        idio = []
        for i in range(N):
            r = scenario(a, 0, mu0, nsim=nsys, seed=100 + i)
            idio.append(r["losses"] * (1 - share) * sizes[i])
        el_bank = r["EL"]
        rc = np.random.default_rng(999)
        hit = rc.random(nsys) < pc
        z = np.exp(sig_c * rc.standard_normal(nsys) - sig_c ** 2 / 2)
        common_total = hit * z * share * el_bank * N / pc
        bank_L = [idio[i] + common_total * sizes[i] / N for i in range(N)]
        sysL = np.sum(bank_L, axis=0)
        standalone = sum(np.quantile(b, Q) for b in bank_L)
        rows.append(dict(mult=1+a, common_share=share, pc=pc,
                         sys_VaR=np.quantile(sysL, Q)*scale,
                         sum_standalone=standalone*scale,
                         div_ratio=np.quantile(sysL, Q)/standalone))
out["exp4"] = rows

# ---------------- Exp 5: CRAR, credit and output ----------------
# RWA_total = 12.5*ORC0/op_share ; capital K = crar * RWA
RWA = 12.5 * ORC0 / P["op_share"]
K = P["crar"] * RWA
rows = []
for r1 in out["exp1"]:
    loss = r1["VaR"] / scale            # 1-in-1000-year loss
    dK = loss
    crar_new = (K - dK) / RWA
    credit_cut = P["xi"] * dK / K * 100          # % fall in credit
    gdp = P["eps"] * credit_cut                   # % fall in output
    rows.append(dict(mult=r1["mult"], loss_pct_K=dK/K*100,
                     crar_after=crar_new*100,
                     crar_drop_bp=(P["crar"]-crar_new)*1e4,
                     breach_min=crar_new < P["crar_min"],
                     credit_cut=credit_cut, gdp=gdp))
out["exp5"] = rows
grid5=[]
for xi in [0.25,0.5,1.0]:
    for eps in [0.1,0.2,0.3]:
        r1=[r for r in out['exp1'] if abs(r['mult']-(1+A_OBS))<1e-9][0]
        dK=r1['VaR']/scale
        grid5.append(dict(xi=xi,eps=eps,credit_cut=xi*dK/K*100,gdp=eps*xi*dK/K*100))
out['exp5_grid']=grid5

# ---------------- Sensitivity (gap after full ILM adjustment, (1+a)=4) -----
sens = []
for key, vals in dict(theta=[0.25, 0.5, 0.75], eta=[0.15, 0.3, 0.45],
                      zeta=[0.0, 0.15, 0.30], sigma0=[2.0, 3.09, 4.58]).items():
    for v in vals:
        old = P[key]; P[key] = v
        m0, bic, b0 = calibrate()
        orc0 = bic * ilm(15*b0["EL"], bic)
        r = scenario(A_OBS if key!='theta' else 1.56**(1/v)-1, 0, m0)
        orc = bic * ilm(15*r["EL"], bic)
        sens.append(dict(param=key, value=v,
                         gap_ILM=(r["VaR"]-orc)/orc*100,
                         gap_fixed=(r["VaR"]-orc0)/orc0*100))
        P[key] = old
out["sensitivity"] = sens

def clean(o):
    if isinstance(o, dict):
        return {k: clean(v) for k, v in o.items() if k != "losses"}
    if isinstance(o, list):
        return [clean(v) for v in o]
    if isinstance(o, (np.floating, np.integer)):
        return float(o)
    if isinstance(o, np.bool_):
        return bool(o)
    return o

with open("results.json", "w") as fh:
    json.dump(clean(out), fh, indent=1)
print(json.dumps(clean(out), indent=1))
