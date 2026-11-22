# Replication package v7.3 — AI-accelerated cyber risk, Basel III operational-risk capital and credit

Archive: Zenodo, DOI 10.5281/zenodo.24439918 (all versions are listed on the Zenodo record).
Code: https://github.com/satyabrat100/ai-cyber-bank-capital
Paper: Maharana, S., "AI-Accelerated Cyber Risk, Bank Capital and Credit Supply" (manuscript v7.3).

Run everything from this folder. Python 3.11+; exact package versions in `requirements.txt` (tested with Python 3.13.18).

## 0. Quick check (no downloads, under one minute)

```
pip install -r requirements.txt
python3 scripts/verify_tables.py     # Table 2 and Appendix C (Tables C1, C2), from data/monthly_panel.csv
python3 scripts/placebo_panel.py     # Section 8.5
```
Expected first line: `poc_30d|count  n=45 IRR 1.76 [1.41,2.19]`.

## 1. Inputs

Included (`data/`): the monthly panel used by every regression; processed extracts of the raw repositories
(`poc_lags.json`, `kev_lags.json`, `msf_counts.json`, `msf_adds.txt`, `msf_module_cves.json`, `nuclei_adds.txt`,
`nuclei_cve_published.json`, `cve_monthly_published.json`, `ent_monthly_published.json`, `inputs/vcdb_extract.csv`,
`kev/known_exploited_vulnerabilities.json`); Indian figures with sources (`india.json`); the exploit-repository sample (`poc_quality.json`).

Not included (third-party raw data; the KEV catalogue v2026.11.20 is included in data/kev). Download at the pinned commits in `data_sources.json` only if you want to rebuild the extracts:

```
cd data
git clone https://github.com/CVEProject/cvelistV5 cvefull && git -C cvefull checkout db766ab518964e91fc0470dfb511605d45e300ed
git clone https://github.com/nomi-sec/PoC-in-GitHub poc && git -C poc checkout 63dfb95a2278d9ad17e89ed0c03b0cf5f1612da8
git clone https://github.com/rapid7/metasploit-framework msf && git -C msf checkout fa68d9cca90702cb1ae86dbae72d53d0738f7a12
git clone https://github.com/vz-risk/VCDB vcdb && git -C vcdb checkout 5ce87b920697e493e697364a972c799f78add489
git clone --filter=blob:none --no-checkout https://github.com/projectdiscovery/nuclei-templates nuclei
cd ..
```

## 2. Full run

`./run_all.sh` runs every step in order (about 75 minutes, mostly simulations). Then `sha256sum -c SHA256SUMS` compares all outputs with the published ones.

| Paper item | Script | Output (results/) |
|---|---|---|
| Table 2, Tables C1-C2 | scripts/verify_tables.py | verify_tables.json |
| Section 8.5 (placebos) | scripts/placebo_panel.py | placebo_panel.json |
| Table 2a (GTIG periods) | scripts/gtig_matched.py | gtig_matched.json |
| Table 2b (exploit functionality) | scripts/poc_quality.py, poc_functional.py, poc_crossval.py | poc_quality.json, poc_functional.json, poc_crossval.json |
| Tables 3-4 (severity, Hill) | scripts/tail_analysis.py, hill_thresholds.py | tail_results.json, hill_thresholds.json |
| Table 5 (India) | scripts/india.py | printed |
| Table 15, Section 3.1 (mapping) | scripts/mapping.py, ent_denominator.py | mapping.json |
| Appendix A (propositions) | scripts/verify_props.py | results_verify_props.json |
| Tables 7-9, Figure 2 | main_simulations.py (uses core_sim.py) | results_main.json |
| Tables 12a-12b (capped losses) | cap_validation.py, cap_probs.py | cap_validation.json, cap_probs.json |
| Table 12c (severity-parameter bootstrap) | sev_bootstrap.py | sev_bootstrap.json |
| Tables 13-14 | sensitivity.py, scripts/bic_sens.py | results_sensitivity.json, bic_sens.json |
| Table 10 (common vendor) | scripts/cv_sens.py | results_cv_sens.json |
| Table 14a (N, omega) | scripts/n_omega_sens.py | n_omega_sens.json |
| Table 14b (fixed-severity common vendor) | scripts/cv_fixed.py | cv_fixed.json |
| Table 11 (CRAR, credit) | scripts/crar_credit.py | crar_credit.json |
| Table 2c, Section 5.8 (AI-specific tests) | scripts/identification.py | identification.json |
| Reference list | scripts/check_dois.py | printed (needs internet) |

`legacy/` holds superseded scripts kept for transparency; none feeds a v7.3 table (`legacy/ai_cyber_sim.py` is used only by verify_props.py for the single-loss check).

## 3. Definitions used in the code

- Exploit code within W days: a PoC-in-GitHub repository created 0 to W days after CVE publication. Regression unit: calendar month, January 2023 to September 2026 (45 months; 5 after the May 2026 break); 90-day measures to August 2026.
- KEV dateAdded is used only as a confirmation lag.
- Loss cap c: a fixed US-dollar amount applied to each single loss after severity scaling. Three probabilities are reported separately: P(L > c), P(max X >= c) = P(N_c >= 1) and P(N_c >= 2).
- Exploit functionality: static checks only (no exploit is executed); terms used are "plausibly functional", "maintainer-reviewed" (Metasploit, nuclei) and "exploited in the wild" (KEV).

## 4. Licence and citation

Code MIT; processed data and results CC BY 4.0 (see LICENSE). Cite with `CITATION.cff` or the Zenodo DOI.
