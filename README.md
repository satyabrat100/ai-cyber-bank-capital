# Replication package (v7): AI-accelerated cyber risk, Basel III operational risk capital and credit

Run everything from this folder. Python 3.11+; exact versions in `requirements.txt` (tested with Python 3.13.18).

## 0. Quick check (no downloads, under one minute)

```
pip install -r requirements.txt
python3 scripts/verify_tables.py      # Table 2, Appendix C (Tables C1, C2) from data/monthly_panel.csv
python3 scripts/placebo_panel.py      # Section 8.5
```

## 1. Raw data (not redistributed) — pin to the commits in `data_sources.json`

```
cd data
git clone https://github.com/CVEProject/cvelistV5 cvefull && git -C cvefull checkout db766ab518964e91fc0470dfb511605d45e300ed
git clone https://github.com/nomi-sec/PoC-in-GitHub poc && git -C poc checkout 63dfb95a2278d9ad17e89ed0c03b0cf5f1612da8
git clone https://github.com/rapid7/metasploit-framework msf && git -C msf checkout fa68d9cca90702cb1ae86dbae72d53d0738f7a12
git clone https://github.com/cisagov/kev-data kev && git -C kev checkout 9c564f4dfa6dab393748a3b37038cde6a11b3585
git clone https://github.com/vz-risk/VCDB vcdb && git -C vcdb checkout 5ce87b920697e493e697364a972c799f78add489
git clone --filter=blob:none --no-checkout https://github.com/projectdiscovery/nuclei-templates nuclei
cd ..
```

`data/nuclei_adds.txt` (template add dates) was produced with
`git -C data/nuclei log --diff-filter=A --name-only --format='@@%cs' --since=2022-12-01 -- '*CVE-20*.yaml'`.
Indian figures are hand-entered in `data/india.json`, with the source of each number.

## 2. Full run

`./run_all.sh` runs every step in order and finally checks all outputs against `SHA256SUMS`.

| Step | Script | Output | Paper |
|---|---|---|---|
| 1 | scripts/cve_denominator.py, ent_denominator.py | data/cve_monthly_published.json, ent_monthly_published.json | Table 2, Section 8.3 |
| 2 | scripts/poc_analysis.py | data/poc_lags.json | input to the panel |
| 3 | scripts/msf_analysis.py, kev_analysis.py | data/msf_counts.json, kev_lags.json | input to the panel |
| 4 | scripts/nuclei_analysis.py | results/nuclei_results.json | Table 2 |
| 5 | scripts/make_panel.py | data/monthly_panel.csv | all regressions |
| 6 | scripts/verify_tables.py | results/verify_tables.json | Table 2, Tables C1, C2 |
| 7 | scripts/placebo_panel.py | results/placebo_panel.json | Section 8.5 |
| 8 | scripts/poc_quality.py | results/poc_quality.json | Section 5.3 (repository content check) |
| 9 | scripts/gtig_matched.py | results/gtig_matched.json | Table 2a |
| 10 | scripts/mapping.py | results/mapping.json | Section 3.1, Table 15 |
| 11 | scripts/tail_analysis.py, hill_thresholds.py | tail_results.json, hill_thresholds.json | Tables 3, 4 |
| 12 | scripts/india.py | printed | Table 5 |
| 13 | scripts/verify_props.py | results/results_verify_props.json | Appendix A |
| 14 | run_all.py (core_sim.py) | results/results_v5.json | Tables 7-9, 12, Figure 2 |
| 15 | sens_v5.py | results/results_sens_v5.json | Tables 12-14 |
| 16 | scripts/cv_sens.py | results/results_cv_sens.json | Table 10 |
| 17 | scripts/bic_sens.py, crar_credit.py | results/bic_sens.json, crar_credit.json | Tables 11, 14 |
| 18 | scripts/check_dois.py | printed | reference list (needs internet) |

Steps 14-15 take about 25 minutes on one CPU core (2,000,000 simulated years per scenario, 20 batches, common random numbers, seed 20261122). Step 14 was re-run from this package and reproduced `results_v5.json` exactly. Step 8 clones GitHub repositories and reads only their file lists; nothing is executed. Its result can change if repositories are deleted.

`legacy/` holds the earlier simulation engine (used only by verify_props.py for the single-loss check) and superseded scripts; none is used for a v6 table.

## 3. Definitions

- Exploit code within W days: a PoC-in-GitHub repository created 0 to W days after CVE publication. Sample January 2023 to September 2026 for W = 7, 30; to August 2026 for W = 90.
- KEV dateAdded is used only as a confirmation lag.
- Loss caps are fixed US-dollar amounts applied to each loss after severity scaling.

## 4. Archive

Public repository: https://github.com/satyabrat100/ai-cyber-bank-capital — Zenodo DOI: [to be inserted]. Citation details in `CITATION.cff`.
