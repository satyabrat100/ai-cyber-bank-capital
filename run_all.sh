#!/usr/bin/env bash
# Full replication of package v8.0. Run from the package root: ./run_all.sh
# Part A needs only this package. Part B needs the raw repositories (README section 1). Parts C-E need only this package.
set -e
echo "A. Regressions from the processed monthly panel (Tables 2, C1, C2; Section 8.5) - under 1 minute"
python3 scripts/verify_tables.py
python3 scripts/placebo_panel.py
if [ -d data/cvefull ] && [ -d data/poc ]; then
  echo "B. Rebuild empirical inputs from the raw repositories"
  [ -e data/cvelist ] || ln -s cvefull data/cvelist
  python3 scripts/cve_denominator.py data
  python3 scripts/ent_denominator.py
  python3 scripts/poc_analysis.py data
  python3 scripts/msf_analysis.py data
  python3 scripts/kev_analysis.py data
  python3 scripts/nuclei_analysis.py data/nuclei_adds.txt
  python3 scripts/make_panel.py
  python3 scripts/verify_tables.py
  python3 scripts/mapping.py
  python3 scripts/gtig_matched.py
  python3 scripts/poc_quality.py      # clones sample repositories; results can change if repositories are deleted
  python3 scripts/poc_functional.py   # static check only, nothing is executed
fi
echo "C. Empirical tables that need only the extracts in data/"
python3 scripts/tail_analysis.py data > /dev/null
python3 scripts/hill_thresholds.py data > /dev/null
python3 scripts/india.py
python3 scripts/poc_crossval.py
python3 scripts/identification.py    # Table 2c (uses data/cve_flags.json when the raw CVE list is absent)
echo "D. Propositions (Appendix A)"
python3 scripts/verify_props.py > /dev/null
echo "E. Simulations (about 75 minutes on one core)"
python3 main_simulations.py            # Tables 7-9, Figure 2   -> results/results_main.json
python3 sensitivity.py            # Tables 13-14           -> results/results_sensitivity.json
python3 cap_validation.py     # Tables 12a-12b (VaR, gap CIs) -> results/cap_validation.json
python3 cap_probs.py          # Table 12b (three probabilities) -> results/cap_probs.json
python3 sev_bootstrap.py      # Table 12c (severity-parameter bootstrap) -> results/sev_bootstrap.json
python3 scripts/cv_sens.py    # Table 10               -> results/results_cv_sens.json
python3 scripts/n_omega_sens.py  # Table 14a           -> results/n_omega_sens.json
python3 scripts/cv_fixed.py   # Table 14b              -> results/cv_fixed.json
python3 scripts/bic_sens.py   # Table 14 (BIC rows)    -> results/bic_sens.json
python3 scripts/crar_credit.py   # Table 11            -> results/crar_credit.json
echo "Done. To compare with the published outputs: copy results/ to results_published/ before running, then python3 scripts/compare_outputs.py"
