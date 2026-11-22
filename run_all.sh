#!/usr/bin/env bash
# Full replication. Step A needs only this package; steps B-D need the raw repositories (see README section 1).
set -e
echo "A. Regressions from the processed panel (Tables 2, C1, C2; Section 8.5)"
python3 scripts/verify_tables.py
python3 scripts/placebo_panel.py
if [ -d data/cvefull ] && [ -d data/poc ]; then
  echo "B. Rebuild empirical inputs from raw data"
  [ -e data/cvelist ] || ln -s cvefull data/cvelist
  python3 scripts/cve_denominator.py data
  python3 scripts/poc_analysis.py data
  python3 scripts/ent_denominator.py
  python3 scripts/nuclei_analysis.py data/nuclei_adds.txt
  python3 scripts/make_panel.py
  python3 scripts/verify_tables.py
  python3 scripts/mapping.py
  python3 scripts/gtig_matched.py
  python3 scripts/tail_analysis.py data && python3 scripts/hill_thresholds.py data
fi
echo "C. Propositions (Appendix A)"
python3 scripts/verify_props.py > /dev/null
echo "D. Simulations (about 25 minutes on one core)"
python3 run_all.py
python3 sens_v5.py
python3 scripts/cv_sens.py
python3 scripts/bic_sens.py
python3 scripts/crar_credit.py
sha256sum -c SHA256SUMS --quiet && echo "All outputs match the published checksums."
