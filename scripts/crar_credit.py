"""Item 16/24: realised 99.9% loss vs capital, CRAR and credit, from results_v5.json.
Baseline 99.9% annual loss = 4.52% of bank capital (Section 7.5 calibration).
CRAR fall (pp) = CRAR x loss/K. Credit fall (%) = xi x incremental loss/K. Output fall (%) = eps x credit fall."""
import json
d = json.load(open('results_v5.json'))
CRAR, BASE = 17.7, 0.0452
out = {}
for M in ['1.1', '1.25', '1.56', '1.76']:
    for sp in ['freq_only', 'freq_sev', 'freq_sev_tail']:
        r = d['main'][f'{M}|{sp}']['0.999']
        lk = BASE * (1 + r['var_up'])
        inc = lk - BASE
        out[f'{M}|{sp}'] = dict(loss_K=lk, crar_after=CRAR * (1 - lk), crar_fall_extra=CRAR * inc,
                                credit_fall=[100 * xi * inc for xi in (0.25, 0.5, 1.0)],
                                output_fall=[100 * xi * inc * e for xi, e in ((0.25, 0.1), (0.5, 0.2), (1.0, 0.6))])
        o = out[f'{M}|{sp}']
        print(M, sp, f"loss/K {100*lk:.2f}% CRAR {o['crar_after']:.2f} extra fall {o['crar_fall_extra']:.2f}pp credit {[round(x,2) for x in o['credit_fall']]} output {[round(x,3) for x in o['output_fall']]}")
json.dump(out, open('data/crar_credit.json', 'w'), indent=1)
