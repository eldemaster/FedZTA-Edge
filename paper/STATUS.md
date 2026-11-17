# Paper status

- **Date:** 2026-11-12
- **Built from master commit:** `d0c80d6e6ca4460b5b1420651460d6f25a846cd2` (plus the edits in this PR; `paper/main.pdf` is the 16-page build of this branch with no undefined references or citations and no overfull boxes in `main.log`)
- **Build:** `cd paper && make` (the Makefile now depends on `main.tex`, `refs.bib`, `sections/*.tex` and `figures/*.pdf`, so `make` rebuilds after edits).

## Merged paper PRs

| PR | Content |
|---|---|
| #7 | Merged paper skeleton, background, system, evaluation, security |
| #16 | Threat-model layout fix |
| #17 | Review of narrative and prose (`PROSE.md`) |
| #18 | Rewrite of `system.tex` and `security.tex` |
| #19 | Rewrite of title, abstract, intro, background, conclusion |
| #20 | Rewrite of `evaluation.tex` (deployed threshold, CSIC, poisoning v2) |
| #21 | `baselines.py`, `baselines_results.json` (integrated into the paper in this PR) |

Evidence PRs: #8 (`review/RIGOR.md`), #9 (`review/NOVELTY.md`), #12 (`eval_deployed.py`), #13 (`poisoning_v2.py`), #14 (`real_data_eval.py`).

## Remaining known issues

1. **Baselines vs shipped model.** `baselines_results.json` (FedAvg ROC-AUC 0.9688) and `fed_model.json` (0.9947) come from the same script and seeds but different runs; SecLists is fetched unpinned at run time. The paper compares only within each file and says so. Cause not isolated; pin SecLists and rerun.
2. **ModSecurity + OWASP CRS not run**; no character-CNN. libinjection, regex, GBDT, MLP, FedProx and pooled training are reported.
3. **Hardware numbers (Section IV-H)** are from the earlier draft only; no archived result file.
4. **No captured benign traffic.** CSIC 2010 is the only external benign set, and the gateway maximum-over-contexts rule flags all of it. No fix to the scorer or threshold is made or evaluated.
5. **Domain-split configuration was selected on test results** (disclosed in Section IV-A); the shipped `fed_model.json` stores the seed-49 model.
6. **`test_auth_attacks.py` output is not archived**; Table XIII is a test plan.
7. **Scale:** two clients for detection, K=2 on hardware (f=0); poisoning only in simulation (K=10, 20).
8. **ML-KEM is not integrated** into the live channel; DP not implemented; no input-space evasion study.
9. Bandwidth figures are analytic, on a 1,040-byte binary update; the implementation sends JSON (5,395 B).
10. Stale figures `fl_sweep.pdf` and `fl_metrics.pdf` are not used in the paper; the README headline table was not audited in this pass.
