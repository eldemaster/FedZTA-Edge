# Legacy artifacts

Superseded material from earlier iterations of this work, retained for provenance.
**Nothing here reproduces the results in `federated_paper_v5.tex`.** Do not run these
scripts expecting the published numbers.

## `superseded-experiments/`

| File | Why it was replaced |
|---|---|
| `poisoning_sim.py` | **Contained no experiment.** Three hardcoded arrays plotted directly to `poisoning_defense.pdf` — no model, no data, no aggregation. Replaced by `poisoning_experiment.py`, which runs K=7 real classifiers with f=2 Byzantine nodes and measures the outcome. |
| `fl_simulation.py`, `fl_simulation_v2.py` | Three defects: train and test sets were resampled from the same payload pool (identical payloads in both), benign and malicious traffic used different URL templates (so request *shape* predicted the label), and the "FedAvg" step averaged two independently trained models once rather than running communication rounds. |
| `fl_simulation_v3.py` | Corrected the splits and implemented iterative FedAvg, but retained the 3-feature syntactic vector that the design-space study found inadequate. Superseded by `fl_simulation_v4.py`. |
| `cloud_aggregator.py` | Plain mean aggregation, no Byzantine robustness. |
| `edge_node.py`, `live_waf.py` | Pre-federation gateway prototypes carrying hardcoded weights with no provenance. |
| `find_evasion.py` | Evasion harness written against the discredited 3-feature model. |
| `fix_features.py`, `fix_features2.py`, `test_v2.py` | One-shot patches applied during earlier iterations. |
| `sim_results.txt` | Output of `fl_simulation_v2.py`; the F1 scores in it reflect the template-leakage artifact. |

## `paper-tooling/`

Scripts that rewrote sections of the manuscript by string substitution. The manuscript is
now edited directly; these are kept only to explain how earlier revisions were produced.

## `paper-versions/`

Manuscripts v1 through v4 with their build artifacts. See `../PAPER_FIXES.md` for the full
audit of what was wrong with v4 and how each finding was resolved.

## `testbed-tools/`

Ad-hoc attack generators, monitors and launcher scripts used while building the cluster.
Not referenced by the paper and not required to reproduce it.
