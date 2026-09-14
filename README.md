# FedZTA-Edge

Federated Learning for Zero-Trust Edge Gateways in Industrial Data Spaces.

Reference implementation and reproduction package for *"Collaborative Defense in Industrial
Data Spaces: A Quantum-Resistant Federated Learning Approach for Zero-Trust Edge Gateways"*
(`federated_paper_v5.tex`).

## Headline result

Whether federation helps depends on **which axis** the data is non-IID along. Partitioning
nodes by threat campaign — the common framing — produces a federated model that lands
*between* the isolated silos. Partitioning by benign traffic profile, with a shared threat
landscape, produces one that beats both:

| Model | ROC-AUC | XSS @0.1% FPR | SQLi @0.1% FPR |
|---|---|---|---|
| Edge A (web gateway) | 0.9766 | 0.998 | 0.712 |
| Edge B (API gateway) | 0.9817 | 0.988 | 0.744 |
| **Federated** | **0.9850** | **1.000** | **0.792** |

On a Raspberry Pi 4: 452 req/s at 0.229 ms per classification, 10.4 MB resident,
1,040-byte synchronisation payload, ML-KEM-512 encapsulation at 0.162 ms.

## Layout

```
fedzta_features.py          shared feature transform - cloud and edge MUST agree
continuous_waf.py           edge gateway (pure Python, zero dependencies)
robust_cloud.py             cloud aggregator, coordinate-wise median over peers
```

### Reproducing each paper claim

| Claim | Script | Runs on |
|---|---|---|
| Design-space matrix (Table III) | `fl_simulation_v4.py` | cloud |
| Production model + detection (Table IV) | `train_production_model.py` | cloud |
| Dimension sweep (Fig. 4) | `sweep_ngram.py` | cloud |
| Polynomial vs md5 hash equivalence | `verify_poly.py` | cloud |
| Template-leakage / feature probe (§VI-B) | `feature_probe.py` | cloud |
| Byzantine resilience (Fig. 5) | `poisoning_experiment.py` | cloud |
| Inference latency and RSS (Table V) | `edge_profiler.py` | edge |
| Hash cost comparison (§IV-A) | `edge_profiler_ngram.py` | edge |
| ML-KEM-512 benchmark (Table VI) | `edge_pqc.py` + `cloud_pqc.py` | edge + cloud |
| Throughput (§VII-D) | `stress_test.py` | any client |
| Continuous-learning loop (§VII-D) | `stress_continuous.py` | any client |
| Bandwidth analysis (Fig. 6, Table VII) | `bandwidth_analysis.py` | cloud |
| Figures | `make_figures.py`, `draw_arch.py` | cloud |

`fed_model.json`, `matrix_results.json`, `poisoning_results.json` and `bandwidth_results.json`
hold the measured outputs the manuscript quotes.

## Testbed

| Role | Hardware |
|---|---|
| Cloud Aggregator | x86\_64 Ubuntu, 14 cores, 31 GB |
| Edge Gateway A/B | Raspberry Pi 4, aarch64 Cortex-A72, 4 GB |

Training studies need `numpy`, `scikit-learn` and `matplotlib`. The gateway and the
aggregator need **neither** — `continuous_waf.py`, `robust_cloud.py` and `fedzta_features.py`
are pure standard library, which is what keeps the edge footprint at 10.4 MB.
The ML-KEM benchmark needs `pqcrypto`.

## Running the cluster

Gateways must be enrolled before they can contribute. An aggregator with no peer
file rejects every update.

```sh
# cloud: issue a credential per gateway
python3 enroll_peer.py edge-web
python3 enroll_peer.py edge-api
scp gateway_secret_edge-web.json edge-web-host:~/gateway_secret.json

# cloud
python3 robust_cloud.py

# each gateway (identity comes from gateway_secret.json)
FEDZTA_SYNC=15 python3 continuous_waf.py
```

`peers.json` and `gateway_secret*.json` are credentials, written 0600 and excluded
from version control. Anything that can read a gateway secret can register as that
gateway.

### Control-plane authentication

Coordinate-wise median tolerates `f` malicious clients only while `f` is bounded.
Unauthenticated enrolment makes `f` unbounded: an attacker registers five sybil
identities and owns the median regardless of how robust the rule is. Every update
therefore carries an HMAC-SHA256 signature over a canonical serialisation, with a
timestamp and single-use nonce.

An update passes through, in order: signature/timestamp/nonce verification,
per-identity rate limit, dimension and finiteness checks, an L2-norm gate against
the reference peer norm, then aggregation.

`test_auth_attacks.py` exercises all of it against a running cluster:

```
 1  unsigned update (old wire format)                401
 2  sybil identity, self-signed                      401
 3  forged signature on enrolled identity            401
 4  tampered weights, stale signature                401
 5  replay of a captured valid update                401
 6  valid signature, timestamp 1h old                401
 7  second update inside the rate-limit window       429
 8  enrolled peer sends 50x scaled weights           409
 9  enrolled peer sends wrong dimension              400
10  enrolled peer sends NaN weights                  400
```

The suite asserts the global model is unchanged when it finishes.

`GET /health` reports enrolled peers, active peers and rejection counts by reason.

`GET /weights` reports the peer count and the Byzantine tolerance actually achieved.
Coordinate-wise median requires `K >= 2f+1`; with two gateways it returns
`byzantine_tolerance: 0, robust: false` rather than implying protection it cannot deliver.

## Methodology notes

Two dataset-construction pitfalls materially affect results in this domain and are
documented in §VI-B:

1. **Split on unique payloads before resampling.** Sampling train and test independently
   from the same pool places identical payloads in both. With 260 unique SQLi strings
   available, the effect is severe.
2. **Use one request template for both classes.** Rendering benign traffic as
   `GET /{path}?v={n}` and attacks as `GET /search?q={payload}` lets the classifier
   separate URL shape instead of maliciousness — it reaches ROC-AUC 1.000 on attack
   classes it never trained on.

## Status

The gateway inspects the request line only -- **no POST bodies, no headers, no
cookies**. Detection figures are measured on query strings. This is the largest
gap between the prototype and a deployable WAF.

Differential privacy is specified but **not implemented**; no epsilon is claimed.
ML-KEM is benchmarked as a component and is not yet wired into the live weight channel.
See the Limitations section of the manuscript.

`legacy/` holds superseded material with an explanation of why each item was replaced.
