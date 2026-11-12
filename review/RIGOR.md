# RIGOR.md — Experimental rigor audit of FedZTA-Edge

Reviewer stance: skeptical peer reviewer. Scope: `fl_simulation_v4.py`, `train_production_model.py`,
`seed_stability.py`, `poisoning_experiment.py`, `bandwidth_analysis.py`, `edge_profiler*.py`,
`stress_test.py`, `continuous_waf.py`, `robust_cloud.py`, the result JSONs, and the evaluation/security
sections on the paper branches (`office/bolt-d4c2`, `office/cosmo-3344`). The paper itself is not edited.

Method: static reading of code and committed result files. Scripts download SecLists from the network
and the gateway/cluster tests need live hardware, so **nothing was re-run**; numbers below are quoted from
`matrix_results.json`, `fed_model.json`, `poisoning_results.json`, `bandwidth_results.json`.
Where I estimate rather than measure, it is marked **(estimate)**.

The new paper's Evaluation section is already unusually candid (it admits within-noise gains, stale
artefacts, no result at the deployed threshold). This audit does not repeat those admissions as news;
it ranks them, adds what the paper does not say, and prices the fixes.

## Verdict

The engineering is careful and the honesty is above average, but the evidence does **not** currently
support the headline claims that matter for a security venue: that the system detects injection attacks
in real traffic, that federation improves detection, and that the poisoning defence is meaningful.
The benchmark is close to trivially separable, has no baselines, and the deployed operating point was
never evaluated. The bandwidth and latency claims are valid arithmetic on favourable assumptions.

## Weaknesses ranked by severity

Severity: **S1** invalidates a headline claim · **S2** seriously weakens a claim · **S3** should be fixed before submission.

### S1-1. The benign class is a directory-brute-force word list, not traffic
`raft-small-words.txt` (web) and `api-seen-in-wild`/`api-endpoints`/`graphql.txt` (API) are *path
tokens*: short, alphanumeric, no punctuation. Attacks are punctuation-dense fuzz strings. Separating them
needs essentially "fraction of non-alphanumeric characters", which is feature #2 of the 3 syntactic
features.

Evidence inside the repo that the task is near-trivial:
- 3 scalar features alone reach ROC-AUC 0.9902–0.9919 (domain axis); 259 hashed n-grams reach 0.9918
  on the D=64 matrix and 0.9947 for the shipped model. The n-gram machinery buys ≈0.002 AUC, inside
  one std (0.003). Syntactic/attack: Edge B, trained *only on SQLi*, scores 0.9891 on a test set that is
  half XSS. Cross-class transfer this large means the model is not learning attack semantics.
- Edge B (SQLi-only, attack axis, n-gram) **beats** the federated model (0.9895 vs 0.9826 AUC).
- The augmentation exists precisely because the first models learned length (paper, §Data augmentation).
  That is a discovered shortcut; the fix removes the shortcuts the authors thought of, not ones they did not.

Consequence: a ceiling effect. All methods land at 0.98–0.995 AUC, so the benchmark cannot rank them,
and the absolute numbers say nothing about false positives on real requests (names with apostrophes,
search text, base64, JSON, URLs with `&=%`), which is where WAFs actually fail.

### S1-2. No baselines of any kind
Missing, in order of how badly it hurts:
1. **Centralised/pooled training** (same data, one model). Without it, "federation" is only compared
   with *less data*. The only honest claim available is "federated ≈ pooled", and that is untested.
2. **Existing WAF**: ModSecurity with OWASP Core Rule Set (paranoia levels 1–4), plus
   libinjection (SQLi/XSS tokenizer, widely embedded; I am confident it exists, Nick Galbreath).
   Report detection and FPR at each paranoia level on the same payloads and the same benign data.
3. **A trivial detector**: regex or "contains one of `' < > ; -- ( )`". If this scores ≈0.98 AUC the
   ML adds nothing on this benchmark (S1-1 suggests it will).
4. **Stronger learners**: gradient-boosted trees or a char-CNN on the same features/data, to show the
   linear model is not leaving headroom, and a standard FL variant (FedProx — Li et al. 2020, which the
   paper already cites as `li2020convergence`) to show FedAvg is not the weak link.
5. Standard public WAF datasets, e.g. CSIC 2010 HTTP dataset (I believe this is Giménez et al.; confirm
   before citing) and CIC-IDS-style web-attack traffic (uncertain which exact release has labelled
   SQLi/XSS; verify).

### S1-3. Deployed operating point was tuned post hoc and never evaluated
- `BLOCK_THRESHOLD = 0.15` (`continuous_waf.py:37`) was set after augmentation moved the intercept
  (commit bd99871). No validation split exists, so the threshold was chosen by looking at outputs on
  data from the same corpora. There is no result file for detection or FPR at 0.15.
- All reported FPR numbers use threshold 0.5; recall is reported at "0.1% FPR". The gateway runs at neither.
  Lowering 0.5 → 0.15 in probability space can easily multiply false positives; the unquantified number
  is the one an operator cares about.
- Evaluation scores one whole wrapped string per sample. The gateway scores path, query, `User-Agent`,
  `Referer`, `Cookie` and body **separately** and blocks on the max (`continuous_waf.py:151-199`).
  Training and serving differ (train/serve skew), and max-over-k-contexts inflates FPR roughly with k
  (up to k× in the worst case **(estimate)**). No experiment reproduces the gateway's real scoring path.
  Note too that the README "Status" says the gateway inspects the request line only and no headers/bodies,
  contradicting the code and the paper; one of them is stale.

### S1-4. "Federation helps" is not supported, and the selection was made on test results
Paper's own numbers (shipped model, 8 seeds): federated AUC 0.9947±0.0019 vs Edge B 0.9938±0.0036,
Δ=+0.0009, ≈0.25 std; federated > Edge B in 5/8 seeds (sign-test two-sided p≈0.73). SQLi recall is
*lower* than Edge B (0.865 vs 0.879). The domain-split configuration was chosen *because* it was "the
only cell in which federated outperforms every silo" (`train_production_model.py` docstring) — selecting
the favourable cell of a 4-cell grid on the evaluation metric, then reporting that cell. Winner's-curse
applies. Further:
- In the "domain" axis both nodes draw attacks from the **same** training pool (`xss_tr`, `sqli_tr`), so
  attack knowledge is IID-shared; heterogeneity exists only in the benign class. "Federation" of two
  shards of one corpus is the easiest possible case.
- Only K=2 nodes; the "silo" baseline is just half the data. Edge B trains on 5.6k API benign samples
  but evaluates on a test set that is 50 % web, so differences reflect test mix, not federation.
- `seed_stability.py` was written to settle this, but it reuses **one fixed payload split**
  (`np.random.default_rng(12345)`) across all seeds, so it only varies init/sampling and **under-estimates**
  variance relative to `matrix_results.json`. It also targets the unaugmented D=64 configuration, and no
  output of it is archived.

### S2-1. Statistics: no CIs, replicated test samples, razor-thin operating point
- Reported ± is `np.std` (ddof=0) over 8 seeds; no confidence intervals, no paired tests.
- Test attack sets are drawn **with replacement** from 205 (SQLi) / 157 (XSS) unique held-out payloads
  to 500 draws each (`draw()`), then randomly wrapped. Effective n is ≈200/157, not 500; the nominal
  sample size overstates precision, and each seed's recall is quantised in jumps ≥1/205.
- "Recall @ 0.1 % FPR" over 1,500 benign test samples puts the threshold at the 2nd-highest benign
  score (`floor(0.001×1500)=1`): the operating point is set by ~1–2 benign samples, hence the ±0.06–0.11
  std on SQLi recall. Report FPR ∈ {1 %, 0.1 %} with benign ≥10⁵ draws, or use bootstrap CIs over unique payloads.
- Split-by-unique-string does not prevent **near-duplicate leakage**: sqlmap/fuzzdb lists contain
  many variants differing by a constant or a quote style, and several XSS lists overlap. Exact dedup ≠
  disjointness. Need clustering/edit-distance grouping, or split by source file / attack family.
- Per-seed vs aggregate mismatch: `fed_model.json` stores coefficients and metrics of the **last** seed (49)
  while its config says `shipped_seed: 42`. The shipped model is therefore not the one labelled as such,
  and its test split is not reproducible from the stated seed.

### S2-2. Poisoning and adversarial coverage is nominal
- One seed, one attack (−12× sign-flip, 2 of 7 nodes). This is the weakest meaningful attack; the
  deployed L2 norm gate (ratio >4) would reject it before aggregation. The experiment therefore tests
  median/trimmed-mean in isolation, not the shipped pipeline (auth → rate limit → norm gate → median).
- Not tested: ALIE-style in-distribution attacks (Baruch et al. 2019, "A Little Is Enough"), the
  aggregation-aware local-model poisoning of Fang et al. 2020 (cited, not run), data poisoning /
  label-flipping at the edge, backdoors (Bagdasaryan et al. 2020), collusion with f at the 2f+1 bound,
  and adaptive timing. Honest nodes also all train on shards of the same pool, which flatters the median;
  heterogeneous honest nodes (web vs API profiles) widen honest spread and are exactly where
  median/trimmed mean lose accuracy (already visible: median 0.958 vs mean 0.984 *before* the attack).
- The simulation uses a different data pipeline from production (plain `GET /search?q=`, no augmentation,
  only `Generic-SQLi.txt`, 400 attacks per node).
- Physical testbed K=2 ⇒ f=0; the paper says so. The robust-aggregation story is therefore simulation-only.
- **No input-space evasion evaluation at all.** A linear model on lowercase hashed 3-grams: trivially
  evaded by case/comment/whitespace mutation (`UN/**/ION`), URL/double-encoding (the gateway
  `unquote`s once), Unicode, SQL token reordering, benign-padding to dilute the L2-normalised n-gram
  vector, and — since the vector is L2-normalised — appending benign n-grams shrinks every attack bucket.
  Evasion tools like sqlmap tamper scripts (exist; I am confident) are the standard probe.
- "Federated learning on live traffic" is effectively inactive: pseudo-label learning was removed to
  avoid drift; local updates come only from `anchor_set.json` (211 bytes) replayed every 60 s. The
  running system averages near-identical, nearly static models; the learning-from-live-attacks narrative
  has no experiment behind it (`stress_continuous.py` exercises the loop, not detection benefit).

### S2-3. Bandwidth claim is arithmetic on a convenient baseline, and the unit is wrong for the wire
- `bandwidth_analysis.py` is analytic, not measured on the wire, despite its docstring's "Measured".
- Federated cost uses 1,040 B (259 float32 + bias). The implementation sends **JSON text**: the
  coefficient list alone is 5,395 B in `fed_model.json` (≈5.2×), plus HMAC, nonce, timestamp, HTTP
  headers, and TLS/PQ-KEM overhead if wired (ML-KEM-512 public key 800 B, ciphertext 768 B per FIPS 203).
  Real sync cost is **(estimate)** 6–8 KB/exchange, which still wins at high rates but moves break-even
  and the 20-round 75 % figure.
- Centralised baseline ships 27.4 B of bare payload per request (word-list artefact). Real log shipping
  carries headers/metadata (larger → favours FL), but a realistic alternative is *sampled or flagged-only*
  shipping or aggregated counters, which the paper does not consider. A 99.9 % reduction against
  "ship every request to the cloud" is a strawman for a WAF.
- No accounting for cloud→edge broadcast of a model per sync interval beyond the 2-direction factor,
  no packet loss/retries, K=2 only (aggregator fan-in at K=100 is untested).

### S2-4. Latency / edge-device claims are not backed by archived measurements
- ARM numbers (0.229 ms inference, 10.4 MB RSS, 452.5±24.3 req/s, 20.5 ms median, 32.2 ms p95, ML-KEM
  timings) come from the **old draft**, not a result file; the paper admits this. Re-measure and commit raw logs.
- `edge_profiler*.py` benchmark a loop of 4 short strings repeated 2,500×: warm cache, tiny inputs, no
  allocation pressure. Feature extraction is O(len); the gateway accepts bodies to 8 KB and scores each
  context separately. By linear extrapolation **(estimate)** an 8 KB body costs tens of ms of pure-Python
  time on a Cortex-A72 — a CPU-exhaustion vector the benchmark cannot see.
- `stress_test.py` targets a hard-coded LAN IP, one benign GET (`/api/v1/sensors/temp`), one asyncio
  client at concurrency 10 (the load generator itself may bound throughput; not checked). No mixed
  attack/benign load, no blocked-request path cost, no comparison with a bare reverse proxy
  (nginx/Caddy) or ModSecurity on the same board, so the *overhead* of the classifier is never isolated.
- RSS is `ru_maxrss` of the profiler process, not the gateway under load with threads and a sync loop.
  No CPU %, temperature/throttling, energy, or tail latency under sustained load (p99.9, minutes→hours).
- Two Raspberry Pi 4 boards on one LAN with the aggregator is not "edge": no WAN RTT/jitter, no
  heterogeneous or constrained devices (Pi Zero/Cortex-M-class gateways), no intermittent connectivity.

### S3-1. Reproducibility
- Data is fetched from `SecLists/master` at run time: a moving target with no commit pin or checksum.
  Evidence of drift already: README cites "260 unique SQLi strings"; production now has 681.
- No `requirements.txt`/lockfile, Python/numpy/sklearn versions unrecorded; global mutable `SEED`
  (`fl_simulation_v4.py`, set from `main()`); `fed_model.json`/`matrix_results.json` overwritten in place, no run logs.
- **Stale artefacts disagree**: README headline table (AUC 0.9850, XSS 1.000, SQLi 0.792) does not match
  `fed_model.json` (0.9947 / 0.980 / 0.865). `fl_sweep.pdf` D-sweep is hard-coded in `make_figures.py`
  from a pre-augmentation run; `fl_metrics.pdf` is a single seed (49) that favours federation.
- `test_auth_attacks.py` needs live infrastructure; its outputs are not archived (paper concedes).
- Reproduction needs two Raspberry Pis, an x86 server, and `pqcrypto`; nothing runs in CI, and the hardcoded IP
  makes `stress_test.py` unrunnable elsewhere.

## What the paper can honestly claim today
1. On public fuzzing lists vs path-word lists, a hashed-n-gram logistic regression separates attacks with
   AUC ≈0.99 (this is largely a punctuation detector).
2. FedAvg of two nodes is about as good as the better isolated node and avoids the worse node's cross-domain
   FPs, in a split where attack data is shared.
3. Coordinate-wise median/trimmed mean survive a naive 12× sign-flip at K=7, f=2, one seed.
4. Gateway overhead in a micro-benchmark of short strings is sub-millisecond; HTTP stack dominates on a Pi.
5. Weight sync is orders of magnitude smaller than shipping every request — against that one alternative.

Not supported: real-world detection/FPR, benefit of federation over pooled or best-silo, robustness to
adaptive poisoning or evasion, deployed-threshold behaviour, edge scalability beyond K=2.

## Extra experiments needed (priority order, effort for one person who knows the code)

| # | Experiment | Closes | Effort |
|---|---|---|---|
| 1 | Realistic benign set: replay real HTTP logs / public benign web traffic (CSIC-2010 normal class, or captured traffic from a test web app; also random real search queries, JSON, base64, names with apostrophes). Report FPR at deployed threshold on ≥10⁵ requests. | S1-1, S1-3 | 3–5 d |
| 2 | Baselines on identical splits: pooled model; regex/char-set rule; libinjection; ModSecurity+CRS at PL1–4 (Docker); tree/char-CNN; FedProx. | S1-2 | 4–6 d |
| 3 | Proper split protocol: train/val/test by attack family or source file (grouped CV), threshold & augmentation chosen on val only, final test once; cluster near-duplicates. | S1-3, S1-4, S2-1 | 2–3 d |
| 4 | Evaluate the deployed pipeline end-to-end: HTTP requests through `continuous_waf.py` at threshold 0.15, per-context max scoring, ROC/DET curve and FPR vs threshold sweep. | S1-3 | 2 d |
| 5 | Re-run seed study correctly: re-split per seed, ≥30 seeds, paired bootstrap CIs over unique payloads, grouped by family; report federated vs pooled vs best silo; archive logs. Fix `fed_model.json` seed mismatch. | S1-4, S2-1 | 1–2 d |
| 6 | Federation under real heterogeneity: K∈{2,5,10,20}, Dirichlet/label-skew and per-node attack campaigns (truly disjoint attack data), partial participation, stragglers. | S1-4 | 3–4 d |
| 7 | Adaptive evasion: sqlmap tamper scripts, encoding/case/comment mutation, benign-padding against the L2-normalised n-gram vector, gradient-guided GCG-style token edits on the known linear model (white-box worst case). Report evasion rate vs FPR. | S2-2 | 4–6 d |
| 8 | Poisoning suite through the real aggregator pipeline: sign-flip, ALIE, Fang-style rule-aware attack, label-flip/data poisoning, backdoor trigger; f up to the 2f+1 bound; ≥10 seeds; include norm gate on/off. | S2-2 | 5–7 d |
| 9 | Bandwidth on the wire: pcap of real sync (JSON/HMAC/TLS or PQ-TLS), K up to 50, loss; compare against sampled/flagged-only shipping and counter aggregation. Binary float32 encoding as optimisation. | S2-3 | 2–3 d |
| 10 | Edge re-measurement with archived raw logs: payload-length sweep to 8 KB, mixed attack/benign, nginx and ModSecurity baselines on the same Pi, CPU/temp/RSS of gateway under load, p99/p99.9, multi-hour run, second device class, WAN-emulated link (`tc netem`). Use a separate load-generator host and `wrk`/`k6` to rule out client bound. | S2-4 | 4–5 d |
| 11 | Reproducibility pack: pin SecLists commit+SHA256, `requirements.txt`/lock, single `make reproduce`, regenerate every figure from JSON (incl. D-sweep), remove stale README table, CI smoke test with mock data. | S3-1 | 2 d |
| 12 | Quantify the "live learning" claim or drop it: inject attacks at the edge, measure time-to-detect and cross-node propagation with the anchor-set mechanism. | S2-2 | 2–3 d |

Total ≈ 5–7 person-weeks for everything. Minimum viable set to make the central claim defensible:
**#1, #2, #3, #4, #5** (≈3 weeks); add **#7, #8** (≈2 weeks) for a security venue.

## Quick wins with no new experiments (≤1 day)
- State plainly in the abstract that detection is on fuzz-list vs path-word data and does not estimate
  production FPR; drop "federation outperforms" wording; present federated as "≈ best silo".
- Report n unique attack payloads (205/157) next to every recall, and quote CIs, not ±std.
- Label the poisoning result "median/trimmed mean in isolation, naive attack, 1 seed".
- Fix README headline table and `fed_model.json` seed field; resolve README "request line only" vs code.
- Replace 1,040 B with the real wire size, or send float32 binary.
- Mark every uncertain citation above (CSIC 2010; CIC web-attack datasets) as "verify" before use.
