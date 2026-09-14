# `federated_paper_v4_final` — Fix List

Audit date: 2026-09-14. Target: `federated_paper_v4_final.tex` (280 lines) + supporting scripts.

All line refs are `federated_paper_v4_final.tex` unless another file is named.

## Testbed — confirmed live

| Host | Role | Arch | Python | Notes |
|---|---|---|---|---|
| `192.168.1.144` | Cloud Aggregator | x86_64, 14 cores, 31 GB | 3.12.3 | `robust_cloud.py` + `cloud_pqc.py` running. `~/venv` has **sklearn 1.9.0** |
| `192.168.1.147` | Edge Node 1 (`edgedataspace`) | aarch64 Cortex-A72, 3.8 GB | 3.13.5 | `continuous_waf.py` running on :8080. `~/venv` has `pqcrypto` |
| `192.168.1.115` | Edge Node 2 (`edgedataspace2`) | aarch64 Cortex-A72, 3.8 GB | 3.13.5 | `continuous_waf.py` running on :8080 |

SSH is key-based and non-interactive — `ssh -o BatchMode=yes <host>` works to all three.

**Local Mac cannot run the simulations**: the installed sklearn is an x86_64 wheel on an arm64 Mac —
`ImportError: ... incompatible architecture (have 'x86_64', need 'arm64')`.
Run all sklearn work on `192.168.1.144` via `~/venv/bin/python`, or reinstall locally:
`pip3 install --force-reinstall --no-cache-dir scikit-learn numpy scipy`.

---

# P0 — Blocking. Do not submit until these are resolved.

## P0-1. Figure 2 is fabricated data presented as measurement

`poisoning_sim.py:8-16` contains three hardcoded Python lists. No model is trained, no weight is
poisoned, no aggregation runs. The file only calls `matplotlib`.

```python
f1_honest         = [0.6, 0.75, 0.82, 0.88, 0.91, 0.93, 0.94, 0.94, 0.94, 0.94]
f1_poisoned_mean  = [0.6, 0.75, 0.82, 0.30, 0.15, 0.05, 0.02, 0.01, 0.0, 0.0]
f1_poisoned_median= [0.6, 0.75, 0.82, 0.83, 0.86, 0.88, 0.90, 0.92, 0.93, 0.94]
```

The paper presents this as an experiment:

- `:120` caption — *"Median aggregation sustains a robust 0.94 F1-Score."*
- `:124` — *"As shown in Fig. 2, injecting a malicious weight vector at round 4 causes the traditional Mean-based FedAvg to collapse entirely (F1-Score approaching 0.0)."*

Nothing was injected. Publishing this as empirical is fabrication.

**Fix — pick one:**

- **(a) Run it for real.** Write `poisoning_experiment.py`: ≥5 edge models on disjoint SecLists
  shards, 10 FedAvg rounds, from round 4 have 1 node upload `w_malicious = -λ·w_honest` (λ≈10).
  Aggregate twice per round — arithmetic mean and coordinate-wise median — and evaluate both on a
  held-out test set each round. Plot the measured F1. Requires K≥5; see P0-4.
- **(b) Relabel as illustrative.** Caption becomes *"Conceptual illustration of the expected
  divergence between mean and median aggregation under Byzantine poisoning; not measured."* Rewrite
  `:124` in the conditional. Weakens the paper considerably — prefer (a).

Verify: `ssh 192.168.1.144 '~/venv/bin/python poisoning_experiment.py'`

## P0-2. Train/test contamination in every class

`fl_simulation_v2.py:52-54` draws training and test sets from the same pools with `np.random.choice`
(replacement, no split):

```python
edge_A_traffic     = make_normal(raw_normal, 2000) + make_malicious(raw_xss,  1000, "POST")
edge_B_traffic     = make_normal(raw_normal, 2000) + make_malicious(raw_sqli, 1000, "GET")
global_test_traffic= make_normal(raw_normal, 1000) + make_malicious(raw_xss,   500, "POST") \
                                                   + make_malicious(raw_sqli,  500, "GET")
```

Source pool sizes (`sim_results.txt:2`): **268 SQLi, 17 XSS, 43,007 normal**.

So 500 test XSS samples are resampled from the same **17 unique strings** used to build the 1,000
training XSS samples. Identical payloads appear in both sets. Same for SQLi (268 unique) and normal.

Consequence: the "unseen zero-day" framing in the title, abstract (`:28`), and `:207` is invalid as
run. F1 = 0.94 measures memorization of 17 strings.

**Fix:** split by *unique payload* before expansion.

```python
rng = np.random.default_rng(42)
def split_pool(pool, frac=0.7):
    pool = sorted(set(pool)); idx = rng.permutation(len(pool)); k = int(len(pool)*frac)
    return [pool[i] for i in idx[:k]], [pool[i] for i in idx[k:]]

sqli_tr,  sqli_te  = split_pool(raw_sqli)    # ~188 / 80
xss_tr,   xss_te   = split_pool(raw_xss)     # ~12 / 5   <-- see P0-3
norm_tr,  norm_te  = split_pool(raw_normal)  # ~30k / 13k
```

Then build Edge A from `xss_tr`+`norm_tr`, Edge B from `sqli_tr`+`norm_tr`, test from the `_te` pools
only. **Expect F1 to drop.** Report the honest number.

## P0-3. XSS corpus is 17 unique strings

`sim_results.txt:2` — `Downloaded: 268 SQLi, 17 XSS, 43007 Normal words`.

`XSS-Bypass-Strings-BruteLogic.txt` yields 17 lines. After the P0-2 split that leaves ~5 test XSS
payloads. No meaningful F1 can be computed on 5 samples.

**Fix:** add XSS sources so the pool is ≥500 unique before splitting. Candidates in SecLists:

```
Fuzzing/XSS/XSS-Somdev.txt
Fuzzing/XSS/XSS-Jhaddix.txt
Fuzzing/XSS/XSS-BruteLogic.txt
Fuzzing/XSS/robot-friendly/XSS-Cheat-Sheet-PortSwigger.txt
```

Update `fl_simulation_v2.py:19` to fetch and union them. Then restate `:177` with the actual unique
count and the exact file list.

## P0-4. Coordinate-wise median gives zero Byzantine tolerance at K=2

`:115` claims the median aggregator *"naturally filters out extreme outlier weights."*
`:169` states the deployed cluster is one cloud + **two** edge nodes.

Median of two values is their mean. With K=2 there is no majority to appeal to — one Byzantine node
is 50% of the population. The robustness argument in §V-A is void at the scale actually deployed.

`robust_cloud.py:19-21` compounds this: the sliding window keeps the last **10 updates**, not the
last update from each of 10 nodes. With 2 nodes posting continuously the window holds ~5 rounds ×
2 nodes — a median over *time*, not over *peers*. That defends against transient drift, not against a
persistently malicious node, which will occupy half of every window.

**Fix — both required:**

1. State the requirement explicitly: coordinate-wise median tolerates `f` Byzantine nodes only for
   `K ≥ 2f+1`. Add this to §V-A and acknowledge K=2 in §VII-C provides `f=0`.
2. Either scale the poisoning experiment to K≥5 (simulated nodes are fine — say so), or rewrite
   `robust_cloud.py` to key the window by client id so the median is genuinely per-peer:

```python
# keyed by client id, one slot per node — median over peers, not over time
latest = {}                     # client_id -> (weights, bias)
latest[data['client_id']] = (data['weights'], data['bias'])
ws = list(latest.values())
global_weights = [statistics.median([w[i] for w,_ in ws]) for i in range(3)]
global_bias    = statistics.median([b for _,b in ws])
```

Then `continuous_waf.py` must send a stable `client_id` in its `/update` POST.

## P0-5. The profiled micro-inferencer has a 100% false-positive rate

`edge_profiler.py:8-9` hardcodes the model:

```python
FEDERATED_COEF = [-0.015, 1.25, 3.42]
FEDERATED_INTERCEPT = -2.10
```

Rerun on `192.168.1.147` — reproduces the paper's Table II exactly, and reveals the problem:

```
Total Requests Analyzed: 10000
Requests Blocked (Anomalous): 10000      <-- all of them
Total Inference Time: 0.347 seconds
Average Latency per Request: 0.035 ms
Peak RAM Usage: 9.14 MB
```

Per-payload check on the node:

```
pred=1  [len=27, spec=6,  H=4.28]  'GET /api/v1/resource?id=123'     <-- benign, blocked
pred=1  [len=39, spec=11, H=4.36]  'GET /search?q=<script>alert(1)...'
pred=1  [len=20, spec=4,  H=3.88]  'GET /images/logo.png'            <-- benign, blocked
pred=1  [len=5,  spec=2,  H=2.32]  'GET /'                           <-- benign, blocked
pred=0  [len=1,  spec=0,  H=-0.0]  'a'
```

The entropy coefficient (3.42) dominates; anything with entropy above ~0.6 is flagged. The model the
paper profiles for latency and RAM cannot classify. Table II and §VIII-B are therefore measuring the
speed of a broken classifier, and the paper never says so.

**Fix:** derive the coefficients from the actual FedAvg output (P0-6), drop them into
`edge_profiler.py`, rerun, and report `Requests Blocked` alongside latency so the number is visible.

## P0-6. Three mutually inconsistent "federated" models in the repo

| Source | Features | Coefficients | Intercept |
|---|---|---|---|
| `fl_simulation_v2.py:56-62` | **4** — len, benign_chars, malicious_chars, entropy | printed at `:102`, never saved | `:103` |
| `edge_profiler.py:8-9` | **3** — len, special_chars, entropy | `[-0.015, 1.25, 3.42]` | `-2.10` |
| `continuous_waf.py:16-17`, `robust_cloud.py:29` | **3** — len, special_chars, entropy | `[0.01, 1.2, 0.5]` | `-7.5` |

`edge_profiler.py:6` comments *"Extracted from Federated Learning (Cloud)"* — it cannot have been;
the simulation produces a 4-coefficient vector. None of the three trace back to a FedAvg run.

The paper describes one architecture and silently mixes results from all three:

- §IV-A `:81` defines `X ∈ R^3` — matches `continuous_waf.py`, **not** the simulation
- §VIII-A F1 = 0.94 comes from the **4-feature** simulation
- §VIII-B Table II latency/RAM comes from `edge_profiler.py`'s **third** weight set

**Fix:**

1. Decide on the 3-feature vector (matches the paper text and the deployed WAF).
2. Change `fl_simulation_v2.py:56-62` to emit exactly those 3 features:
   ```python
   def extract_features(payload):
       length = len(payload)
       special = sum(1 for c in payload if not c.isalnum())
       prob = [payload.count(c)/length for c in dict.fromkeys(payload)] if length else []
       entropy = -sum(p*math.log2(p) for p in prob) if prob else 0.0
       return [length, special, entropy]
   ```
3. Have the simulation **write** `fed_model.json` with the learned coefficients.
4. Make `edge_profiler.py`, `continuous_waf.py` and `robust_cloud.py` load that file instead of
   hardcoding. One model, one provenance, end to end.

## P0-7. The headline claim is contradicted by the paper's own results

`sim_results.txt:8-10`:

```
Edge A (Trained only on SecLists XSS) F1-Score: 0.94
Edge B (Trained only on SecLists SQLi) F1-Score: 0.93
Federated Model F1-Score: 0.94
```

The federated model **ties** the best isolated node. Yet:

- `:28` abstract — *"significantly outperforming isolated silos"*
- `:47` contribution 2 — *"demonstrating a superior F1-Score (0.94) compared to isolated learning"*
- `:207` — *"the isolated nodes performed poorly (F1-Score ≈ 0.93/0.94 is acceptable but flawed...)"*

`:207` is also internally incoherent: it calls 0.94 "poorly" and then reports the federated model's
0.94 as the win.

Root cause: aggregate F1 over a test set that is 50% normal traffic drowns the per-class signal. The
real result is hiding one level down — `:207` already asserts *"Node A misclassified every SQLi
attack as normal traffic"*, which is the actual finding and is never quantified.

**Fix:** report **per-attack-class recall**, which is where federation genuinely wins.

```python
from sklearn.metrics import recall_score, classification_report
mask_sqli = np.array([lbl==1 and 'q=' in p and 'script' not in p for p,lbl in global_test_traffic])
mask_xss  = np.array([lbl==1 and 'script' in p for p,lbl in global_test_traffic])
for name, m in [("SQLi", mask_sqli), ("XSS", mask_xss)]:
    for mdl_name, pred in [("A",y_pred_A), ("B",y_pred_B), ("Fed",y_pred_fed)]:
        print(f"{name:5s} recall  {mdl_name:3s}: {recall_score(y_test[m], pred[m]):.3f}")
print(classification_report(y_test, y_pred_fed, digits=3))
```

Expect: Edge A ≈ 0.0 SQLi recall, Edge B ≈ 0.0 XSS recall, Federated high on both. Rewrite `:28`,
`:47`, `:207` around that table. Also report precision and FPR — §IX claims false positives on JWT
endpoints but never measures the rate.

---

# P1 — Numbers that contradict each other or the code

## P1-1. Table I contradicts the simulation

`:187-188` claim Edge A and Edge B each train on **4,000** normal samples.
`fl_simulation_v2.py:47` sets `n_train_normal = 2000`. Off by 2×.

The attack and test columns do match the code (`:48-50` → 1,000 / 1,000 / 500 / 500).

**Fix:** regenerate Table I from the script's actual constants after P0-2 changes the split anyway.
Add a "Unique payloads" column — resampled counts alone hide the 17-string problem.

## P1-2. ML-KEM latency — two values in the paper, both wrong

- `:227` §VIII-B — **0.26 ms**
- `:250` Conclusion — **0.28 ms**

Both came from single cold-start runs of `edge_pqc.py:14-16`, which times one `encaps()` call right
after process start and a network fetch. Rerunning it now gives 0.25 ms — the number is not stable.

Proper benchmark on `192.168.1.147` (Cortex-A72, 50-iteration warmup, n=1000, `perf_counter`):

```
ENCAPS  mean 0.162 ms | stdev 0.002 | p50 0.162 | p95 0.163 | min 0.162 | max 0.180
DECAPS  mean 0.205 ms | stdev 0.003 | p50 0.204
KEYGEN  mean 0.122 ms | stdev 0.002
sizes:  pk=800  ct=768  ss=32  sk=1632 bytes
```

**Fix:** replace both figures with **0.162 ms ± 0.002 (n=1000)**. Report decaps and keygen too — a
KEM handshake is not encaps alone. The 800-byte public key claim at `:227` is correct. Add the
benchmark harness to the repo so the number is reproducible.

## P1-3. Throughput — three different numbers, never reconciled

- `:225` §VIII-B — **218 RPS**, p50 **18.56 ms**
- `:230` §VIII-C — 200 requests in 6.29 s ≈ **31 RPS** per node
- `:250` Conclusion — **62 RPS** across the cluster

62 is 31+31, but the paper never says so, and 218 vs 62 sits unexplained in abstract-adjacent text.

Rerunning `stress_test.py` (1,000 requests, concurrency 10, against `.147`) right now:

```
Time taken:  4.06 s
Requests/s:  246.06 RPS
Successful:  1000    Failed: 0
p50 29.11 ms | p95 110.94 ms | p99 169.24 ms
```

246 RPS / p50 29.11 ms vs the paper's 218 / 18.56. Single-run variance over the LAN is large and
unreported.

**Fix:**

1. Run `stress_test.py` ≥10 times, report mean ± stdev for RPS and each percentile.
2. Explain the 218-vs-62 gap in the text. They measure different things: 218/246 is idle-path
   inference throughput; 31/node is throughput *with* SGD backpropagation on every request.
3. **Important caveat to state:** `continuous_waf.py` serves via `http.server.HTTPServer`, a
   single-threaded `BaseHTTPRequestHandler`. Given inference is 0.035 ms, ~246 RPS is almost entirely
   Python HTTP-stack overhead — it is *not* the ML inference ceiling. The paper currently implies it
   is. One sentence fixes this and actually strengthens the argument.

## P1-4. `99.95\%` confidence is unverifiable

`:232` — *"Edge Node 1 retained its ability to block targeted XSS attacks with 99.95\% confidence."*

`stress_continuous.py:45-53` prints only HTTP status codes. No script in the repo computes or emits
that number. Every `.log` on all three nodes is empty (`waf.log` is 0 bytes) — no raw artifact exists
for it, nor for 218 RPS, 0.035 ms, 9.14 MB, or 0.26 ms.

**Fix:** make `continuous_waf.py` return the sigmoid probability in its response body, have
`stress_continuous.py` record it, and write a CSV. Then quote the measured value. If it cannot be
reproduced, delete the claim.

## P1-5. Sync window: 15 s in the paper, 18 s in the code

`:169` and `:232` say 15 seconds. `stress_continuous.py:37` — `for i in range(18, 0, -1)`.

**Fix:** pick one. If the aggregator's period is 15 s, the test should wait longer than one period on
purpose — say that, rather than stating a wrong number.

## P1-6. Bandwidth arithmetic

`:244` — *"only the 4 floating-point scalars of the SGD model (3 coefficients + 1 intercept)"*.

Correct for the 3-feature model, **wrong** for the 4-feature model that produced the F1 results
(5 scalars). Resolving P0-6 fixes this — just make sure the final text matches whichever model wins.

Two further problems:

- `:235` says *"For our 10,000-payload dataset, this represents approximately 500 KB"*. The dataset
  elsewhere is 9,000 samples (Table I) or 43,007 (abstract). Three different sizes.
- The comparison is one-shot raw upload vs **one round** of weights. §VI `:152` says convergence
  takes **20 rounds**, and weights flow both ways across K nodes. Honest total:
  `20 rounds × 2 nodes × 2 directions × 0.01 KB = 0.8 KB`. Still a ~99.8% reduction — the claim
  survives, so make it correctly.

**Fix:** one dataset size, stated once. Total bytes over the full training run, both directions.
Recompute the percentage.

---

# P2 — Build, citations, structure

## P2-1. The PDF currently renders `??` and `[?]`

`federated_paper_v4_final.log`:

```
696: LaTeX Warning: Reference `fig:poisoning' on page 3 undefined on input line 124.
700: LaTeX Warning: Citation `friend_pqtls' on page 3 undefined on input line 140.
719: LaTeX Warning: Reference `fig:metrics' on page 4 undefined on input line 207.
729: LaTeX Warning: Reference `fig:bandwidth' on page 5 undefined on input line 244.
786: LaTeX Warning: There were undefined references.
789: LaTeX Warning: Label(s) may have changed. Rerun to get cross-references right.
```

Only one `pdflatex` pass was run. Every `\ref` and the one `\cite` are broken in the shipped PDF.

**Fix:** `pdflatex` is at `/Library/TeX/texbin/pdflatex`.

```sh
cd /Users/eldemaster/Documents/MIUN/FederatedZeroTrust
pdflatex -interaction=nonstopmode federated_paper_v4_final.tex
pdflatex -interaction=nonstopmode federated_paper_v4_final.tex
grep -E "undefined|Rerun" federated_paper_v4_final.log   # must be empty
```

## P2-2. Placeholder text left in the bibliography

`:277`:

```latex
\bibitem{friend_pqtls} [Nome Amico / Autore], ``Evaluating Post-Quantum TLS Performance for the
Internet of Things Using Raspberry Pi Devices,'' \textit{[Nome Conferenza o Journal]}, [Anno Pubblicazione].
```

Italian placeholders. This is the paper's only `\cite`, at `:140`.

**Fix:** fill in author, venue, year.

## P2-3. Sixteen bibliography entries, one `\cite` in the entire text

Only `\cite{friend_pqtls}` (`:140`) appears anywhere. Named in prose with no citation attached:

| Location | Named | Should cite |
|---|---|---|
| `:38` | ModSecurity | `\cite{modsecurity}` |
| `:40` | Gaia-X | `\cite{gaiaX2021}` |
| `:55` | Snort, Suricata | needs new entries |
| `:57` | Wang *et al.* | `\cite{wang2020}` |
| `:59` | McMahan *et al.* (2017) | `\cite{mcmahan2017}` |
| `:36` | Zero-Trust Architecture | `\cite{zheng2019}` |
| `:115` | Coordinate-wise Median | `\cite{blanchard2017}` |
| `:110` | Byzantine worker / poisoning | `\cite{fang2020}` |
| `:127` | model inversion / gradient leakage | needs Zhu *et al.*, *Deep Leakage from Gradients*, NeurIPS 2019 |
| `:128-132` | Differential Privacy | needs Abadi *et al.*, *Deep Learning with Differential Privacy*, CCS 2016 |
| `:138` | ML-KEM (Kyber) | needs **NIST FIPS 203** |
| `:144` | Gradient quantization | needs Alistarh *et al.*, QSGD, NeurIPS 2017 |
| `:148-152` | non-IID convergence bound | needs Li *et al.*, *On the Convergence of FedAvg on Non-IID Data*, ICLR 2020 |

**Fix:** attach every one. Reviewers flag an uncited bibliography immediately. FIPS 203 is the most
conspicuous omission given §V-C is a core contribution.

## P2-4. Section roadmap is stale

`:52` — *"Section III defines the threat model. Section IV details the proposed architecture.
Section V outlines the experimental setup. Section VI presents the results, followed by the
conclusion in Section VII."*

Actual structure: I Intro · II Background · III System Model · IV Proposed Architecture ·
V Advanced Threat Modeling · VI Convergence Analysis · **VII Experimental Setup** ·
VIII Evaluation · IX Discussion · **X Conclusion** · XI Future Work.

Sections V and VI were inserted in v2/v3 and the roadmap was never updated. The conclusion is X, not VII.

**Fix:** rewrite `:52`. Also consider merging §III-B (`:66-68`) into §V — two separate threat-model
sections covering overlapping ground reads as accretion.

## P2-5. Unimplemented defenses presented as architecture

§V-B (`:126-132`) is written as a system component but nothing implements it. `:128` says *"we
advocate for"* — correct — yet `:28` (abstract) claims nodes *"share only **encrypted** mathematical
weights."* No encryption is applied to the weight channel: `continuous_waf.py` POSTs plaintext JSON
to `http://192.168.1.144:5000/update`. PQ-TLS was benchmarked standalone (`edge_pqc.py`) and never
wired into the FL path.

`:132` also overclaims: *"rendering Gradient Leakage attacks mathematically infeasible."* DP bounds
an adversary's advantage by `(ε, δ)`; it does not make attacks infeasible. No ε is ever chosen.

**Fix:**

- Rewrite `:28` to say weights are transmitted in place of raw data, and mark DP and PQ-TLS as
  *proposed* rather than deployed.
- Soften `:132` to the actual guarantee, and name a concrete `(ε, δ)`.
- Best: actually wire `edge_pqc.py`'s KEM into the `continuous_waf.py` → `robust_cloud.py` channel.
  The measured cost is 0.162 ms — it is nearly free, and it converts a proposal into a contribution.
- If DP stays unimplemented, add one sentence to §IX saying its F1 cost was not measured.

## P2-6. Abstract and §IX contradict each other

`:28` sells robust zero-day detection at F1 0.94. `:247` admits the model is bypassable by Entropy
Dilution — padding an XSS payload with repeated characters to depress Shannon entropy.

Given P0-5 (entropy coefficient 3.42 dominates the decision), this bypass is not a footnote; it is
the model's central weakness.

**Fix:** state the limitation in the abstract. Quantify the bypass — what padding ratio defeats
detection, and what is the resulting recall? `find_evasion.py` appears to be the relevant harness.

---

# P3 — Wording, typos, housekeeping

| Line | Issue | Fix |
|---|---|---|
| `:28` | *"nodes share only encrypted..."* — sentence begins lowercase, word missing | *"Edge nodes share only..."* |
| `:28` | *"a dataset of over 43,000 real-world cybersecurity payloads"* — these are 43,007 **benign wordlist paths**; the attack corpus is 268 SQLi + 17 XSS = **285 unique strings** | State both numbers honestly |
| `:38` | `polymophic` | `polymorphic` |
| `:12` | `\usepackage{lipsum}` unused, plus the comment *"though we will write mostly real text"* | Delete the line |
| `:144` | *"quantify the updates"* | *"quantize the updates"* |
| `:144` | 32→8 bit is 75% ✓, but ternary `(-1,0,1)` needs ~1.58 bits — a different figure | Split the two claims, or cite QSGD |
| `:144` | *"without noticeably degrading the F1-Score"* — asserted, not measured | Cite, or mark as expected |
| `:136` | *"mathematically proven to be vulnerable"* | *"vulnerable to Shor's algorithm on a CRQC"* |
| `:152` | *"almost instantaneously"* | Give the number: 20 rounds × sync period |
| `:210` | *"We processed 10,000 continuous HTTP requests"* — `edge_profiler.py:44` repeats **4 unique strings** 2,500× | Say so, or profile on real dataset samples |
| `:221` | Peak RAM 9.14 MB is `ru_maxrss` of the whole CPython process, i.e. interpreter baseline. The model itself is 4 floats | Report both: process RSS and model size |
| `:256` | Verify `github.com/alessandro-demartini/FedZTA-Edge` exists and is public | Repo must contain the fixed scripts |
| `:259` | Verify the KK-stiftelsen Synergy grant is real and covers this work | Remove if not |
| `:259` | *"thank the anonymous reviewers for their constructive feedback"* on a pre-submission draft | Remove until after review |

---

# Suggested order of work

1. **P2-1** — double `pdflatex`. Two commands, removes every `??` from the PDF. Do it first.
2. **P3** + **P2-2** + **P2-4** — typos, placeholder bibitem, roadmap. Mechanical, no reruns.
3. **P2-3** — attach citations throughout.
4. **P0-6** — unify to one 3-feature model, emit `fed_model.json`, load it everywhere. Unblocks 5 and 6.
5. **P0-2** + **P0-3** — fix the split, widen the XSS corpus, rerun on `.144`. **Numbers will change.**
6. **P0-7** — add per-class recall; rewrite the abstract and §VIII-A around the honest result.
7. **P0-5** — rerun `edge_profiler.py` with the real coefficients, regenerate Table II.
8. **P1-2** + **P1-3** — rerun KEM and stress benchmarks n≥10, report mean ± stdev.
9. **P0-1** + **P0-4** — real poisoning experiment at K≥5, regenerate Figure 2.
10. **P1-1**, **P1-4**, **P1-5**, **P1-6**, **P2-5**, **P2-6** — reconcile remaining text against the new data.
11. Final double `pdflatex`; confirm the log is clean.

# Command reference

```sh
PAPER=/Users/eldemaster/Documents/MIUN/FederatedZeroTrust
CLOUD=192.168.1.144; E1=192.168.1.147; E2=192.168.1.115

# build (always twice)
cd $PAPER && pdflatex -interaction=nonstopmode federated_paper_v4_final.tex && \
              pdflatex -interaction=nonstopmode federated_paper_v4_final.tex && \
              grep -E "undefined|Rerun" federated_paper_v4_final.log

# push a script to the cloud node and run it there (local sklearn is broken)
scp $PAPER/fl_simulation_v2.py $CLOUD:~/ && ssh $CLOUD '~/venv/bin/python fl_simulation_v2.py'

# hardware profiling (edge_profiler.py is NOT present on E2 — copy it if you want both)
ssh $E1 'python3 edge_profiler.py'
scp $PAPER/edge_profiler.py $E2:~/ && ssh $E2 'python3 edge_profiler.py'

# ML-KEM benchmark — note the API is keygen/encaps/decaps, NOT generate_keypair
ssh $E1 '~/venv/bin/python -c "
import pqcrypto.kem.ml_kem_512 as k, time, statistics
pk,sk=k.keygen()
for _ in range(50): k.encaps(pk)
ts=[]
for _ in range(1000):
    s=time.perf_counter(); k.encaps(pk); ts.append((time.perf_counter()-s)*1000)
print(\"encaps mean %.3f stdev %.3f\"%(statistics.mean(ts),statistics.stdev(ts)))"'

# throughput (run 10x, aggregate)
for i in $(seq 10); do python3 $PAPER/stress_test.py | grep "Requests per second"; done

# live services — restart after editing continuous_waf.py / robust_cloud.py
ssh $CLOUD 'pgrep -af "robust_cloud|cloud_pqc"'
ssh $E1 'pgrep -af continuous_waf'
ssh $E2 'pgrep -af continuous_waf'
```

# Measurements taken during this audit (2026-09-14)

Reproduced against the live cluster, for comparison with the paper's claims:

| Quantity | Paper | Measured now | Note |
|---|---|---|---|
| Inference latency, Cortex-A72 | 0.035 ms | **0.035 ms** | reproduces (4 unique payloads × 2,500) |
| Peak RAM | 9.14 MB | **9.14 MB** | reproduces; is process RSS, not model size |
| Total inference time | 0.349 s | 0.347 s | within noise |
| Requests blocked by profiled model | not reported | **10,000 / 10,000** | 100% FPR — see P0-5 |
| ML-KEM-512 encaps | 0.26 / 0.28 ms | **0.162 ms ± 0.002** (n=1000) | paper timed a cold start |
| ML-KEM-512 decaps | not reported | 0.205 ms ± 0.003 | |
| ML-KEM-512 keygen | not reported | 0.122 ms ± 0.002 | |
| ML-KEM public key size | 800 B | 800 B | correct |
| WAF throughput (idle path) | 218 RPS | **246.06 RPS** | single run; high variance |
| WAF p50 latency | 18.56 ms | **29.11 ms** | single run |
| Unique XSS payloads | not reported | **17** | see P0-3 |
| Unique SQLi payloads | 268 | 268 | correct |

---

# ROUND 2 — work completed 2026-09-14, and one new P0

Everything below was executed against the live cluster. New artefacts in the paper directory:
`fl_simulation_v3.py`, `feature_probe.py`, `fed_model.json`, and a rewritten `edge_profiler.py`.

## P0-8 (NEW, most serious) — the benign and malicious templates differ, so the label leaks

`fl_simulation_v2.py:36,43` builds the two classes from different URL templates:

```python
payloads.append((f"GET /{path}?v={np.random.randint(1,100)}", 0))   # every benign request
payloads.append((f"{method} /search?q={p}", 1))                     # every attack
```

Benign traffic is always `GET /<word>?v=<int>`. Attacks are always `<METHOD> /search?q=<payload>`.
The request *shape* is a perfect predictor of the label, independent of payload content.

Measured consequence — `feature_probe.py` on the cloud node, before the fix:

```
BASELINE: 3 syntactic features
  node            AUC seen class  AUC unseen class     gap
  A(XSS-only)             1.0000            1.0000  0.0000
  B(SQLi-only)            1.0000            1.0000  0.0000
```

Perfect AUC on payload classes the node never trained on, with a zero generalisation gap. The model
is separating `/search?q=` from `?v=`, not malicious from benign. Every F1 number in the paper —
including the headline 0.94 — is measuring template discrimination.

**Fixed** in `fl_simulation_v3.py`: benign and malicious traffic now share one template,
`GET /search?q=<value>`, so only the value of `q` varies. With that corrected, a real cross-class gap
appears for the first time:

```
BASELINE: 3 syntactic features (matched templates)
  node            AUC seen class  AUC unseen class     gap
  A(XSS-only)             1.0000            0.9666  0.0334
  B(SQLi-only)            0.9707            0.9999 -0.0293
```

~3 points of AUC. Real, but far smaller than the paper's narrative assumes.

## Completed fixes

| Item | Status | Evidence |
|---|---|---|
| P0-2 train/test contamination | **fixed** | `split_pool()` splits unique payloads before resampling; asserts zero overlap |
| P0-3 XSS corpus of 17 | **fixed** | 8 SecLists sources → **531 unique** XSS payloads (371 train / 160 test) |
| P0-5 profiler 100% FPR | **fixed** | reloaded from `fed_model.json`; now blocks 5,000/10,000 — exactly the 2 malicious of 4 payloads |
| P0-6 three inconsistent models | **fixed** | `fl_simulation_v3.py` emits `fed_model.json`; `edge_profiler.py` consumes it |
| P0-7 no per-class metrics | **fixed** | per-class recall, ROC-AUC, PR-AUC, FPR, and threshold-matched recall all reported |
| One-shot averaging, not FedAvg | **fixed** | R=20 rounds × E=50 local epochs, broadcast-and-restart each round |
| P1-2 KEM latency | **measured** | 0.162 ms ± 0.002, n=1000 |
| P1-3 throughput variance | **measured** | n=10 runs, below |

Still open: **P0-1** (fabricated Fig. 2), **P0-4** (K=2 median), **P1-1**, **P1-4**, **P1-5**,
**P1-6**, all of **P2**, all of **P3**.

## Corrected results — use these numbers

`ssh 192.168.1.144 '~/venv/bin/python fl_simulation_v3.py'`

Corpus after deduplication and disjoint split:

| Class | Unique total | Train | Test |
|---|---|---|---|
| SQLi | 260 | 182 | 78 |
| XSS | 531 | 371 | 160 |
| Normal | 43,007 | 30,104 | 12,903 |

Default threshold:

| Model | F1 | Precision | Recall | XSS recall | SQLi recall | FPR |
|---|---|---|---|---|---|---|
| Edge A (XSS only) | 0.888 | 1.000 | 0.799 | 0.948 | 0.650 | 0.000 |
| Edge B (SQLi only) | 0.951 | 0.998 | 0.909 | 0.996 | 0.822 | 0.002 |
| Federated (FedAvg) | 0.926 | 1.000 | 0.862 | 0.966 | 0.758 | 0.000 |

Threshold-matched — the only fair comparison, since the three models sit at different operating points:

| Model | ROC-AUC | PR-AUC | XSS@0.1% FPR | SQLi@0.1% FPR |
|---|---|---|---|---|
| Edge A (XSS only) | 0.9786 | 0.9846 | 1.000 | 0.798 |
| Edge B (SQLi only) | 0.9856 | 0.9900 | 0.996 | 0.822 |
| **Federated (FedAvg)** | 0.9854 | 0.9899 | **1.000** | **0.822** |

Convergence: F1 plateaus at **round 5**, not 20. §VI `:152` should say 5.

## What this means for the paper's central claim

**The claim as written does not survive.** Federated does not "significantly outperform isolated
silos" — at matched FPR it is statistically indistinguishable from Edge B (ROC-AUC 0.9854 vs 0.9856).

There is one defensible claim left, and it is genuinely true in the data:

> The federated model is the **only** configuration that reaches the best observed recall on *both*
> attack classes simultaneously (XSS 1.000, SQLi 0.822 at 0.1% FPR). Each isolated silo gives up
> ground on one class — Edge A loses 2.4 points of SQLi recall, Edge B loses 0.4 points of XSS —
> and neither knows in advance which class it will be short on.

That is a modest, honest contribution. It will not carry the paper alone. The strong results are now
the systems results: 0.034 ms inference, 9.12 MB RSS, 0.162 ms ML-KEM on ARM, and the bandwidth
reduction — all of which reproduce and all of which survive scrutiny.

Why the effect is small: with three purely syntactic features, SQLi and XSS occupy nearly the same
region of feature space — both are long, special-character-dense, high-entropy strings. A model
trained on either already covers most of the other. Adding 23 lexical keyword features
(`feature_probe.py`) does not widen the gap either (0.0294 vs 0.0334 AUC). The non-IID problem the
paper is built around is largely absent at this feature resolution.

## Benchmarks, n=10 (replaces the single-run figures at `:225`)

`for i in $(seq 10); do python3 stress_test.py; done`

| Metric | Mean | Stdev | Min | Max | Paper claims |
|---|---|---|---|---|---|
| Throughput | **231.78 RPS** | 29.25 | 161.43 | 264.49 | 218 RPS |
| p50 latency | **30.09 ms** | 1.66 | 27.76 | 32.60 | 18.56 ms |
| p95 latency | **121.32 ms** | 9.57 | 110.81 | 139.29 | not reported |

218 RPS falls inside the measured range; **18.56 ms p50 does not** — the true median is ~30 ms.

Profiler after the P0-5 fix (`ssh 192.168.1.147 'python3 edge_profiler.py'`):

```
Total Requests Analyzed: 10000
Requests Blocked: 5000 (50.0%)      <-- correct: 2 of the 4 distinct payloads are malicious
Total Inference Time: 0.339 seconds
Average Latency per Request: 0.034 ms
Peak RAM Usage: 9.12 MB
```

Table II survives essentially unchanged (0.035→0.034 ms, 9.14→9.12 MB) but now describes a model
that actually classifies.

## Decision required before the text can be rewritten

The narrative fork, in preference order:

1. **Reframe around privacy and systems cost.** Contribution becomes: federation matches the best
   silo at 0.1% FPR while never moving raw data, at 0.034 ms and 9.12 MB on ARM with 0.162 ms
   post-quantum key exchange. Add the negative result — syntactic features make attack classes
   nearly indistinguishable, so cross-silo transfer buys little — as an honest finding. Requires no
   new experiments; all numbers above are ready.
2. **Redesign the features so the non-IID problem is real.** Character n-gram hashing or a small
   token vocabulary would separate SQLi from XSS properly, restoring a genuine zero-day gap for
   federation to close. More work, and it inflates the model past the "4 floats" bandwidth claim,
   but it rescues the original story.
3. **Change the split axis.** Partition nodes by *traffic domain* (public web vs SCADA telemetry)
   rather than by attack class. The paper already motivates this at `:147`; it is likely a more
   honest source of non-IID-ness than SQLi-vs-XSS.

Option 1 is the fastest route to a submittable paper. Option 2 is the strongest paper.

---

# ROUND 3 — Option 2 and Option 3 resolved experimentally

Option 2 (richer features) and Option 3 (split nodes by traffic domain) are **orthogonal**, so
rather than guessing, both were run as a 2x2 matrix: `fl_simulation_v4.py`, `sweep_ngram.py`,
`verify_poly.py`, `edge_profiler_ngram.py`, results in `matrix_results.json`.

## Design space

**Features**

- `syntactic` — the paper's 3 features (length, special-char count, Shannon entropy)
- `ngram` — hashed character 3-grams into D buckets, L2-normalised, plus the 3 syntactic features

**Non-IID axis**

- `attack` — nodes differ by threat campaign (A sees only XSS, B only SQLi); identical benign traffic
- `domain` — nodes differ by benign traffic profile (A = public web `raft-small-words`,
  B = API gateway `api-seen-in-wild` + `api-endpoints` + `graphql`); both see the full attack mix

The API corpus gives **8,013 unique** real endpoint paths, so the domain split uses genuinely
different benign distributions rather than synthetic traffic.

## The matrix — recall at a 0.1% false-positive budget

| Cell | dim | Model | ROC-AUC | XSS | SQLi | FPR web | FPR api |
|---|---|---|---|---|---|---|---|
| syntactic/attack | 3 | Edge A | 0.9466 | 0.932 | 0.460 | 0.0013 | 0.0093 |
| | | Edge B | 0.9732 | 0.904 | 0.438 | 0.0027 | 0.0187 |
| | | Federated | 0.9718 | 0.898 | 0.438 | 0.0027 | 0.0067 |
| syntactic/domain | 3 | Edge A | 0.9716 | 0.898 | 0.438 | 0.0027 | 0.0067 |
| | | Edge B | 0.9777 | 0.960 | 0.662 | 0.0013 | 0.0013 |
| | | Federated | 0.9766 | 0.916 | 0.490 | 0.0027 | 0.0027 |
| ngram/attack | 67 | Edge A | 0.9142 | 0.940 | 0.280 | 0.0013 | 0.0093 |
| | | Edge B | 0.9716 | 0.900 | 0.652 | 0.0013 | 0.0320 |
| | | Federated | 0.9671 | 0.934 | 0.490 | 0.0013 | 0.0067 |
| **ngram/domain** | **67** | Edge A | 0.9709 | 0.900 | 0.558 | 0.0013 | 0.0147 |
| | | Edge B | 0.9710 | 0.942 | 0.632 | 0.0067 | 0.0107 |
| | | **Federated** | **0.9762** | **0.954** | **0.650** | **0.0013** | **0.0040** |

Federation gain on the worst attack class, at 0.1% FPR:

| Cell | vs weaker silo | vs stronger silo |
|---|---|---|
| syntactic/attack | +0.000 | −0.022 |
| syntactic/domain | +0.052 | −0.172 |
| ngram/attack | **+0.210** | −0.162 |
| **ngram/domain** | **+0.092** | **+0.018** |

## Finding

**Neither option alone is sufficient. Together they work.**

- **Option 2 alone** (`ngram/attack`) rescues the weak silo dramatically (+0.210) but the federated
  model still loses to the stronger silo (−0.162). This is textbook FedAvg behaviour under sharp
  non-IID labels: averaging two models whose local optima diverge lands between them, not above.
- **Option 3 alone** (`syntactic/domain`) barely moves anything — the 3 syntactic features cannot
  express what distinguishes the two benign profiles.
- **Option 2 + Option 3** (`ngram/domain`) is the **only cell in the matrix where the federated
  model beats both isolated silos**, and it does so on every metric simultaneously: ROC-AUC, XSS
  recall, SQLi recall, and false-positive rate on *both* benign domains.

The mechanism is coherent and defensible: attack knowledge is shared across nodes, so no node is
blind to a threat class, while the benign profiles differ — and averaging over heterogeneous benign
distributions is exactly what makes the global model generalise instead of overfit. That is a real
federated-learning result, not an artefact.

## Dimension sweep — accuracy vs update size (`sweep_ngram.py`)

| D | dim | Update bytes | Edge A AUC | Edge B AUC | Federated AUC | Fed XSS | Fed SQLi | Beats both? |
|---|---|---|---|---|---|---|---|---|
| 32 | 35 | 144 | 0.9738 | 0.9735 | 0.9800 | 0.940 | 0.542 | YES |
| 64 | 67 | 272 | 0.9709 | 0.9710 | 0.9762 | 0.954 | 0.650 | YES |
| 128 | 131 | 528 | 0.9752 | 0.9746 | 0.9794 | 0.988 | 0.734 | YES |
| **256** | **259** | **1,040** | 0.9771 | 0.9766 | **0.9811** | **0.990** | **0.772** | YES |
| 512 | 515 | 2,064 | 0.9740 | 0.9791 | 0.9809 | 0.996 | 0.816 | YES |

Federation wins at every dimension — the result is not a single-point fluke. **D=256 selected.**
This table is itself a paper figure, and it directly serves §V-D, which currently discusses the
bandwidth/accuracy tradeoff with no data behind it.

## Hash choice — `verify_poly.py`, `edge_profiler_ngram.py`

md5 per n-gram is the obvious latency risk on ARM, so a polynomial rolling hash was tested as a
drop-in. Accuracy is equivalent — federated ROC-AUC differs by **0.0012**, and federation beats both
silos under either hash:

| Hash | Edge A | Edge B | Federated | Fed XSS@0.1% | Fed SQLi@0.1% |
|---|---|---|---|---|---|
| md5 | 0.9771 | 0.9766 | 0.9811 | 0.990 | 0.772 |
| polynomial | 0.9725 | 0.9766 | 0.9798 | 0.996 | 0.742 |

Edge cost on the Cortex-A72, 10,000 requests, D=256:

| Feature path | Total | Per request | vs syntactic |
|---|---|---|---|
| md5 n-grams | 4.041 s | 0.4041 ms | 9.6x |
| **polynomial n-grams** | **2.418 s** | **0.2418 ms** | **5.8x** |
| syntactic only | 0.420 s | 0.0420 ms | 1.0x |

**Polynomial hash ships.** Equivalent accuracy, 1.7x faster than md5, and the cloud aggregator must
use the identical bucketing.

## Consequences for the paper's claims

| Claim | Old | New | Verdict |
|---|---|---|---|
| Inference latency | 0.035 ms | **0.242 ms** | still sub-millisecond — headline survives |
| Peak RSS | 9.14 MB | **15.17 MB** | `:48` and `:250` say "less than 10 MB" — must become ~15 MB |
| Update size | 4 floats / 0.01 KB | **260 floats / 1,040 B** | still ~99.8% vs 500 KB raw — claim survives, restate it |
| Feature vector | `X ∈ R^3` | `X ∈ R^259` | §IV-A needs a full rewrite |
| Federation beats silos | unsupported | **supported** under ngram/domain | the contribution is now real |
| Inference is the bottleneck | implied | no — 0.242 ms is ~4,100 RPS ceiling vs 232 RPS from `http.server` | state it |

The 15.17 MB figure was measured with all three feature paths loaded for comparison. A lean
deployment build carrying only the polynomial path should be re-profiled before the number is
quoted — expect it lower.

## Recommended framing

> Nodes differ in the benign traffic they serve (public web vs API gateway) while facing a shared
> threat landscape. Federated averaging over hashed character n-grams produces a global model that
> outperforms every isolated silo on both attack classes *and* on false-positive rate across both
> benign domains — at 0.242 ms per request and 1,040 bytes per update on a Raspberry Pi 4.

## Still open

**P0-1** (fabricated Fig. 2) and **P0-4** (K=2 median) are unchanged and still blocking.
All of **P2** (build, citations, roadmap) and **P3** (typos) are untouched and independent of the
narrative — they can be done at any time.

---

# ROUND 4 — implementation complete, paper rewritten

## P0-1 CLOSED — the poisoning figure is now measured

`poisoning_experiment.py` replaces `poisoning_sim.py`. K=7 real SGD classifiers on domain-split
SecLists shards with the deployed n-gram transform; f=2 turn Byzantine at round 4, uploading
`-12 * w_k`. Each round the same uploads are aggregated three ways and every resulting global model
is scored on a held-out set disjoint from all seven nodes.

| Round | Mean | Median | Trimmed |
|---|---|---|---|
| 3 | 0.9841 | 0.9584 | 0.9786 |
| **4** (attack begins) | **0.0137** | 0.9782 | 0.9831 |
| 12 (final) | **0.2628** | **0.9838** | **0.9864** |

Mean aggregation inverts the model (ROC-AUC 0.0137 is *below* random — attacks rank as more benign
than benign traffic) and never recovers. Median advantage: **+0.721 ROC-AUC**. `poisoning_defense.pdf`
regenerated from these measurements.

## P0-4 CLOSED — median is now taken across peers, with an honest tolerance report

`robust_cloud.py` rewritten: updates keyed by `client_id`, only the latest upload per peer retained,
so the median is over peers rather than over a time window. The aggregator computes
`f = floor((K-1)/2)` and returns it with every global model. Live response from the deployed cluster:

```json
{"n_clients": 2, "clients": ["edge-web", "edge-api"], "aggregation": "median",
 "byzantine_tolerance": 0, "robust": false}
```

With two gateways it reports `robust: false` rather than implying protection it cannot deliver.
`K >= 2f+1` is stated as an equation in the paper and carried into the Limitations section.

## Deployed and verified live

`fedzta_features.py` is now the single feature transform shared verbatim by cloud and edge.
Services restarted across the cluster and verified end to end:

| Request | Result | p(malicious) |
|---|---|---|
| `api/v1/sensors/temp` | HTTP 200 | 0.270 |
| `images/logo.png` | HTTP 200 | 0.070 |
| `admin' OR '1'='1 UNION SELECT...` | HTTP 403 | 0.9998 |
| `<script>alert(document.cookie)</script>` | HTTP 403 | 0.9545 |

Both gateways sync every 15 s; `[sync] global model applied from 2 peers` confirmed in `waf.log`.

## Throughput regression found and fixed

The first deployment measured **42--56 RPS with 27--36 failed requests per 1,000**. Cause was not the
86x larger model: serving HTTP/1.1 keep-alive from a single-threaded `BaseHTTPRequestHandler`
serialises concurrent connections, so each client holds the only handler thread until it disconnects.
Switching to `ThreadingHTTPServer` gave:

| Metric | Before | After |
|---|---|---|
| Throughput | 42--56 RPS | **452.48 ± 24.32 RPS** |
| Failed requests | 27--36 / 1,000 | **0 / 10,000** |
| p50 | 16 ms | 20.50 ± 0.66 ms |

Nearly 2x the *original* 232 RPS, with a 259-dimensional model instead of 3. Worth noting in the
paper precisely because it looks like an ML cost and is not.

## Final measured values

| Quantity | Value | Source |
|---|---|---|
| Federated ROC-AUC | 0.9850 | `fed_model.json` |
| Edge A (web) / Edge B (API) | 0.9766 / 0.9817 | `fed_model.json` |
| XSS / SQLi recall @0.1% FPR | 1.000 / 0.792 | `fed_model.json` |
| Convergence | within 0.001 of best by **round 3** | `fed_model.json` |
| Inference latency | 0.2288 ms | `edge_profiler.py` on .147 |
| Single-core ceiling | 4,370 req/s | idem |
| Peak RSS (lean build) | **10.36 MB** | idem |
| Model size | 1,040 B | idem |
| Throughput | 452.48 ± 24.32 RPS, 0 failures | `stress_test.py` x10 |
| ML-KEM-512 encaps | 0.162 ± 0.002 ms | n=1000 on .147 |
| Bandwidth, training run | 75.0% reduction | `bandwidth_analysis.py` |
| Bandwidth, steady state @452 rps | **99.94%** | idem |
| Break-even | 0.25 req/s per node | idem |

The earlier 15.17 MB figure was the comparison harness holding three feature paths at once. The lean
deployment build measures **10.36 MB**.

## Paper rewritten — `federated_paper_v5.tex`

7 pages, builds clean: **0 undefined references, 0 undefined citations, 0 overfull boxes**.

All 19 headline numbers verified programmatically against the JSON artifacts. Stale-value scan
confirms none of `0.94`, `43,000`, `99.99%`, `9.14 MB`, `0.035 ms`, `218 RPS`, `0.26/0.28 ms`,
`62 RPS` or `18.56 ms` survive anywhere in the text.

Structural changes:

- Abstract and Introduction rebuilt around the actual finding — the non-IID *axis* decides whether
  federation helps — and the negative result is stated in the abstract rather than buried.
- §IV-A rewritten for the n-gram feature map, including why the 3-feature version fails.
- §IV-D added: Byzantine-robust aggregation with the `K >= 2f+1` bound as a numbered equation.
- §V marks differential privacy explicitly as *specified but not implemented*; no fabricated epsilon.
- §VI documents both dataset-construction failures (payload overlap, template leakage) as methodology
  rather than hiding them.
- §VII-A is new: the 2x2 design-space table carrying the central finding.
- §VIII Limitations is substantially expanded and concrete — SQLi recall of 0.792 bounds deployment,
  78 test payloads make it the least secure number, no adaptive-adversary evaluation, DP unimplemented,
  ML-KEM not yet in the live channel, two-node deployment gives f=0.
- **25 references, every one cited in text.** Added NIST SP 800-207, FIPS 203, Zhu (gradient leakage),
  Abadi (DP), Yin (median/trimmed mean), Li (FedAvg non-IID convergence), Weinberger (feature hashing),
  Alistarh (QSGD), Snort, Suricata.
- All P3 typos fixed; `lipsum` removed; roadmap matches the actual structure.

## The one thing that still needs you

`federated_paper_v5.tex` bibliography, entry `friend_pqtls`:

```latex
\bibitem{friend_pqtls} TODO---AUTHOR, ``Evaluating Post-Quantum TLS Performance for the
Internet of Things Using Raspberry Pi Devices,'' TODO---VENUE, TODO---YEAR.
```

Author, venue and year cannot be invented. It is cited once, in §V-B.

Also verify before submission: the KK-stiftelsen acknowledgment, and that
`github.com/alessandro-demartini/FedZTA-Edge` exists and is public with the new scripts.
