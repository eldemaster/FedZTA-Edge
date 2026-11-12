# Novelty and Positioning Review — FedZTA-Edge

Reviewer stance: tough peer reviewer. Reviewed material: `paper/` as assembled in PR #7 (`office/dot-0c11`, supersedes #1–#6), plus the code on `master` (`robust_cloud.py`, `fedzta_auth.py`, `fedzta_features.py`, `continuous_waf.py`, `cloud_pqc.py`, `edge_pqc.py`, `train_production_model.py`, `poisoning_experiment.py`). `paper/` itself is not edited.

**Citation policy.** Entries marked **[V]** I am confident exist (from memory of the literature, author/venue/year as stated). Entries marked **[W]** were found by web search in this session; I saw abstracts/metadata only, not full text. Entries marked **[?]** I believe exist but could not confirm; do not cite without checking. I did no exhaustive literature search; the "nothing found" statements below mean "not found in a limited search", not "does not exist".

---

## 1. TL;DR

- No single component is new. FedAvg + hashed-n-gram linear classifier, median/trimmed-mean, HMAC-signed updates with nonces, and ML-KEM on a Raspberry Pi are all textbook or already benchmarked.
- The *combination* (federated + edge WAF + authenticated Byzantine-robust aggregator + PQC KEM, in ~10 MB pure Python) is a reasonable systems/engineering contribution, and I found no single prior paper doing exactly it. But "nobody combined these" is a weak novelty claim, and the closest competitors (2024–2026 federated-XSS and PQ+Byzantine FL work) are close enough that reviewers will ask for comparison.
- The paper's strongest asset is its **honesty**: the negative finding that federation does not beat the best silo, the dataset pitfalls, the stale-artifact disclosures. That is valuable but it is a "careful measurement" contribution, and the measurements are too small to carry a paper alone.
- The title/keywords promise "quantum-resistant" and "zero-trust" but the live channel is plain-HTTP JSON with HMAC only; ML-KEM is a standalone benchmark. The "continuous/behavioral authentication" framing in the repo name does not match the paper: the system classifies *request payloads*, it does not authenticate *users or devices* behaviourally.
- **Recommendation: improve (substantially) before submitting anywhere above workshop/regional level.** Details in §8.

---

## 2. Closest prior work

### 2.1 Federated learning for intrusion / anomaly detection

| Work | Note |
|---|---|
| Nguyen et al., **DIoT**, ICDCS 2019 **[V]** | Federated per-device-type GRU anomaly detection on IoT gateways. Closest "FL on gateways" ancestor. Network-flow, not HTTP payloads. |
| Mothukuri et al., FL anomaly detection for IoT attacks, IEEE IoT-J 2021 **[V]** | GRU ensemble, FL, Modbus dataset. |
| Preuveneers et al., chained anomaly detection models for FL, Applied Sciences 2018 **[V]** | Early FL-IDS with blockchain-ish model chaining. |
| Rey et al., FL for malware detection in IoT, Computer Networks 2022 **[V]** | Also studies poisoning against FL detectors. |
| Taheri et al., **Fed-IIoT**, IEEE TII 2020 **[V]** | Federated malware detection in *industrial* IoT with GAN-based poisoning defence. Overlaps the "FL + IIoT + poisoning" claim directly. |
| Campos et al., Evaluating FL for IoT intrusion detection (2021/22) **[V, venue unsure]** | Studies non-IID partitions for FL-IDS: pre-empts part of the "which kind of heterogeneity matters" claim. |
| Nguyen et al., FL for IoT survey, IEEE COMST 2021 **[V]** | Survey; paper already cites. |
| Jazi & Ben-Gal, *Federated Learning for XSS Detection: A Privacy-Preserving Approach*, SCITEPRESS 2024 **[W]** | Federated XSS detection on edge devices, non-IID as a central issue. **Closest on the web-attack axis.** Not in paper. |
| Bharath & Latha, FedXSS-Guard, J. Intell. Fuzzy Syst. (2026?) **[W]** | Federated hybrid deep XSS detector, server/edge/mobile, claims <5 ms. Self-reported numbers. |
| Wang et al., federated XSS under non-IID/OOD, Sussex preprint 2025 **[W]** | Claims "first systematic" FL for XSS. Overlaps the non-IID evaluation. Preprint. |
| Poisoning/Byzantine FL-IDS papers on N-BaIoT / ToN-IoT / Edge-IIoTset **[?]** | Many exist; I did not enumerate them. |

Gap I could not close: no hit for federated **SQLi** or federated **WAF** specifically. That is the one thin sliver of white space on this axis, and it is thin because FL-XSS exists and SQLi vs. XSS is a label change.

### 2.2 Continuous / behavioural authentication

| Work | Note |
|---|---|
| Patel et al., continuous user authentication on mobile devices, IEEE Signal Processing Mag. 2016 **[V]** | Canonical CA survey. |
| Wazzeh et al., warmup / transfer-learning FL for IoT continuous authentication (IEEE Network 2023; arXiv 2211.05662) **[W]** | FL + continuous auth + IoT. Uses image datasets + UMDAA-02-FD. |
| Mobile-crowdsourcing FL continuous auth, IEEE Access 2024 **[W]** | |
| FL smartphone sensor identification, SBRC (Brazil) **[W]** | |

**Observation.** This literature authenticates *users/devices* from behavioural signals (touch, gait, keystroke). FedZTA-Edge does not do that. It does binary SQLi/XSS-vs-benign classification of request strings. Calling this "continuous authentication" or "behavioural" is a category mismatch (the "behavioural" n-gram profiling in the Background is PAYL-style payload anomaly detection). Either drop the term or add real per-client behavioural authentication. As written, a CA reviewer will read the paper as having no CA contribution.

### 2.3 Zero-trust architecture at the edge

| Work | Note |
|---|---|
| NIST SP 800-207 (Rose et al., 2020) **[V]** | Standard reference. |
| Ward & Beyer, BeyondCorp, ;login: 2014 **[V]** | |
| Syed et al., Zero Trust Architecture (ZTA): a comprehensive survey, IEEE Access 2022 **[V]** | Good survey to cite. |
| He et al., survey on ZTA: challenges and future trends, Wireless Commun. Mob. Comput. 2022 **[V, details unsure]** | |
| ZTA + FL / PQC integration papers **[W/?]** | One search listing described PQC + zero trust for securing AI models; I did not confirm the source. Treat as unverified. |

ZTA is used here as motivation only. Nothing in the system implements NIST 800-207 components beyond "a gateway scores requests": no policy engine, no device posture, no per-session trust score, no identity-aware access decision. The "zero-trust" label attaches to (a) the authenticated aggregator and (b) payload inspection. Reviewers from the ZT community will call this a stretch. The paper's own framing (Intro: "authentication of the learning loop") is the defensible reading: *the FL control plane is authenticated per-update*. Keep that, drop the broader ZTA claims.

### 2.4 PQC in IoT / edge / TLS

| Work | Note |
|---|---|
| Bos et al., PQ key exchange for TLS from RLWE, IEEE S&P 2015 **[V]** | |
| Bos et al., Frodo, CCS 2016 **[V]** | |
| Sikeridis, Kampanakis, Devetsikiotis, PQ authentication in TLS 1.3: a performance study, NDSS 2020 **[V]** | |
| Bürstinghaus-Steinbach et al., PQ TLS on embedded systems, AsiaCCS 2020 **[V]** | Directly on embedded PQ-TLS cost. |
| Kannwischer et al., pqm4, 2019 **[V]** | Cortex-M4 benchmarking. |
| Botros, Kannwischer, Schwabe, Kyber on Cortex-M4, AFRICACRYPT 2019 **[V]** | |
| Stebila & Mosca, PQ key exchange for the Internet and Open Quantum Safe, SAC 2016 **[V]** | liboqs. |
| Hybrid X25519+Kyber/ML-KEM in browsers/CDNs (Chrome, Cloudflare, 2023–24); IETF TLS hybrid design drafts **[V]**, industry blogs/drafts, not papers | Production deployment already exists; the paper's "PQ channel at the edge is feasible" is not news. |
| Rahmati & Rahmati, Byzantine-robust FL with PQ secure aggregation, arXiv 2601.01053 (Jan 2026) **[W]** | Preprint: Kyber KEM + homomorphic encryption + reputation-based Byzantine exclusion, industrial-IoT IDS datasets, self-reported 96.8% / 40% Byzantine. **Closest competitor on the FL + PQC + Byzantine + IIoT-IDS combination.** Not cited. |
| Post-quantum FL for threat intelligence with Kyber+Dilithium on Raspberry Pi clusters, arXiv 2603.07726 **[W]** | Hardware-based PQ-FL; overlaps the "ML-KEM on RPi" claim. Not cited. |

ML-KEM-512 on a Pi 4 at ~0.16 ms encapsulation is consistent with prior Kyber benchmarks; it is a sanity data point, not a result. Also note: NIST security level 1 (512) is the weakest set; CNSA 2.0 requires ML-KEM-1024, and most deployments default to 768. A reviewer will ask why 512.

### 2.5 Robust aggregation and poisoning defences

| Work | Note |
|---|---|
| Blanchard et al., Krum, NeurIPS 2017 **[V]** | |
| Yin et al., coordinate-wise median / trimmed mean, ICML 2018 **[V]** | The paper's actual defence. |
| El Mhamdi et al., Bulyan, ICML 2018 **[V]** | |
| Pillutla et al., robust aggregation (RFA, geometric median), IEEE TSP 2022 **[V]** | |
| Karimireddy et al., learning from history for Byzantine-robust optimisation, ICML 2021 **[V]** | Shows momentum/history needed against time-coupled attacks. |
| Cao et al., **FLTrust**, NDSS 2021 **[V]** | Server-side root dataset trust bootstrapping; arguably the natural defence for this system, since the aggregator could hold a small clean/anchor set. |
| Nguyen et al., FLAME, USENIX Security 2022 **[V]** | |
| Fung et al., FoolsGold: mitigating Sybils in FL poisoning, 2018 (arXiv) **[V]** | Sybil-specific. |
| Fang et al., local model poisoning, USENIX Security 2020 **[V]** | Cited. |
| Baruch et al., "A little is enough", NeurIPS 2019 **[V]** | Defeats median/Krum with small perturbations. |
| Xie et al., Fall of Empires, UAI 2019 **[V]** | Inner-product manipulation. |
| Bhagoji et al., analyzing FL through an adversarial lens, ICML 2019 **[V]** | |
| Bagdasaryan et al., how to backdoor FL, AISTATS 2020 **[V]** | |
| Shejwalkar & Houmansadr, manipulating the Byzantine, NDSS 2021 **[V]** | Generic optimisation attacks vs. robust aggregators. |
| Shejwalkar et al., back to the drawing board: critical evaluation of poisoning attacks on production FL, IEEE S&P 2022 **[V]** | Argues threat models in the FL-poison literature are often unrealistic, which cuts both ways for this paper (see §6). |

The paper's poisoning experiment (K=7, f=2, sign-flip ×12, one seed) is the weakest attack on this list. Sign-flip with large boost is rejected by *any* norm clipping or median; the 0.984 vs 0.263 contrast is a demonstration, not evidence.

### 2.6 n-gram / HTTP payload anomaly detection and ML-based WAFs

| Work | Note |
|---|---|
| Forrest et al., sense of self for Unix processes, IEEE S&P 1996 **[V]** | |
| Wang & Stolfo, **PAYL**, RAID 2004 **[V]** | Byte-frequency payload model. The feature design here is closest to this. |
| Wang et al., **Anagram**, RAID 2006 **[V]** | Higher-order n-gram + Bloom filter; hashing of n-grams is already there. Not cited. |
| Perdisci et al., **McPAD**, 2009 **[V]** | Multiple one-class classifiers over 2-gram features. Not cited. |
| Kruegel & Vigna, CCS 2003; Kruegel, Vigna, Robertson, Computer Networks 2005 **[V]** | Anomaly detection of web attacks. |
| Weinberger et al., feature hashing, ICML 2009 **[V]** | Cited. |
| Fogla & Lee, evading network anomaly detection systems, CCS 2006; Fogla et al., polymorphic blending attacks, USENIX Sec 2006 **[V]** | Break PAYL-style statistical payload models. **Directly relevant evasion literature for this feature design; not cited.** |
| Sommer & Paxson, outside the closed world, IEEE S&P 2010 **[V]** | Cited; the paper uses it well. |
| CSIC 2010 HTTP dataset (Torrano-Giménez, Pérez-Villegas, Álvarez) **[V, details unsure]** | Standard HTTP-attack benchmark. Not used. |
| Betarte et al., web application attack detection using ML, ICMLA 2018 **[?]** | |
| DeepXSS, Fang et al., 2018 **[?]** | Deep XSS detection. |
| ModSecurity / OWASP CRS; Cloudflare ML-WAF score (industry) | Rule-based plus ML-assisted; vendor docs, not papers. |

---

## 3. Comparison table

Legend: ✔ yes / ◐ partial or claimed-only / ✘ no / ? unknown. "Datasets" are those named in the source; table is from abstracts/memory, so treat cells as approximate.

| Work | Federated | Edge/IoT | PQC | Continuous auth | Poisoning defence | Datasets |
|---|---|---|---|---|---|---|
| **FedZTA-Edge (this)** | ✔ (K=2 real, K=7 sim.) | ✔ Pi 4 | ◐ KEM benchmarked, *not in live path* | ✘ (payload classification, not auth) | ◐ median/trimmed mean + norm gate; naive sign-flip only | SecLists fuzzing lists (681 SQLi, 523 XSS, ~51k benign wordlists) |
| DIoT (Nguyen '19) | ✔ | ✔ | ✘ | ✘ | ✘ | Real IoT traffic (own testbed) |
| Mothukuri '21 | ✔ | ◐ | ✘ | ✘ | ✘ | Modbus IoT set |
| Fed-IIoT (Taheri '20) | ✔ | ✔ IIoT | ✘ | ✘ | ✔ (GAN-based) | Android/IIoT malware sets |
| Rey '22 | ✔ | ✔ | ✘ | ✘ | ◐ studies poisoning | N-BaIoT |
| Jazi & Ben-Gal '24 [W] | ✔ | ✔ edge | ✘ | ✘ | ? | XSS corpora |
| FedXSS-Guard [W] | ✔ | ✔ | ✘ | ✘ | ? | XSS corpora |
| Wazzeh et al. '23 [W] | ✔ | ✔ IoT | ✘ | ✔ | ✘ | MNIST/FEMNIST/CIFAR-10/UMDAA-02-FD |
| Rahmati & Rahmati 2026 [W] | ✔ | ✔ IIoT | ✔ (Kyber + HE) | ✘ | ✔ reputation | IIoT IDS sets (unspecified) |
| PQ-FL threat intel 2026 [W] | ✔ | ✔ RPi cluster (sim.) | ✔ Kyber+Dilithium | ✘ | ? | ? |
| FLTrust (Cao '21) | ✔ | ✘ | ✘ | ✘ | ✔ | Image/HAR sets |
| Krum / median / Bulyan | ✔ (aggr.) | ✘ | ✘ | ✘ | ✔ | MNIST/CIFAR |
| PAYL / Anagram / McPAD | ✘ | ✘ | ✘ | ✘ | ✘ | DARPA / own HTTP traces |
| Pure PQ-TLS embedded (Bürstinghaus-Steinbach '20) | ✘ | ✔ | ✔ | ✘ | ✘ | n/a (perf) |

Reading: every column of FedZTA-Edge is covered by someone else; only the *intersection of federated + WAF payloads + authenticated-aggregator + KEM-on-Pi* is unoccupied in my search, and the 2026 PQ-FL preprints cover most of that intersection for IIoT intrusion detection generally.

---

## 4. Assessment

### 4.1 Genuinely new (modest)

1. **A measured, negative-leaning result on federation for payload classifiers**: at matched 0.1% FPR with payload-disjoint splits, federation (a) ≈ best silo (ROC-AUC 0.9947 vs 0.9938, below one std), (b) lifts the weak silo, (c) cuts cross-domain FPR. The "benign-profile axis vs attack axis" framing is a useful, honestly reported observation. Prior FL-IDS work mostly reports federated > local without this discipline. This is the paper's best idea.
2. **Dataset-construction pitfalls documented empirically** (resample-before-split memorisation; class-specific request templates giving AUC≈1 on unseen attack classes; length-shortcut and header-baseline artefacts). Not new in principle (Sommer & Paxson, "Dos and Don'ts of ML in security", Arp et al. USENIX Sec 2022 **[V]**), but a concrete HTTP-payload case study is useful. Cite Arp et al.
3. **The aggregator reports its own achievable Byzantine tolerance** (`f = ⌊(K-1)/2⌋`, `robust` flag). Small, sensible engineering practice; the observation that two gateways give f=0 is correct and rare to see stated.
4. **Keying robust aggregation by authenticated peer identity** and showing a time-window median is wrong. Engineering lesson, not research novelty.

### 4.2 Incremental

- Fixed-size hashed-trigram + 3 scalars logistic regression: PAYL/Anagram/McPAD lineage plus feature hashing. A good engineering choice; no ML novelty.
- Federating it with FedAvg then median: standard.
- HMAC + timestamp + nonce + allowlist + rate limit + norm gate: standard API-auth hygiene. The ten-case attack suite tests designed status codes, not an adversary; and the paper says no pass count is archived.
- Edge cost measurements: a pure-Python linear model is cheap by construction; 452 req/s is an HTTP-stack number. Interesting only as a footprint statement.
- Bandwidth comparison: against a baseline (shipping 27.4-byte payloads) that nobody would use; 99.94% is an artefact of that baseline.

### 4.3 Already done elsewhere

- FL on IoT/IIoT gateways for intrusion detection (DIoT, Fed-IIoT, others).
- FL for XSS detection at the edge with non-IID analysis (Jazi & Ben-Gal 2024; Wang 2025 preprint).
- Byzantine-robust FL + Kyber on IIoT intrusion data (Rahmati & Rahmati 2026 preprint).
- Median / trimmed-mean / Krum robustness; their failure to adaptive attacks.
- ML-KEM/Kyber timing on ARM and in TLS.
- Hashed n-gram payload anomaly detection for HTTP.
- Federation as non-IID-sensitive (Li et al. 2020; Campos et al.).

### 4.4 Genuinely missing relative to the paper's framing

Zero-trust decisioning, continuous/behavioural authentication, post-quantum live channel, differential privacy, adaptive attacks, real traffic. See §5/§8.

---

## 5. Overclaimed or mismatched claims

Ranked by how likely a reviewer is to attack them.

1. **"Quantum-resistant" in the title and keywords / PQC as a contribution.** The live `/update` and `/weights` path is HMAC-authenticated JSON over plain HTTP. ML-KEM-512 is a standalone demo. HMAC-SHA256 is already quantum-safe against forgery, while the *confidentiality* that ML-KEM would give is absent. The title promises the missing property. Also ML-KEM key exchange is demonstrated but the HMAC keys are *symmetric secrets provisioned manually*, so the PQ story is orthogonal to how auth works. (The paper does disclose this in the abstract; the title still overreaches.)
2. **"Zero-Trust" as architecture.** See §2.3. One gateway scoring payloads plus an authenticated aggregator is not a ZTA in the NIST 800-207 sense (no PDP/PEP split, no trust score, no identity/posture of the *requester*).
3. **"Continuous"** (`continuous_waf.py`, README framing, Background's "behavioural profiling"). The detector is a stateless per-request classifier; nothing tracks users, sessions or drift over time except the anchor-set replay. There is no behavioural authentication.
4. **Byzantine robustness.** "Median keeps ROC-AUC at 0.984 where averaging collapses to 0.263" is a one-seed, K=7, f=2, naive ×12 sign-flip. With f=2 of 7 and a ×12 norm, the deployed norm gate (ρ=4) would reject those uploads outright; `poisoning_experiment.py` contains no norm gate (checked by grep), so the experiment tests the bare median/trimmed mean, not the deployed pipeline. That is defensible as an ablation but means the paper never shows the deployed pipeline under attack, and never shows an attack that passes the gate. The physical system has f=0. Honest in the Limitations but the abstract/contribution list still lead with it.
5. **Sybil resistance.** Enrolment is a *manual allowlist with symmetric secrets*; that is not Sybil resistance in the FL sense (FoolsGold etc.), it is closed membership. Fine for an industrial consortium, but then say "closed-membership" and drop "Sybil-resistant aggregation".
6. **"Federation helps / when federation helps."** The data support only: federated ≈ best silo, better than weak silo. Contribution 2 in the introduction frames it as a finding about *which axis helps*, resting on K=2, D=64 unaugmented matrix configs and a 0.0009 AUC margin. The attack-axis result (federated sits between the silos) is the generic FedAvg expectation. With two nodes this is anecdote.
7. **Detection quality.** ROC-AUC 0.995 and ~0.98 XSS / ~0.87 SQLi recall at 0.1% FPR on SecLists wordlists: benign class = directory-brute-force word lists and API-path lists, attacks = fuzzing payload lists. These are *very* different string distributions (short slugs vs. quote/angle-bracket strings), so a 259-dim linear model separating them is unsurprising. This does not demonstrate WAF performance on real traffic. The ten per-wrapper augmentation changes also shifted the model so the deployed threshold (0.15) has *no reported held-out FPR/recall*, i.e. the deployed operating point is unevaluated. The paper says so, but then headline numbers are for a different operating point.
8. **Bandwidth 99.94%.** Baseline artefact; at 15 s sync the claim drops to 98.88%, and the paper itself shows federated training transfers 83 KB vs 333 KB (75%). Also a 27-byte "request" is not a request.
9. **Edge cost.** Measurements come from the *old* draft, pre-augmentation, no result file, and the PQ timings likewise. The paper discloses this; it cannot be submitted that way. Similarly the D-sweep figure is hard-coded from an earlier run.
10. **Contribution 6 ("methodology")** is a list of mistakes the authors made and fixed. Honest, but venues read it as a weakness unless the study is bigger.
11. **Security-test claim.** "Ten-case attack suite exercises the control plane against a live cluster" with no archived output.
12. **"We are not aware of prior work that evaluates how the non-IID axis affects a federated WAF"** (Background). Hedged correctly, but Jazi & Ben-Gal (2024), Wang et al. (2025) and Campos et al. make this statement risky. Re-check before submission.
13. Intro says the Gaia-X data-sovereignty constraint motivates the design; no experiment shows a sovereignty property beyond "payloads aren't sent". No privacy attack (gradient/membership inference) was run and DP is unimplemented. For a linear model with 259 hashed features, update leakage should actually be *measured*; with a few hundred unique attack strings, a linear model may leak them.

---

## 6. Additional critical points (technical)

- **Linear model on hashed trigrams is trivially evadable** (Fogla & Lee 2006 polymorphic blending; padding with benign trigrams; `max` over contexts does not help against payloads in a single field). The L2-normalised histogram means appending benign padding *dilutes* the signal, which the augmentation (JSON/prose padding wrappers) partly trains against but also teaches the model that long benign padding around attack tokens is "benign-ish" in distribution; at τ=0.15 with intercept ≈ −5.6 this is precisely where recall will leak. An adaptive attack evaluation is a must for a security venue.
- **Threshold / calibration:** lowering τ to 0.15 to compensate for intercept shift is a patch. Report PR / ROC at the deployed τ, FPR on real benign traffic.
- **Evaluation hygiene:** unique-string splits fix exact-string leakage but not near-duplicate leakage (SecLists SQLi lists are heavily templated variants). A split by *list/source* (leave-one-corpus-out) would be a much harder and more honest generalisation test and is the natural fit to the "zero-day" story.
- **Two real nodes, domain-split by wordlist type.** "Heterogeneity" is the choice of corpus. With only two clients, FedAvg ≈ weight interpolation; no statement about FL at scale.
- **Median over 2 clients = mean**, so the deployed system is not robust (admitted). The paper's security story is therefore simulation-only.
- **Aggregator trust.** Symmetric HMAC means the aggregator holds all secrets and is a single point of compromise; ZT claims should not rest on that. A signature scheme (Ed25519 now, ML-DSA for PQ) is the obvious upgrade and also would make the PQC angle coherent (the paper itself discusses ML-DSA as an unevaluated alternative).
- **Shejwalkar et al. (S&P 2022)** also warns that FL poisoning threat models assuming a large fraction of compromised clients are unrealistic in cross-silo settings. In cross-silo (a few enrolled gateways) the realistic threat is *one* compromised gateway, where median over K≤4 gives little and the more relevant defences are FLTrust-style server validation, or per-update validation on a held-out anchor set (which the repo already has).
- **Provenance bugs the paper itself reports** (`fed_model.json` stores seed 49 while config says 42; hard-coded plot arrays) are reproducibility red flags a reviewer will weigh against the "every number from a result file" claim.

---

## 7. Venue assessment

| Tier | Fit |
|---|---|
| Top security (CCS, S&P, USENIX Sec, NDSS) | No. No new attack, defence, or analysis; small data; no adaptive adversary. |
| Strong systems / IoT / networking (IoT-J, TIFS, TDSC, INFOCOM, IMC) | Not as is. Would need real traffic, ≥8–20 nodes, adaptive attacks and a live PQ channel. |
| Solid applied venues (IEEE IoT-J lower end, Computer Networks, Future Generation CS, IEEE Access, Computers & Security, IEEE TII applications track) | **Plausible after the "improve" work** in §8; today borderline, with likely major-revision outcome on the stale artefacts and overclaiming. |
| Workshops / second-tier conferences (e.g., IEEE/IFIP edge/IoT-security workshops, ARES, IEEE TrustCom-type, EdgeSys-type, FL-related workshops) | **Most plausible current tier.** The IEEEtran conference format used also points there. |
| Open-access megajournals (Access, Sensors, Electronics, Applied Sciences) | Would likely accept as is after fixing stale artefacts; low signal value. |

Most plausible tier for the paper as it stands: **workshop / third-tier conference**. With §8 priorities 1–6 done: **mid-tier applied journal or good IoT/edge-security conference**. The paper's own honesty is an asset with reviewers at those tiers, and a liability only if the headline results are weak (they are).

---

## 8. Recommendation: **IMPROVE (substantially), do not submit as is**

Not "submit as is": stale numbers, a title the artefact does not support, a deployed operating point with no evaluation, and the 2024–2026 related work missing. Not "start over": the system works, the honesty is good, and the measurement angle (what does federation actually buy?) is a legitimate story if scaled up.

### Prioritised to-do list

**P0 (blocking; needed for any submission)**
1. **Fix title/claims**: remove "Quantum-Resistant" from the title unless P1.1 is done; drop "continuous authentication/behavioural" and reduce "zero-trust" to "authenticated learning loop" unless implemented. Reframe contributions as: (i) measurement study of federation for payload classifiers, (ii) authenticated robust aggregator with explicit f reporting, (iii) edge footprint.
2. **Regenerate every stale artefact** from current code: ARM latency/throughput/ML-KEM timings with archived raw JSON, D-sweep, attack-suite results (archived pass/fail output), single-seed figure from the multi-seed run. Fix `fed_model.json` seed provenance.
3. **Evaluate at the deployed threshold** (τ=0.15): ROC/PR, FPR, recall per class on held-out payloads, plus a calibration check.
4. **Cite and differentiate** from: Jazi & Ben-Gal 2024, Wang 2025 preprint, FedXSS-Guard, Rahmati & Rahmati 2026, PQ-FL threat-intel 2026, Fed-IIoT, DIoT, Anagram, McPAD, Fogla & Lee, FLTrust, Bulyan, Baruch et al., Shejwalkar et al., Arp et al. (all verify before citing; [W] ones are web-found abstracts only).

**P1 (what turns it into a real paper)**
5. **Wire ML-KEM into the live path** (KEM-derived key → AEAD over `/update` and `/weights`), ideally hybrid with X25519 as deployed in practice; measure end-to-end cost on the Pi; consider ML-KEM-768. Optionally replace HMAC with Ed25519/ML-DSA per-gateway keys and measure.
6. **Adaptive adversary evaluation**: (a) model-poisoning tailored to median/trimmed mean (Fang, "little is enough", inner-product manipulation), with norm gate on; (b) input-space evasion of the trigram map (padding, encoding, case/comment tricks, polymorphic blending); (c) backdoor-style poisoning. Report attacker budgets.
7. **Real data**: add at least one standard HTTP-attack dataset (CSIC 2010; ideally also captured/benign logs from the testbed or an OWASP Juice Shop/DVWA traffic replay) and an IoT/IIoT set (Edge-IIoTset **[V, Ferrag et al. 2022]**). Use **leave-one-corpus-out** splits to test the zero-day claim.
8. **Compare to baselines**: ModSecurity + OWASP CRS, a centralised model on pooled data (upper bound), a non-linear model (GBDT/small MLP over the same features) and one published federated XSS model. Without a centralised upper bound the "federation costs nothing" claim is uninterpretable.
9. **Scale the federation**: ≥10–20 simulated clients with Dirichlet/natural non-IID splits and heterogeneous data volumes; seed sweep (≥8 seeds) for the poisoning study with CIs; ablate gate-on/gate-off so the median's contribution is isolated.

**P2 (strengthens, optional for mid-tier)**
10. Measure privacy leakage from updates (gradient / membership inference / payload-recovery from linear weights) and, if claiming privacy, implement DP or secure aggregation with a utility trade-off.
11. FLTrust-style server validation using the anchor set; compare to median.
12. Mixed attack/benign load throughput, and fail-open/closed behaviour under load.
13. If the CA/ZTA framing is to stay: implement per-client/session trust scoring and device-identity binding, and evaluate on a behavioural dataset; otherwise cut it.
14. Threat-model fix for symmetric keys: aggregator compromise analysis, key rotation, enrolment procedure.

**If only one week is available:** do P0 1–4 and P1.5 (live KEM) + P1.6(a) (one adaptive poisoning attack) + a centralised baseline; target a workshop or lower-tier journal and be explicit that this is a prototype study.

---

## 9. Verification notes / caveats

- Web searches (3, standard mode) supported only the **[W]** entries; they were abstracts and listings, so venue/year/numbers may be imperfect and none of the self-reported accuracies were verified.
- All **[V]** entries are from memory; double-check years/venues before they enter `refs.bib`. Items marked **[?]** should be verified or dropped.
- I did not run any code or re-derive any numbers; figures quoted come from the paper text in PR #7 / #6 / #5. I grepped `poisoning_experiment.py` for a norm gate: none present (§5.4).
- "Not found" ≠ "does not exist": the federated-SQLi/WAF gap in particular should be re-searched (IEEE Xplore, ACM DL, Google Scholar, arXiv) immediately before claiming it.
