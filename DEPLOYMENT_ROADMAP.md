# Deployment Roadmap & Security Remediation

This roadmap documents the critical path to transition the **Adaptive Zero-Trust WAF** from an academic prototype to a production-ready, defensively secure system. It addresses core vulnerabilities identified during the adversarial system review, prioritising structural security (Tier 1) and threat visibility (Tier 0) over raw detection accuracy.

---

## Tier 0: WAF Threat Visibility (Next for Claude)
**Problem:** The current micro-inferencer (`continuous_waf.py`) implements `do_GET` only. It concatenates the URL path and query string to extract features, rendering it entirely blind to `POST`/`PUT` request bodies, headers (e.g., `User-Agent`), and cookies. In the real world, the vast majority of SQLi and XSS payloads are delivered precisely via these uninspected vectors.
**Impact:** Critical False Negatives. The gateway is functionally blind to ~80% of the modern attack surface.

**Action Items:**
- [x] Implement `do_POST` and `do_PUT` handlers.
- [x] Inspect and extract features from critical HTTP Headers (e.g., `User-Agent`, `Referer`, `Cookie`).
- [x] Parse and inspect `POST`/`PUT` payloads up to a hardcoded size cap (8 KB) to prevent memory exhaustion on the Edge.
- [x] Score each context (URL, Header, Body) independently rather than concatenating them, preventing statistical dilution.

---

## Tier 1: Zero-Trust Control Plane Authentication (COMPLETED)
**Problem:** The Cloud Aggregator (`robust_cloud.py`) assumes a "Zero-Trust" posture for the Edge nodes, but ironically enforces *zero trust checks* on its own `/update` endpoint. It accepts unauthenticated POST requests from any IP.
**Impact:** Critical Sybil Attack vulnerability. An attacker can spin up multiple fake identities, overwhelming the bounded $f$ Byzantine tolerance of the Median aggregator and completely hijacking the global model coordinates.

**Action Items:**
- [x] **mTLS / Cryptographic Signatures:** Require signed updates using a per-gateway cryptographic key (HMAC-SHA256, timestamps, single-use nonces).
- [x] **Enrolment Allowlist:** Hardcode or dynamically manage a list of legitimate `client_id` fingerprints (`enroll_peer.py`).
- [x] **Rate-Limiting:** Enforce a strict rate limit per identity to prevent flood-based poisoning (nonce consumed before rate-limit check).
- [x] **Outlier Rejection:** Reject extreme dimensional or norm outliers *before* passing the gradients to the Median aggregator (fixed K=2 fallback bug).

---

## Tier 2: Detection Quality & Model Drift (In Progress)
**Problem:** The SQLi recall is stuck at 0.792. Furthermore, the active learning loop trains on its own confident predictions (pseudo-labeling). This creates a dangerous feedback loop lacking a fixed anchor, causing mathematical drift (e.g., confidence dropping from 0.95 to 0.79 on repeated attacks).
**Impact:** Sub-optimal detection and gradual degradation of the decision boundary over time.

**Action Items:**
- [ ] **Data Expansion:** Expand the SQLi dataset. 260 unique payloads is the binding constraint. Integrate CTF corpora, SQLi-Fuzzing, and Payloadbox to multiply the training data.
- [ ] **Non-Linear Models:** Replace Logistic Regression with a lightweight Gradient-Boosted Tree (XGBoost/LightGBM) or a 2-layer MLP over the 259 features. This maintains the millisecond latency and fixed-parameter constraints while solving the syntactic evasion limits.
- [x] **Anchor Set / Replay:** Kill the pseudo-label loop. Replace it with a frozen anchor set replayed each round, or rely *exclusively* on human-verified / federated updates rather than local self-reinforcement.

---

## Tier 3: Operations & SRE (COMPLETED)
**Problem:** The system lacks basic reliability engineering components required for real-world deployment.
**Impact:** Inability to survive node reboots, monitor true False Positive Rates (FPR), or rollback corrupted models.

**Action Items:**
- [x] **Weight Persistence:** Save `classifier.weights` to disk atomically so they survive a service restart, rather than relying exclusively on the bootstrap file (`local_weights.json`).
- [x] **Model Versioning:** Maintain a history of global models on the Cloud to allow instant rollbacks if a poisoned model slips through (`models/global_v<timestamp>.json`).
- [x] **Shadow Mode:** Implement a "Monitor-Only" flag where the WAF computes the probability and logs it, but never blocks (`HTTP 403`). This is essential to measure the real-world FPR against production traffic before enforcing blocking (`FEDZTA_SHADOW=1`).
- [x] **Fail-Open Policy:** If the WAF script crashes or hangs, the proxy should fail-open (allow traffic) or fail-closed (block traffic) based on an explicit configuration flag, rather than dropping TCP connections unpredictably (`FEDZTA_FAIL_OPEN=1`).
