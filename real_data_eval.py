"""Real-data evaluation of the shipped FedZTA featurisation / model.

Writes real_data_results.json. Three experiments, addressing RIGOR.md S1-1/S1-3:

  1. CSIC 2010 HTTP dataset (downloaded here, never committed). The *shipped*
     model (fed_model.json) is scored through a replica of the gateway's
     per-context scoring path (continuous_waf.py::_inspect_request: path,
     unquoted query, User-Agent, Referer, Cookie, raw body; max over contexts)
     at the deployed threshold 0.15 and at 0.5.
  2. Leave-one-corpus-out (LOCO): hold out one SecLists source file (or a whole
     family: sqli / xss / web / api), retrain with the shipped featuriser and
     SGD hyper-parameters, and test on the held-out source. NOTE: LOCO training
     is *pooled* (centralised) training on the shipped augmentation, not FedAvg;
     it measures featuriser+linear-model generalisation, not federation.
  3. FPR on synthetic-but-realistic benign text (names with apostrophes, search
     text, JSON, base64, URLs, IDs, IoT telemetry), plus a separately reported
     "hard negatives" category (code snippets / markup in prose).

Edge-IIoTset / other IoT sets are NOT included (see "not_included" in output).

Usage:  python real_data_eval.py [--quick] [--cache-dir DIR] [--out FILE]
Needs: numpy, scikit-learn. Network access (SecLists + CSIC mirror).
Every number in the JSON is computed here; nothing is hand-entered.
"""
import argparse
import hashlib
import json
import os
import re
import string
import sys
import time
import urllib.parse
import urllib.request
from multiprocessing import Pool

import numpy as np
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import roc_auc_score

import fedzta_features as F
import train_production_model as T  # reuse SRC, fetch, draw, split_pool, hyper-params

CSIC_BASE = ("https://raw.githubusercontent.com/msudol/Web-Application-Attack-Datasets/"
             "master/OriginalDataSets/csic_2010/")
CSIC_FILES = {"normalTrafficTraining": "normalTrafficTraining.txt",
              "normalTrafficTest": "normalTrafficTest.txt",
              "anomalousTrafficTest": "anomalousTrafficTest.txt"}
THRESHOLDS = (0.5, 0.15)  # 0.5 = eval convention in paper, 0.15 = deployed BLOCK_THRESHOLD
LOCO_SEEDS = (42, 43, 44)
CLASSES = np.array([0, 1])


# ----------------------------------------------------------------- stats utils
def wilson(k, n, z=1.96):
    if n == 0:
        return [None, None]
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [float(max(0, c - h)), float(min(1, c + h))]


def rate(flags):
    flags = np.asarray(flags, bool)
    k, n = int(flags.sum()), len(flags)
    return {"k": k, "n": n, "rate": (k / n if n else None), "ci95_wilson": wilson(k, n)}


def boot_mean_ci(vals, B=2000, seed=0):
    """Percentile bootstrap CI of the mean of per-item values (items resampled)."""
    v = np.asarray(vals, float)
    if len(v) == 0:
        return [None, None]
    r = np.random.default_rng(seed)
    idx = r.integers(0, len(v), (B, len(v)))
    m = v[idx].mean(1)
    return [float(np.percentile(m, 2.5)), float(np.percentile(m, 97.5))]


def boot_auc_ci(y, s, B=300, seed=0):
    y, s = np.asarray(y), np.asarray(s)
    r = np.random.default_rng(seed)
    pos, neg = np.where(y == 1)[0], np.where(y == 0)[0]
    out = []
    for _ in range(B):
        i = np.concatenate([r.choice(pos, len(pos)), r.choice(neg, len(neg))])
        out.append(roc_auc_score(y[i], s[i]))
    return [float(np.percentile(out, 2.5)), float(np.percentile(out, 97.5))]


# ------------------------------------------------------------------ featurising
_POOL = None


def featurise(strings, procs):
    global _POOL
    if len(strings) < 2000 or procs <= 1:
        return np.array([F.extract(s) for s in strings])
    if _POOL is None:
        _POOL = Pool(procs)
    return np.array(_POOL.map(F.extract, strings, chunksize=500))


def sigmoid_scores(X, coef, intercept):
    z = np.clip(X @ np.asarray(coef) + intercept, -250, 250)
    return 1 / (1 + np.exp(-z))


# --------------------------------------------------------------------- download
def cached(url, cache_dir):
    os.makedirs(cache_dir, exist_ok=True)
    fn = os.path.join(cache_dir, hashlib.sha1(url.encode()).hexdigest() + "_" + url.rsplit("/", 1)[-1])
    if not os.path.exists(fn):
        print(f"    downloading {url}")
        with urllib.request.urlopen(url, timeout=180) as r, open(fn + ".part", "wb") as o:
            o.write(r.read())
        os.replace(fn + ".part", fn)
    return fn


def sha256(fn):
    h = hashlib.sha256()
    with open(fn, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


# ------------------------------------------------------------------- CSIC parse
REQ_START = re.compile(r"^(GET|POST|PUT|HEAD|DELETE|OPTIONS|TRACE|CONNECT)\s+(.*)\s+HTTP/\d\.\d\s*$")


def parse_csic(fn):
    reqs, cur = [], None
    with open(fn, "r", encoding="latin-1") as f:
        for line in f:
            line = line.rstrip("\r\n")
            m = REQ_START.match(line)
            if m:
                cur = {"method": m.group(1), "target": m.group(2), "headers": {}, "body": [], "in_body": False}
                reqs.append(cur)
                continue
            if cur is None:
                continue
            if not cur["in_body"]:
                if line == "":
                    cur["in_body"] = True
                elif ":" in line:
                    k, v = line.split(":", 1)
                    cur["headers"][k.strip().lower()] = v.strip()
            else:
                if line != "":
                    cur["body"].append(line)
    return reqs


def gateway_contexts(r):
    """Mirror of continuous_waf.py::_inspect_request context extraction."""
    parsed = urllib.parse.urlparse(r["target"])
    query = urllib.parse.unquote(parsed.query)
    ctx = []
    if parsed.path:
        ctx.append(("path", parsed.path))
    if query:
        ctx.append(("query", query))
    for h in ("user-agent", "referer", "cookie"):
        v = r["headers"].get(h)
        if v:
            ctx.append((h, v))
    if r["method"] in ("POST", "PUT"):
        try:
            length = int(r["headers"].get("content-length", 0))
        except ValueError:
            length = 0
        if length > 0:
            body = "\n".join(r["body"])[:min(length, 8192)]
            if body:
                ctx.append(("body", body))
    return ctx


def summarize_requests(name, per_req, types):
    """per_req: list of {ctx_type: prob}. Returns max-over-contexts summaries."""
    full = np.array([max(d.values()) if d else 0.0 for d in per_req])
    payload = np.array([max([p for t, p in d.items() if t in ("path", "query", "body")] or [0.0])
                        for d in per_req])
    out = {"n_requests": len(per_req)}
    for lab, sc in (("gateway_all_contexts", full), ("payload_contexts_only", payload)):
        out[lab] = {f"flag_rate@{t}": rate(sc >= t) for t in THRESHOLDS}
    out["per_context_flag_rate@0.15"] = {
        t: rate([d.get(t, 0.0) >= 0.15 for d in per_req if t in d]) for t in types}
    return out, full, payload


# --------------------------------------------------------------- experiment 1
def exp_csic(cache_dir, model, procs, quick):
    print("[1] CSIC 2010")
    data, prov = {}, {}
    for k, f in CSIC_FILES.items():
        fn = cached(CSIC_BASE + f, cache_dir)
        data[k] = parse_csic(fn)
        prov[k] = {"url": CSIC_BASE + f, "sha256": sha256(fn), "parsed_requests": len(data[k])}
        if quick:
            data[k] = data[k][:2000]
        print(f"    {k}: {len(data[k])} requests")
    coef, b = model["coefficients"], model["intercept"]
    types = ("path", "query", "user-agent", "referer", "cookie", "body")
    scored, distinct = {}, {}
    for k, reqs in data.items():
        flat, owner = [], []
        for i, r in enumerate(reqs):
            for t, s in gateway_contexts(r):
                flat.append(s)
                owner.append((i, t))
        t0 = time.time()
        p = sigmoid_scores(featurise(flat, procs), coef, b)
        print(f"    scored {k}: {len(flat)} contexts in {time.time()-t0:.0f}s")
        distinct[k] = {}
        for (i, t), pr, st in zip(owner, p, flat):
            distinct[k].setdefault(t, {})[st] = float(pr)
        per = [dict() for _ in reqs]
        for (i, t), pr in zip(owner, p):
            per[i][t] = max(per[i].get(t, 0.0), float(pr))
        scored[k] = per
    diag = {}
    for k, dd in distinct.items():
        diag[k] = {t: {"n_distinct_strings": len(m),
                       "n_distinct_scoring_>=0.15": sum(v >= 0.15 for v in m.values()),
                       "example_scores": {(st[:80]): round(v, 4) for st, v in list(m.items())[:3]}}
                   for t, m in dd.items() if t in ("user-agent", "cookie", "path")}
    res = {"distinct_string_diagnostic": diag,
           "provenance": prov, "label_note":
           "CSIC 'anomalous' = all attack types in the dataset (SQLi, XSS, buffer overflow, CRLF, "
           "path traversal, info gathering, parameter tampering ...). Many are not payload-signature "
           "attacks; recall is NOT attack-family recall. Not stratified by sub-type (no sub-type labels in file).",
           "model": "shipped fed_model.json", "per_file": {}}
    for k in data:
        s, _, _ = summarize_requests(k, scored[k], types)
        res["per_file"][k] = s
    # benign pooled vs anomalous, ROC-AUC with bootstrap CI
    ben = scored["normalTrafficTraining"] + scored["normalTrafficTest"]
    s_ben, f_ben, p_ben = summarize_requests("normal_pooled", ben, types)
    s_att, f_att, p_att = summarize_requests("anomalous", scored["anomalousTrafficTest"], types)
    res["normal_pooled"], res["anomalous"] = s_ben, s_att
    for lab, fb, fa in (("gateway_all_contexts", f_ben, f_att), ("payload_contexts_only", p_ben, p_att)):
        y = np.r_[np.zeros(len(fb)), np.ones(len(fa))]
        sc = np.r_[fb, fa]
        auc = float(roc_auc_score(y, sc))
        # recall at 1% benign FPR, threshold chosen on the SAME benign data (oracle, optimistic)
        thr = float(np.quantile(fb, 0.99))
        res[f"auc_{lab}"] = {"auc": auc, "ci95_bootstrap": boot_auc_ci(y, sc, B=50 if quick else 300),
                             "oracle_thr_at_1pct_fpr": thr,
                             "recall_at_oracle_thr": rate(fa > thr)}
    return res


# --------------------------------------------------------------- experiment 2
def build_sources(raw):
    """Per-file sources with family tags. raw: {path: [strings]}"""
    return {p: {"family": fam, "strings": raw[p]} for fam, ps in T.SRC.items() for p in ps}


def new_model(seed):
    return SGDClassifier(loss="log_loss", penalty="l2", alpha=1e-4, learning_rate="constant",
                         eta0=0.01, random_state=seed)


def train_pooled(X, y, seed, epochs):
    m = new_model(seed)
    r = np.random.default_rng(seed)
    for _ in range(epochs):
        o = r.permutation(len(y))
        m.partial_fit(X[o], y[o], classes=CLASSES)
    return m


def aug_each(strings, label, rng):
    """One random augmentation per payload (same wrappers as shipped training)."""
    return [T.draw([s], 1, label, rng)[0] for s in strings]


def run_fold(srcs, holdout_paths, seed, epochs, procs, test_cap):
    """Train on every source not in holdout_paths; return per-payload scores for held-out
    strings plus a fixed in-distribution benign/attack test set."""
    rng = np.random.default_rng(seed)
    held = [p for p in srcs if p in holdout_paths]
    held_set = {fam: set() for fam in T.SRC}
    for p in held:
        held_set[srcs[p]["family"]] |= set(srcs[p]["strings"])
    split = {}
    for fam in T.SRC:
        for p in [q for q in srcs if srcs[q]["family"] == fam]:
            if p in holdout_paths:
                continue
            pool = [s for s in srcs[p]["strings"] if s not in held_set[fam]]
            split[p] = T.split_pool(pool, rng)
    def pool(fam, j):
        return [s for p, v in split.items() if srcs[p]["family"] == fam for s in v[j]]
    def draw_fams(fams, n_total, label, j=0):
        fams = [f for f in fams if pool(f, j)]
        out = []
        for f in fams:
            out += T.draw(pool(f, j), n_total // len(fams), label, rng)
        return out
    tr = (draw_fams(["web", "api"], 2 * T.N_BENIGN, 0) +
          draw_fams(["sqli", "xss"], T.N_ATTACK * 2, 1))
    Xtr = featurise([s for s, _ in tr], procs)
    ytr = np.array([l for _, l in tr])
    m = train_pooled(Xtr, ytr, seed, epochs)
    coef, b = m.coef_[0], float(m.intercept_[0])
    # in-distribution fixed test: 30% splits of the non-held-out sources
    ref_ben = draw_fams(["web", "api"], 2000, 0, j=1)
    ref_att = draw_fams(["sqli", "xss"], 1000, 1, j=1)
    pr_ben = sigmoid_scores(featurise([s for s, _ in ref_ben], procs), coef, b)
    pr_att = sigmoid_scores(featurise([s for s, _ in ref_att], procs), coef, b) if ref_att else np.array([])
    out = {"ref_benign": pr_ben, "ref_attack": pr_att}
    if not held:
        return out
    held_strings = sorted({s for p in held for s in srcs[p]["strings"]})
    if len(held_strings) > test_cap:
        idx = np.random.default_rng(0).permutation(len(held_strings))[:test_cap]
        held_strings = [held_strings[i] for i in sorted(idx)]
    label = 1 if srcs[held[0]]["family"] in ("sqli", "xss") else 0
    aug = aug_each(held_strings, label, rng)
    out["held_strings_n"] = len(held_strings)
    out["held"] = sigmoid_scores(featurise([s for s, _ in aug], procs), coef, b)
    out["label"] = label
    return out


def exp_loco(raw, procs, quick):
    print("[2] leave-one-corpus-out")
    srcs = build_sources(raw)
    epochs = 20 if quick else T.ROUNDS * T.LOCAL_EPOCHS
    seeds = LOCO_SEEDS[:1] if quick else LOCO_SEEDS
    folds = {"(none: in-distribution reference)": []}
    for p in srcs:
        folds[p] = [p]
    for fam in T.SRC:
        folds[f"FAMILY:{fam}"] = [p for p in srcs if srcs[p]["family"] == fam]
    if quick:
        folds = dict(list(folds.items())[:2] + [("FAMILY:xss", folds["FAMILY:xss"])])
    res = {"note": "pooled centralised training with the shipped featuriser, augmentation and SGD "
                   "hyper-parameters; held-out strings exactly de-duplicated from training within their family; "
                   "recall/FPR use ONE random augmentation per held-out payload per seed; bootstrap CI over "
                   "payloads of the seed-averaged outcome. AUC = held-out vs in-distribution test (30% splits) "
                   "of the opposite class, mean and min/max over seeds.",
           "seeds": list(seeds), "epochs": epochs, "folds": {}}
    for name, hold in folds.items():
        runs = []
        t0 = time.time()
        for sd in seeds:
            if not hold:
                # reference: nothing held out; "held" = the 30% attack split
                r = run_fold({k: v for k, v in srcs.items()}, set(), sd, epochs, procs, 0)
                r["held"], r["label"] = r["ref_attack"], 1
                r["held_strings_n"] = len(r["held"])
            else:
                r = run_fold(srcs, set(hold), sd, epochs, procs, 3000)
            runs.append(r)
        lab = runs[0]["label"]
        H = np.array([r["held"] for r in runs])  # seeds x payloads
        entry = {"held_out_label": "attack" if lab else "benign", "n_payloads": int(H.shape[1]),
                 "n_files_held_out": len(hold)}
        for t in THRESHOLDS:
            flags = (H >= t).mean(0)  # per-payload fraction of seeds flagging
            key = "recall" if lab else "fpr"
            entry[f"{key}@{t}"] = {"mean": float(flags.mean()), "ci95_bootstrap": boot_mean_ci(flags),
                                   "per_seed": [float((h >= t).mean()) for h in H]}
        # in-distribution benign FPR (context): from same models
        entry["ref_benign_fpr@0.5"] = float(np.mean([(r["ref_benign"] >= 0.5).mean() for r in runs]))
        entry["ref_benign_fpr@0.15"] = float(np.mean([(r["ref_benign"] >= 0.15).mean() for r in runs]))
        aucs = []
        for r in runs:
            if lab:
                y = np.r_[np.zeros(len(r["ref_benign"])), np.ones(len(r["held"]))]
                s = np.r_[r["ref_benign"], r["held"]]
            elif len(r["ref_attack"]):
                y = np.r_[np.zeros(len(r["held"])), np.ones(len(r["ref_attack"]))]
                s = np.r_[r["held"], r["ref_attack"]]
            else:
                continue
            aucs.append(float(roc_auc_score(y, s)))
        entry["auc_vs_other_class"] = {"mean": float(np.mean(aucs)), "min": min(aucs), "max": max(aucs)}
        res["folds"][name] = entry
        k = "recall@0.15" if lab else "fpr@0.15"
        print(f"    {name[-60:]:<60} {k}={entry[k]['mean']:.3f}  ({time.time()-t0:.0f}s)")
    return res


# --------------------------------------------------------------- experiment 3
FIRST = ["Sean", "Mary", "Liam", "Aoife", "Giovanni", "Nicole", "Patrick", "Siobhan", "Dante", "Kate",
         "Anne-Marie", "Jean-Luc", "Maria", "Tom", "Ali", "Zoe", "Noor", "Peter", "Hannah", "Oscar"]
APOS = ["O'Brien", "O'Connor", "O'Neill", "D'Angelo", "D'Souza", "N'Diaye", "L'Heureux", "McDonald's",
        "O'Reilly", "Dell'Orto", "Sant'Anna", "D'Arcy", "O'Sullivan", "De'Ath", "Ma'at", "Ka'ahumanu",
        "Hawai'i", "Rock 'n' Roll", "O'Hara", "Mac'Donald"]
WORDS = ("best cheap laptop under 500 dollars reviews weather tomorrow london how to bake sourdough bread "
         "train times from paris to lyon python list comprehension examples nearest pharmacy open now "
         "football scores today recipe for vegetarian lasagne password reset instructions "
         "difference between tcp and udp pizza near me cheap flights to rome hotel with pool "
         "used car prices fix leaking tap what is the capital of australia learn spanish online "
         "install update windows driver select an option from the menu drop shipping business ideas "
         "union station parking hours insert coin arcade games order of operations delete browser history "
         "create account sign in table for two restaurant").split()
KEYS = ["id", "name", "email", "status", "count", "price", "items", "tags", "address", "created_at",
        "user", "device", "value", "unit", "ok", "note", "lang", "page", "limit", "sort"]
HOSTS = ["example.com", "shop.example.org", "api.acme.io", "maps.example.net", "news.example.co.uk"]
PATHS = ["search", "products/list", "v1/users", "cart/add", "docs/getting-started", "images/cat.png",
         "blog/2024/05/release-notes", "api/v2/orders", "login", "static/js/app.min.js"]
PARAMS = ["q", "page", "sort", "utm_source", "utm_medium", "ref", "lang", "id", "redirect", "filter", "category"]


def _words(r, lo, hi):
    return " ".join(r.choice(WORDS, int(r.integers(lo, hi + 1))))


def _json(r, depth=0):
    d = {}
    for k in r.choice(KEYS, int(r.integers(2, 6)), replace=False):
        c = int(r.integers(0, 7 if depth < 2 else 6))
        d[str(k)] = (_words(r, 1, 6) if c == 0 else int(r.integers(0, 10 ** 6)) if c == 1
                     else float(np.round(r.random() * 100, 2)) if c == 2 else bool(r.integers(0, 2)) if c == 3
                     else [int(x) for x in r.integers(0, 100, 3)] if c == 4 else None if c == 5
                     else _json(r, depth + 1))
    return d


def _b64(r):
    import base64
    raw = bytes(r.integers(0, 256, int(r.integers(12, 220)), dtype=np.uint8))
    kind = int(r.integers(0, 3))
    if kind == 0:
        return base64.b64encode(raw).decode()
    if kind == 1:
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")
    h = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    p = base64.urlsafe_b64encode(json.dumps({"sub": str(r.integers(1, 10 ** 6)), "exp": int(r.integers(1.7e9, 1.8e9))}).encode()).decode().rstrip("=")
    return f"{h}.{p}.{base64.urlsafe_b64encode(raw[:32]).decode().rstrip('=')}"


def synth_benign(n_each, seed=2024):
    r = np.random.default_rng(seed)
    cats = {k: set() for k in ("names_with_apostrophes", "search_text", "json_bodies", "base64_and_jwt",
                               "urls_with_query_strings", "ids_emails_dates_addresses", "iot_telemetry",
                               "hard_negatives_code_and_markup")}
    def fill(cat, gen):
        tries = 0
        while len(cats[cat]) < n_each and tries < n_each * 50:
            cats[cat].add(gen()); tries += 1
    def name():
        k = int(r.integers(0, 4))
        full = f"{r.choice(FIRST)} {r.choice(APOS)}"
        return [full, f"last_name={urllib.parse.quote(str(r.choice(APOS)))}&first_name={r.choice(FIRST)}",
                f"name={full.replace(' ', '+')}", f"Dear {full}, your order #{r.integers(1000, 99999)} has shipped"][k]
    def search():
        q = _words(r, 2, 8)
        k = int(r.integers(0, 4))
        return [q, f'"{q}"', f"q={urllib.parse.quote_plus(q)}&page={r.integers(1, 30)}", f"{q} -{r.choice(WORDS)} 2024"][k]
    def js():
        s = json.dumps(_json(r), separators=(",", ":") if r.integers(0, 2) else (", ", ": "))
        return s
    def url():
        q = "&".join(f"{p}={urllib.parse.quote_plus(_words(r, 1, 3))}" if r.integers(0, 2) else f"{p}={r.integers(0, 9999)}"
                     for p in r.choice(PARAMS, int(r.integers(1, 5)), replace=False))
        frag = f"#{r.choice(WORDS)}" if r.integers(0, 3) == 0 else ""
        return f"https://{r.choice(HOSTS)}/{r.choice(PATHS)}?{q}{frag}"
    def ident():
        k = int(r.integers(0, 6))
        h = "".join(r.choice(list("0123456789abcdef"), 32))
        u = f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"
        return [f"{r.choice(FIRST).lower()}.{r.choice(['smith','jones','garcia','khan'])}{r.integers(1, 99)}@{r.choice(HOSTS)}", u,
                f"2024-{r.integers(1, 13):02d}-{r.integers(1, 29):02d}T{r.integers(0, 24):02d}:{r.integers(0, 60):02d}:00Z",
                f"+{r.integers(1, 99)} ({r.integers(100, 999)}) {r.integers(100, 999)}-{r.integers(1000, 9999)}",
                f"{r.integers(1, 999)} {r.choice(['Main','Oak','High','Park'])} Street, Apt #{r.integers(1, 40)}, Springfield, IL {r.integers(10000, 99999)}",
                f"/home/user{r.integers(1, 99)}/documents/report_{r.integers(1, 99)}.pdf"][k]
    def iot():
        k = int(r.integers(0, 3))
        dev = f"sensor-{r.integers(1, 500)}"
        if k == 0:
            return json.dumps({"deviceId": dev, "temp": round(float(r.normal(21, 4)), 2), "humidity": round(float(r.uniform(20, 80)), 1),
                               "battery": int(r.integers(5, 100)), "ts": int(r.integers(1.7e9, 1.8e9))}, separators=(",", ":"))
        if k == 1:
            return f"/api/v1/devices/{dev}/telemetry?from={r.integers(1.7e9, 1.75e9)}&to={r.integers(1.75e9, 1.8e9)}&fields=temp,humidity"
        return f"mqtt/{r.choice(['site-a','site-b'])}/{dev}/state={r.choice(['ON','OFF','IDLE'])};rssi=-{r.integers(40, 95)}"
    def hard():
        k = int(r.integers(0, 5))
        return [f"I <3 this product, {r.integers(1, 9)} < {r.integers(10, 99)} && {r.integers(100, 999)} > {r.integers(1, 9)}",
                f"you can use SELECT name FROM users WHERE id = {r.integers(1, 99)} to list it",
                f"**bold** and `code` and <b>{r.choice(WORDS)}</b> text",
                f"if (x > {r.integers(1, 9)} && y < {r.integers(1, 9)}) {{ return {r.choice(KEYS)}; }}",
                f"<p>{_words(r, 3, 8)}</p><a href=\"https://{r.choice(HOSTS)}/\">link</a>"][k]
    for cat, g in (("names_with_apostrophes", name), ("search_text", search), ("json_bodies", js), ("base64_and_jwt", lambda: _b64(r)),
                   ("urls_with_query_strings", url), ("ids_emails_dates_addresses", ident), ("iot_telemetry", iot),
                   ("hard_negatives_code_and_markup", hard)):
        fill(cat, g)
    return {k: sorted(v) for k, v in cats.items()}


def exp_synth(model, procs, quick):
    print("[3] synthetic realistic benign FPR")
    cats = synth_benign(100 if quick else 500)
    coef, b = model["coefficients"], model["intercept"]
    res = {"note": "synthetic, generated deterministically (seed 2024) by synth_benign(); each string scored as "
                   "ONE context with the shipped model. 'hard_negatives_*' (SQL words / markup / operators in "
                   "prose) are reported separately and excluded from the headline aggregate.",
           "model": "shipped fed_model.json", "categories": {}}
    allp, head = [], []
    for c, strs in cats.items():
        p = sigmoid_scores(featurise(strs, procs), coef, b)
        res["categories"][c] = {"n": len(strs), **{f"fpr@{t}": rate(p >= t) for t in THRESHOLDS},
                                "examples": strs[:3], "highest_scoring": [strs[i] for i in np.argsort(-p)[:3]]}
        if not c.startswith("hard"):
            head.append(p)
    hp = np.concatenate(head)
    res["headline_micro_excl_hard"] = {f"fpr@{t}": rate(hp >= t) for t in THRESHOLDS}
    res["headline_macro_excl_hard"] = {f"fpr@{t}": float(np.mean([(p >= t).mean() for p in head])) for t in THRESHOLDS}
    return res


# ------------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="smoke test: tiny subsets, results NOT for the paper")
    ap.add_argument("--cache-dir", default=os.path.expanduser("~/.cache/fedzta_real_data"))
    ap.add_argument("--out", default="real_data_results.json")
    ap.add_argument("--procs", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    ap.add_argument("--only", default="123", help="which experiments to run, e.g. 13")
    a = ap.parse_args()
    model = json.load(open("fed_model.json"))
    assert len(model["coefficients"]) == F.DIM
    out = {"quick_mode": a.quick, "thresholds": list(THRESHOLDS),
           "threshold_note": "0.5 = convention used elsewhere in the paper; 0.15 = deployed BLOCK_THRESHOLD "
                             "(continuous_waf.py). Neither was tuned on the data used here.",
           "model_sha256": sha256("fed_model.json"),
           "not_included": {"Edge-IIoTset": "Not attempted: distributed through IEEE DataPort / Kaggle "
                            "(account-gated as far as known, not a plain download), and its released tables "
                            "are network-flow features rather than raw HTTP payload strings, so the payload "
                            "featuriser would need a different pipeline. Listed as future work.",
                            "other_IoT_sets": "None cheaply downloadable with raw HTTP payloads were found."}}
    if "1" in a.only:
        out["csic2010"] = exp_csic(a.cache_dir, model, a.procs, a.quick)
    if "2" in a.only:
        print("[*] downloading SecLists")
        raw = {p: T.fetch([p]) for fam in T.SRC.values() for p in fam}
        out["loco"] = exp_loco(raw, a.procs, a.quick)
    if "3" in a.only:
        out["synthetic_benign"] = exp_synth(model, a.procs, a.quick)
    with open(a.out, "w") as f:
        json.dump(out, f, indent=2)
    print(f"[+] wrote {a.out}")


if __name__ == "__main__":
    main()
