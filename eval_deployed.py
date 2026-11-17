"""Deployed-operating-point evaluation of the FedZTA payload classifier.

Addresses the review findings S1-3, S1-4, S2-1 (review/RIGOR.md) without touching the
existing experiment scripts. Writes eval_deployed_results.json. Every number in that file
is produced by this script; nothing is hard-coded.

What it does
  1. Proper train / validation / test split (60/20/20 by payload group). Thresholds are
     selected on VALIDATION only. Reported on TEST at (a) the deployed
     BLOCK_THRESHOLD=0.15 and (b) the validation-selected thresholds (largest recall with
     validation FPR <= 1 % and <= 0.1 %): FPR (all / web / api), per-class recall, ROC-AUC, PR-AUC.
  2. Serving-path reproduction. Each test payload is embedded in a synthetic HTTP request
     (query / path / body / cookie / referer / user-agent, uniformly) with benign background
     headers, then scored the way continuous_waf.py does: path, unquoted query, User-Agent,
     Referer, Cookie, body scored independently, block on the MAX. Compared with
     whole-string scoring (the training/evaluation-script convention) and with scoring only
     the injected context (isolates max-over-contexts inflation from the context mix).
  3. Uncertainty: bootstrap 95 % CIs resampling UNIQUE PAYLOADS (not draws) on a primary
     split; paired federated-vs-silo comparison over >= 20 seeds where every seed draws a NEW
     split (seed_stability.py reused one fixed split via default_rng(12345)). The silo
     compared against is chosen on validation AUC (no test-set winner's curse); the
     test-oracle best silo is reported as well (optimistic for the silo). A pooled/centralised
     model is included as the missing baseline.
  4. Leakage control: split modes `random` (exact-unique, as train_production_model.py),
     `cluster` (near-duplicate groups kept together) and `source` (whole SecLists source
     files held out for the attack classes). Near-duplicate rate (test payload with
     normalised-Levenshtein similarity >= 0.80 to some train payload) is measured per mode.

Caveats (also written into the JSON)
  * Models are RE-TRAINED here with the production recipe (D=256 3-gram + 3 syntactic
    features, domain split, FedAvg R=20 x E=30, same augmentation). fed_model.json cannot be
    scored honestly: its training payloads overlap any random test split. BLOCK_THRESHOLD
    0.15 was set for that shipped model, so FPR at 0.15 here is a statement about the
    recipe, not about the shipped weights.
  * Benign data are SecLists word lists (path tokens), still not real traffic.
  * The gateway scorer is a re-implementation of continuous_waf._inspect_request (that
    module cannot be imported: it loads an enrolment secret at import time).
  * Benign near-duplicate grouping is a normalised key (case/digits/separators/extension/
    plural), NOT edit distance (43k^2 pairs); attack grouping is edit-distance based.

Usage: python eval_deployed.py [--seeds 20] [--workers 8] [--cache DIR] [--quick]
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from multiprocessing import Pool

import numpy as np
from scipy import stats as sps
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import average_precision_score, precision_recall_curve, roc_auc_score, roc_curve

import fedzta_features as F
import train_production_model as T

try:
    from rapidfuzz import fuzz, process
    HAVE_RF = True
except ImportError:  # slow fallback
    import difflib
    HAVE_RF = False

DEPLOYED_THR = 0.15          # continuous_waf.BLOCK_THRESHOLD
BUDGETS = (0.01, 0.001)      # validation FPR budgets for threshold selection
SIM_THR = 80                 # near-duplicate: normalised similarity >= 0.80 (fuzz.ratio scale)
FRACS = (0.6, 0.2, 0.2)
MODES = ("random", "cluster", "source")
MODELS = ("Edge A (web)", "Edge B (api)", "Federated", "Pooled")
CLS = ("web", "api", "sqli", "xss")
CAP_BENIGN, ATTACK_REPS = 1500, 3     # test/val: unique benign per domain, wrappers per attack payload
LOCS = ("query", "path", "body", "cookie", "referer", "ua")
VIEWS = ("whole", "gateway", "gateway_inject_only")
CORPUS = None  # set in main, inherited by forked workers


# ----------------------------------------------------------------------------- corpus
def read_source(path, cache):
    fn = os.path.join(cache, path.replace("/", "__")) if cache else None
    if fn and os.path.exists(fn):
        raw = open(fn, "rb").read()
    else:
        with urllib.request.urlopen(T.RAW + path, timeout=90) as r:
            raw = r.read()
        if fn:
            os.makedirs(cache, exist_ok=True)
            open(fn, "wb").write(raw)
    lines = [l.strip() for l in raw.decode("utf-8", "ignore").splitlines() if l.strip()]
    return lines, hashlib.sha256(raw).hexdigest()


def norm_attack(s):
    return re.sub(r"\d+", "0", re.sub(r"\s+", "", s.lower()))


def key_benign(s):
    s = s.lower().split(".")[0] or s.lower()
    s = re.sub(r"\d+", "0", re.sub(r"[^a-z0-9]", "", s))
    return s.rstrip("s") or s


def groups_attack(payloads):
    n = len(payloads)
    parent = list(range(n))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i
    keys = [norm_attack(p) for p in payloads]
    if HAVE_RF:
        M = process.cdist(keys, keys, scorer=fuzz.ratio, score_cutoff=SIM_THR, workers=-1)
        pairs = np.argwhere(M >= SIM_THR)
    else:
        pairs = [(i, j) for i in range(n) for j in range(i + 1, n)
                 if difflib.SequenceMatcher(None, keys[i], keys[j]).ratio() * 100 >= SIM_THR]
    for i, j in pairs:
        parent[find(int(i))] = find(int(j))
    return [find(i) for i in range(n)]


def load_corpus(cache):
    corpus, hashes = {}, {}
    for cls, paths in T.SRC.items():
        d = {}
        for si, p in enumerate(paths):
            lines, h = read_source(p, cache)
            hashes[p] = h
            for l in lines:
                d.setdefault(l, set()).add(si)
        pay = sorted(d)
        if cls in ("sqli", "xss"):
            grp = groups_attack(pay)
        else:
            ids = {}
            grp = [ids.setdefault(key_benign(p), len(ids)) for p in pay]
        corpus[cls] = {"payloads": pay, "src": [sorted(d[p]) for p in pay], "group": grp,
                       "n_src": len(paths)}
    return corpus, hashes


# ----------------------------------------------------------------------------- splits
def fill(units, rng):
    order = rng.permutation(len(units))
    N = sum(len(u) for u in units)
    out, c = ([], [], []), 0
    for i in order:
        r = 0 if c < FRACS[0] * N else (1 if c < (FRACS[0] + FRACS[1]) * N else 2)
        out[r].extend(units[i])
        c += len(units[i])
    return out


def split_class(cls, mode, rng):
    c = CORPUS[cls]
    pay = c["payloads"]
    if mode == "random":
        return fill([[p] for p in pay], rng)
    if mode == "source" and cls in ("sqli", "xss"):
        n = c["n_src"]
        perm = rng.permutation(n)
        ntr = max(1, round(FRACS[0] * n))
        nva = max(1, round(FRACS[1] * n))
        if ntr + nva >= n:
            nva = max(1, n - ntr - 1)
        role = {int(s): (0 if i < ntr else 1 if i < ntr + nva else 2) for i, s in enumerate(perm)}
        out = ([], [], [])
        for p, ss in zip(pay, c["src"]):
            out[min(role[s] for s in ss)].append(p)   # any train source -> train: exact-disjoint
        return out
    units = {}
    for p, g in zip(pay, c["group"]):
        units.setdefault(g, []).append(p)
    return fill(list(units.values()), rng)


def near_dup_rate(train, test):
    """Fraction of test attack payloads with similarity >= 0.80 to some train payload, plus mean max-sim."""
    if not test or not train:
        return None
    a, b = [norm_attack(p) for p in test], [norm_attack(p) for p in train]
    if HAVE_RF:
        mx = process.cdist(a, b, scorer=fuzz.ratio, workers=1).max(axis=1)
    else:
        mx = np.array([max(difflib.SequenceMatcher(None, x, y).ratio() * 100 for y in b) for x in a])
    return {"frac_ge_0.8": float((mx >= SIM_THR).mean()), "mean_max_sim": float(mx.mean() / 100)}


# ----------------------------------------------------------------------------- gateway path
def gateway_contexts(target, headers, body, method):
    """Mirror of continuous_waf.Gateway._inspect_request context assembly (lines ~151-185)."""
    parsed = urllib.parse.urlparse(target)
    query = urllib.parse.unquote(parsed.query)
    ctx = []
    if parsed.path:
        ctx.append(("path", parsed.path))
    if query:
        ctx.append(("query", query))
    for h, name in (("User-Agent", "ua"), ("Referer", "referer"), ("Cookie", "cookie")):
        v = headers.get(h)
        if v:
            ctx.append((name, v))
    if method in ("POST", "PUT") and body:
        b = body.encode()[:8192].decode(errors="ignore")
        if b:
            ctx.append(("body", b))
    return ctx


def build_request(payload, loc, rng):
    headers = {"User-Agent": str(rng.choice(T.UAS))}
    target, body, method = "/api/items?page=1&limit=20", "", "GET"
    if rng.random() < 0.5:
        headers["Referer"] = "https://example.com/"
    if rng.random() < 0.5:
        headers["Cookie"] = f"_ga=GA1.2.{rng.integers(100000, 999999)}; _gid=GA1.2.{rng.integers(100000, 999999)}"
    if loc == "query":
        target = "/search?q=" + urllib.parse.quote(payload, safe="")
    elif loc == "path":
        target = "/" + urllib.parse.quote(payload, safe="/")
    elif loc == "body":
        method, target = "POST", "/submit"
        body = (f"form_data={payload}&submit=true" if rng.random() < 0.5
                else f'{{"query":"{payload}","page":1}}')
    elif loc == "cookie":
        headers["Cookie"] = f"_ga=GA1.2.{rng.integers(100000, 999999)}; session={payload}"
    elif loc == "referer":
        headers["Referer"] = "https://example.com/search?q=" + payload
    elif loc == "ua":
        headers["User-Agent"] = payload
    return gateway_contexts(target, headers, body, method)


# ----------------------------------------------------------------------------- feature cache / datasets
_FC = {}


def feats(text):
    v = _FC.get(text)
    if v is None:
        if len(_FC) > 400000:
            _FC.clear()
        v = _FC[text] = np.array(F.extract(text))
    return v


class EvalSet:
    """Aligned per-sample arrays for whole-string and gateway views over one payload universe."""

    def __init__(self, split, rng):
        self.payloads, self.pcls = [], []     # universe
        samples = []                          # (pid, label, cls)
        for cls in CLS:
            pl = list(split[cls])
            if cls in ("web", "api"):
                if len(pl) > CAP_BENIGN:
                    pl = [pl[i] for i in rng.choice(len(pl), CAP_BENIGN, replace=False)]
                reps = 1
            else:
                reps = ATTACK_REPS
            lab = 0 if cls in ("web", "api") else 1
            for p in pl:
                pid = len(self.payloads)
                self.payloads.append(p)
                self.pcls.append(cls)
                samples += [(pid, lab, cls)] * reps
        self.pid = np.array([s[0] for s in samples])
        self.y = np.array([s[1] for s in samples])
        self.cls = np.array([s[2] for s in samples])
        self.pcls = np.array(self.pcls)
        # whole-string view: production augmentation wrapper
        self.whole = np.array([feats(T.draw([self.payloads[i]], 1, int(l), rng)[0][0])
                               for i, l in zip(self.pid, self.y)])
        # gateway view: one synthetic request per sample
        flat, off, inj, nctx = [], [], [], []
        for i in self.pid:
            loc = LOCS[rng.integers(0, len(LOCS))]
            ctx = build_request(self.payloads[i], loc, rng)
            if loc not in [n for n, _ in ctx]:   # e.g. payload "/" -> "//" parsed as netloc, path empty
                loc = "query"
                ctx = build_request(self.payloads[i], loc, rng)
            off.append(len(flat))
            inj.append(len(flat) + [n for n, _ in ctx].index(loc))
            nctx.append(len(ctx))
            flat += [feats(t) for _, t in ctx]
        self.gflat, self.goff, self.ginj = np.array(flat), np.array(off), np.array(inj)
        self.nctx = float(np.mean(nctx))

    def scores(self, coef, b):
        sig = lambda z: 1.0 / (1.0 + np.exp(-np.clip(z, -250, 250)))
        pc = sig(self.gflat @ coef + b)
        return {"whole": sig(self.whole @ coef + b),
                "gateway": np.maximum.reduceat(pc, self.goff),
                "gateway_inject_only": pc[self.ginj]}


# ----------------------------------------------------------------------------- metrics
def metrics(p, ds, thr, w):
    pred, ben = p >= thr, ds.y == 0
    out = {}
    wb = w[ben]
    out["fpr"] = float((wb * pred[ben]).sum() / wb.sum())
    for c in ("web", "api", "sqli", "xss"):
        m = ds.cls == c
        key = ("fpr_" if c in ("web", "api") else "recall_") + c
        out[key] = float((w[m] * pred[m]).sum() / w[m].sum())
    return out


def auc_pr(p, ds, w):
    return {"roc_auc": float(roc_auc_score(ds.y, p, sample_weight=w)),
            "pr_auc": float(average_precision_score(ds.y, p, sample_weight=w))}


def select_thr(p, ds, budget):
    """Smallest threshold on a VALIDATION set whose benign FPR <= budget (predict p >= thr)."""
    b = np.sort(p[ds.y == 0])[::-1]
    k = int(np.floor(budget * len(b)))
    return float(np.nextafter(b[k], np.inf)) if k < len(b) else float(b[-1])


def boot_weights(ds, rng):
    w = np.zeros(len(ds.payloads))
    for c in CLS:
        idx = np.where(ds.pcls == c)[0]
        w[idx] = rng.multinomial(len(idx), np.full(len(idx), 1.0 / len(idx)))
    return w[ds.pid]


# ----------------------------------------------------------------------------- training
def new_model(seed):
    return SGDClassifier(loss="log_loss", penalty="l2", alpha=1e-4, learning_rate="constant",
                         eta0=0.01, random_state=seed)


def train_iso(X, y, seed):
    m, r = new_model(seed), np.random.default_rng(seed)
    for _ in range(T.ROUNDS * T.LOCAL_EPOCHS):
        o = r.permutation(len(y))
        m.partial_fit(X[o], y[o], classes=T.CLASSES)
    return m.coef_[0].copy(), float(m.intercept_[0])


def train_fed(Xa, ya, Xb, yb, seed):
    na, nb = new_model(seed), new_model(seed)
    ra, rb = np.random.default_rng(seed), np.random.default_rng(seed + 1)
    g = None
    for _ in range(T.ROUNDS):
        if g:
            T.set_params(na, *g)
            T.set_params(nb, *g)
        for m, X, y, r in ((na, Xa, ya, ra), (nb, Xb, yb, rb)):
            for _ in range(T.LOCAL_EPOCHS):
                o = r.permutation(len(y))
                m.partial_fit(X[o], y[o], classes=T.CLASSES)
        w = np.array([len(ya), len(yb)], float)
        w /= w.sum()
        g = (w[0] * na.coef_ + w[1] * nb.coef_, w[0] * na.intercept_ + w[1] * nb.intercept_)
    return g[0][0].copy(), float(g[1][0])


def train_set(split, rng):
    half = T.N_ATTACK // 2
    mk = lambda ben: (T.draw(split[ben], T.N_BENIGN, 0, rng) + T.draw(split["xss"], half, 1, rng)
                      + T.draw(split["sqli"], half, 1, rng))
    a, b = mk("web"), mk("api")
    return T.build(a), T.build(b)


def _init(corpus):
    global CORPUS
    CORPUS = corpus


# ----------------------------------------------------------------------------- one (mode, seed) task
def run_task(args):
    mode, seed, B_delta, B_primary = args
    t0 = time.time()
    rng = np.random.default_rng(np.random.SeedSequence([seed, MODES.index(mode)]))
    parts = {c: split_class(c, mode, rng) for c in CLS}
    tr = {c: parts[c][0] for c in CLS}
    va = {c: parts[c][1] for c in CLS}
    te = {c: parts[c][2] for c in CLS}
    leak = {c: near_dup_rate(tr[c], te[c]) for c in ("sqli", "xss")}
    sizes = {c: [len(x) for x in parts[c]] for c in CLS}

    (Xa, ya), (Xb, yb) = train_set(tr, rng)
    models = {"Edge A (web)": train_iso(Xa, ya, seed), "Edge B (api)": train_iso(Xb, yb, seed),
              "Federated": train_fed(Xa, ya, Xb, yb, seed),
              "Pooled": train_iso(np.vstack([Xa, Xb]), np.concatenate([ya, yb]), seed)}
    dsv, dst = EvalSet(va, rng), EvalSet(te, rng)

    res, sc_test, sc_val = {}, {}, {}
    one = lambda ds: np.ones(len(ds.y))
    for nm, (coef, b) in models.items():
        sv, st = dsv.scores(coef, b), dst.scores(coef, b)
        sc_val[nm], sc_test[nm] = sv, st
        r = {}
        for v in VIEWS:
            thr = {f"val_sel_fpr{bud}": select_thr(sv[v], dsv, bud) for bud in BUDGETS}
            if v != "whole":
                thr.update({f"whole_val_sel_fpr{bud}": select_thr(sv["whole"], dsv, bud) for bud in BUDGETS})
            thr["deployed_0.15"] = DEPLOYED_THR
            r[v] = {"val_roc_auc": auc_pr(sv[v], dsv, one(dsv))["roc_auc"],
                    **auc_pr(st[v], dst, one(dst)),
                    "ops": {k: {"threshold": t, **metrics(st[v], dst, t, one(dst))} for k, t in thr.items()}}
        res[nm] = r

    # paired delta federated - silo (silo chosen on validation AUC), bootstrap over unique test payloads
    silo_val = max(("Edge A (web)", "Edge B (api)"), key=lambda n: res[n]["whole"]["val_roc_auc"])
    silo_orc = max(("Edge A (web)", "Edge B (api)"), key=lambda n: res[n]["whole"]["roc_auc"])
    brng = np.random.default_rng(seed + 999)
    dl = []
    for _ in range(B_delta):
        w = boot_weights(dst, brng)
        dl.append(roc_auc_score(dst.y, sc_test["Federated"]["whole"], sample_weight=w)
                  - roc_auc_score(dst.y, sc_test[silo_val]["whole"], sample_weight=w))
    out = {"mode": mode, "seed": seed, "sizes_unique_train_val_test": sizes, "near_dup_test_vs_train": leak,
           "silo_by_val": silo_val, "silo_oracle": silo_orc, "mean_contexts_per_request": dst.nctx,
           "n_test_samples": int(len(dst.y)), "n_test_unique": {c: int((dst.pcls == c).sum()) for c in CLS},
           "models": res,
           "delta_auc_fed_minus_silo_val": res["Federated"]["whole"]["roc_auc"] - res[silo_val]["whole"]["roc_auc"],
           "delta_auc_fed_minus_silo_val_boot95": [float(np.percentile(dl, 2.5)), float(np.percentile(dl, 97.5))]}

    if B_primary:   # bootstrap CIs on the primary split
        prng = np.random.default_rng(seed + 31337)
        coef, b = models["Federated"]
        ops = {v: {k: o["threshold"] for k, o in res["Federated"][v]["ops"].items()} for v in VIEWS}
        acc = {}
        for _ in range(B_primary):
            w = boot_weights(dst, prng)
            for v in VIEWS:
                for k, t in ops[v].items():
                    for mk, mv in metrics(sc_test["Federated"][v], dst, t, w).items():
                        acc.setdefault(f"{v}|{k}|{mk}", []).append(mv)
                for mk, mv in auc_pr(sc_test["Federated"][v], dst, w).items():
                    acc.setdefault(f"{v}|{mk}", []).append(mv)
            for k in ("deployed_0.15",):   # paired: gateway minus whole-string FPR
                acc.setdefault("gateway_minus_whole|deployed_0.15|fpr", []).append(
                    metrics(sc_test["Federated"]["gateway"], dst, DEPLOYED_THR, w)["fpr"]
                    - metrics(sc_test["Federated"]["whole"], dst, DEPLOYED_THR, w)["fpr"])
        out["primary_bootstrap95"] = {k: [float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))]
                                      for k, v in acc.items()}
        out["primary_bootstrap_B"] = B_primary
        curves = {}
        for v in VIEWS:
            fp, tp, _ = roc_curve(dst.y, sc_test["Federated"][v])
            pr, rc, _ = precision_recall_curve(dst.y, sc_test["Federated"][v])
            si = lambda n: np.unique(np.linspace(0, n - 1, 200).astype(int))
            curves[v] = {"roc_fpr": fp[si(len(fp))].tolist(), "roc_tpr": tp[si(len(tp))].tolist(),
                         "pr_precision": pr[si(len(pr))].tolist(), "pr_recall": rc[si(len(rc))].tolist()}
        out["primary_curves_federated"] = curves
        out["primary_test_attack_prevalence_in_samples"] = float(dst.y.mean())
    out["seconds"] = round(time.time() - t0, 1)
    print(f"[{mode:7s} seed {seed}] done in {out['seconds']}s", flush=True)
    return out


# ----------------------------------------------------------------------------- aggregation
def ci(v):
    v = np.asarray(v, float)
    if len(v) < 2:
        return {"mean": float(v.mean()), "std": None, "ci95": None, "n": len(v)}
    h = sps.t.ppf(0.975, len(v) - 1) * v.std(ddof=1) / np.sqrt(len(v))
    return {"mean": float(v.mean()), "std": float(v.std(ddof=1)),
            "ci95": [float(v.mean() - h), float(v.mean() + h)], "n": len(v)}


def aggregate(runs):
    agg = {"models": {}}
    for nm in MODELS:
        agg["models"][nm] = {}
        for v in VIEWS:
            e = {k: ci([r["models"][nm][v][k] for r in runs]) for k in ("roc_auc", "pr_auc")}
            e["ops"] = {}
            for op in runs[0]["models"][nm][v]["ops"]:
                e["ops"][op] = {k: ci([r["models"][nm][v]["ops"][op][k] for r in runs])
                                for k in runs[0]["models"][nm][v]["ops"][op]}
            agg["models"][nm][v] = e
    # paired federated vs silo
    def pair(sel):
        d = {}
        for label, ref in (("vs_silo_selected_on_val", lambda r: r["silo_by_val"]),
                           ("vs_silo_test_oracle_best", lambda r: r["silo_oracle"]),
                           ("vs_pooled", lambda r: "Pooled")):
            rows = []
            for r in runs:
                f, s = r["models"]["Federated"], r["models"][ref(r)]
                rows.append(sel(f) - sel(s))
            rows = np.array(rows)
            e = ci(rows)
            e["fed_wins"] = int((rows > 0).sum())
            e["ties"] = int((rows == 0).sum())
            nz = rows[rows != 0]
            e["sign_test_p_two_sided"] = float(sps.binomtest(int((nz > 0).sum()), len(nz), 0.5).pvalue) if len(nz) else None
            try:
                e["wilcoxon_p_two_sided"] = float(sps.wilcoxon(rows).pvalue)
            except ValueError:
                e["wilcoxon_p_two_sided"] = None
            d[label] = e
        return d
    agg["paired_fed_minus_baseline"] = {
        "roc_auc_whole": pair(lambda m: m["whole"]["roc_auc"]),
        "pr_auc_whole": pair(lambda m: m["whole"]["pr_auc"]),
        "roc_auc_gateway": pair(lambda m: m["gateway"]["roc_auc"]),
        "recall_sqli_at_val_sel_fpr0.01_whole": pair(lambda m: m["whole"]["ops"]["val_sel_fpr0.01"]["recall_sqli"]),
        "recall_xss_at_val_sel_fpr0.01_whole": pair(lambda m: m["whole"]["ops"]["val_sel_fpr0.01"]["recall_xss"]),
        "fpr_at_deployed_0.15_whole": pair(lambda m: m["whole"]["ops"]["deployed_0.15"]["fpr"]),
    }
    agg["silo_selected_by_val_counts"] = {n: sum(r["silo_by_val"] == n for r in runs)
                                          for n in ("Edge A (web)", "Edge B (api)")}
    agg["near_dup_test_vs_train"] = {c: {k: ci([r["near_dup_test_vs_train"][c][k] for r in runs])
                                         for k in ("frac_ge_0.8", "mean_max_sim")} for c in ("sqli", "xss")}
    agg["mean_contexts_per_request"] = ci([r["mean_contexts_per_request"] for r in runs])
    return agg


def main():
    global CORPUS
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=20)
    ap.add_argument("--first-seed", type=int, default=42)
    ap.add_argument("--workers", type=int, default=min(8, os.cpu_count() or 1))
    ap.add_argument("--cache", default=None, help="directory to cache downloaded SecLists files")
    ap.add_argument("--out", default="eval_deployed_results.json")
    ap.add_argument("--B-primary", type=int, default=1000)
    ap.add_argument("--B-delta", type=int, default=200)
    ap.add_argument("--quick", action="store_true", help="smoke test: 2 seeds, tiny bootstrap")
    a = ap.parse_args()
    if a.quick:
        a.seeds, a.B_primary, a.B_delta = 2, 20, 20
    if a.seeds < 2:
        sys.exit("need >=2 seeds")

    print("[*] loading corpora + clustering", flush=True)
    CORPUS, hashes = load_corpus(a.cache)
    seeds = list(range(a.first_seed, a.first_seed + a.seeds))
    tasks = [(m, s, a.B_delta, a.B_primary if (m == "cluster" and s == seeds[0]) else 0)
             for m in MODES for s in seeds]
    with Pool(a.workers, initializer=_init, initargs=(CORPUS,)) as pool:
        runs = pool.map(run_task, tasks, chunksize=1)

    by_mode = {m: sorted([r for r in runs if r["mode"] == m], key=lambda r: r["seed"]) for m in MODES}
    primary = next(r for r in by_mode["cluster"] if "primary_bootstrap95" in r)
    try:
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        commit = None
    out = {
        "meta": {"script": "eval_deployed.py", "git_head": commit, "seeds": seeds, "modes": list(MODES),
                 "deployed_block_threshold": DEPLOYED_THR, "threshold_budgets_val_fpr": list(BUDGETS),
                 "split_fractions_train_val_test": FRACS, "views": list(VIEWS),
                 "numpy": np.__version__, "rapidfuzz": HAVE_RF,
                 "ci_notes": "Across-seed CIs: t-interval on per-seed values. Primary-split CIs: bootstrap "
                             "resampling unique payloads within each class (B per primary_bootstrap_B).",
                 "eval_set": f"val/test: up to {CAP_BENIGN} unique benign per domain x1 wrapper; every unique attack "
                             f"payload x{ATTACK_REPS} random wrappers; PR-AUC depends on this attack prevalence.",
                 "corpus_unique_payloads": {c: len(CORPUS[c]["payloads"]) for c in CLS},
                 "corpus_attack_clusters": {c: len(set(CORPUS[c]["group"])) for c in CLS},
                 "corpus_benign_key_groups": {c: len(set(CORPUS[c]["group"])) for c in ("web", "api")},
                 "seclists_sha256": hashes,
                 "caveats": [
                     "Models are re-trained with the production recipe; shipped fed_model.json is not scored "
                     "(its training payloads overlap random test splits). Threshold 0.15 was set for the shipped "
                     "model, so FPR at 0.15 here characterises the recipe.",
                     "Benign data are SecLists word lists, not real traffic.",
                     "Gateway scorer re-implements continuous_waf._inspect_request; request construction "
                     "(location mix, background headers) is synthetic.",
                     "Benign near-duplicate grouping is a normalised key, not edit distance."]},
        "primary": {"mode": "cluster", "seed": primary["seed"], "result": primary},
        "per_seed": by_mode,
        "aggregate": {m: aggregate(by_mode[m]) for m in MODES},
    }
    with open(a.out, "w") as fh:
        json.dump(out, fh, indent=1)
    print(f"[+] wrote {a.out}")


if __name__ == "__main__":
    main()
