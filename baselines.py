"""Baselines for the FedZTA payload classifier, on the data, splits and benign
sets of train_production_model.py (same corpora, same per-seed RNG stream, same
domain-split topology: node A = web benign, node B = api benign, both with the
same XSS/SQLi training attacks; test = held-out web/api benign + held-out
XSS/SQLi payloads).

Writes baselines_results.json. Models:
  pooled_linear      centralised SGD logistic regression on A+B (upper bound)
  fedavg_sgd         production FedAvg (sklearn SGD, as train_production_model.py)
  fedavg_np          FedAvg, own numpy minibatch logistic regression
  fedprox_mu*        FedProx (proximal term mu/2 ||w - w_global||^2), same solver
  isolated_A/B       single-node models, no federation
  regex              trivial regex detector (count of matched signature classes)
  charclass          character-class detector (fraction of metacharacters)
  libinjection       libinjection SQLi + XSS flags (if pip-installable)
  gbt                HistGradientBoosting on the same features, pooled
  mlp                MLP(64,32) on the same features, pooled
  modsecurity_crs    NOT RUN (see config.not_run)

Metrics per seed on the test set: ROC-AUC, recall (all attacks) at 0.1% and 1%
benign FPR (threshold from the benign test scores, strict '>'), plus per-class
recall. 95% CIs: B bootstrap resamples of the test set per seed; the CI of the
seed-mean averages replicate b across seeds (test-sampling uncertainty), and the
across-seed std is reported separately (training-sampling uncertainty).
"""
import json
import re
import sys

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import roc_auc_score
from sklearn.neural_network import MLPClassifier

import fedzta_features as F
import train_production_model as T

B_BOOT = 200
FPRS = (0.001, 0.01)
FEDNP = dict(lr=0.5, batch=32, alpha=1e-4)
MUS = (0.0, 0.01, 0.1, 1.0)

try:
    import libinjection
    HAVE_LIBINJ = True
except ImportError:
    HAVE_LIBINJ = False

REGEX_CLASSES = [
    r"(?i)\bunion\b.{0,20}\bselect\b", r"(?i)\bselect\b.{0,40}\bfrom\b",
    r"(?i)\b(or|and)\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+", r"(?i)\bsleep\s*\(|benchmark\s*\(|waitfor\s+delay",
    r"(?i)(--|#|/\*)\s*$|;\s*(drop|insert|update|delete|exec)\b", r"'\s*(or|and|;|--|\))",
    r"(?i)<\s*script", r"(?i)\bon\w+\s*=", r"(?i)javascript\s*:", r"(?i)<\s*(img|svg|iframe|body|input|a)\b[^>]*>",
    r"(?i)\b(alert|prompt|confirm)\s*\(", r"(?i)document\.(cookie|location)|eval\s*\(",
]
REGEX_RE = [re.compile(p) for p in REGEX_CLASSES]


def s_regex(texts):
    return np.array([sum(1 for r in REGEX_RE if r.search(t)) for t in texts], float)


def s_charclass(texts):
    meta = set("'\"<>;()=&|`\\%{}[]*/#-")
    return np.array([sum(c in meta for c in t) / max(len(t), 1) for t in texts], float)


def s_libinj(texts):
    out = []
    for t in texts:
        out.append(float(libinjection.is_sql_injection(t)["is_sqli"])
                   + float(libinjection.is_xss(t)["is_xss"]))
    return np.array(out)


def recall_at(score, y, tgt):
    ben = np.sort(score[y == 0])[::-1]
    k = int(np.floor(tgt * len(ben)))
    thr = ben[k] if k < len(ben) else ben[-1]
    return thr


def metrics(score, y, m_xss, m_sql):
    out = {"roc_auc": float(roc_auc_score(y, score))}
    for t in FPRS:
        thr = recall_at(score, y, t)
        det = score > thr
        out[f"recall@fpr{t}"] = float(det[y == 1].mean())
        out[f"xss_recall@fpr{t}"] = float(det[m_xss].mean())
        out[f"sqli_recall@fpr{t}"] = float(det[m_sql].mean())
        out[f"actual_fpr@{t}"] = float(det[y == 0].mean())
    return out


def boot(score, y, rng):
    """Bootstrap replicates of (auc, recall@0.1%, recall@1%)."""
    n = len(y)
    res = np.empty((B_BOOT, 3))
    for b in range(B_BOOT):
        i = rng.integers(0, n, n)
        s, yy = score[i], y[i]
        res[b, 0] = roc_auc_score(yy, s)
        for j, t in enumerate(FPRS):
            thr = recall_at(s, yy, t)
            res[b, 1 + j] = (s[yy == 1] > thr).mean()
    return res


# ---- numpy logistic regression, FedAvg / FedProx ---------------------------
def local_train(w, b, X, y, rng, epochs, mu, wg, bg):
    lr, bs, al = FEDNP["lr"], FEDNP["batch"], FEDNP["alpha"]
    n = len(y)
    for _ in range(epochs):
        o = rng.permutation(n)
        for s in range(0, n, bs):
            i = o[s:s + bs]
            z = np.clip(X[i] @ w + b, -30, 30)
            e = 1 / (1 + np.exp(-z)) - y[i]
            gw = X[i].T @ e / len(i) + al * w + mu * (w - wg)
            gb = e.mean() + mu * (b - bg)
            w = w - lr * gw
            b = b - lr * gb
    return w, b


def fed_np(Xs, ys, mu, seed):
    d = Xs[0].shape[1]
    wg, bg = np.zeros(d), 0.0
    rs = [np.random.default_rng(seed), np.random.default_rng(seed + 1)]
    wts = np.array([len(y) for y in ys], float)
    wts /= wts.sum()
    for _ in range(T.ROUNDS):
        loc = [local_train(wg.copy(), bg, X, y, r, T.LOCAL_EPOCHS, mu, wg, bg)
               for X, y, r in zip(Xs, ys, rs)]
        wg = sum(w * l[0] for w, l in zip(wts, loc))
        bg = sum(w * l[1] for w, l in zip(wts, loc))
    return wg, bg


def fedavg_sgd(X_a, y_a, X_b, y_b, seed):
    """Exactly the production FedAvg loop."""
    na, nb, g = T.new_model(), T.new_model(), None
    ra, rb = np.random.default_rng(seed), np.random.default_rng(seed + 1)
    for _ in range(T.ROUNDS):
        if g:
            T.set_params(na, *g)
            T.set_params(nb, *g)
        for m, X, y, r in ((na, X_a, y_a, ra), (nb, X_b, y_b, rb)):
            for _ in range(T.LOCAL_EPOCHS):
                o = r.permutation(len(y))
                m.partial_fit(X[o], y[o], classes=T.CLASSES)
        w = np.array([len(y_a), len(y_b)], float)
        w /= w.sum()
        g = (w[0] * na.coef_ + w[1] * nb.coef_, w[0] * na.intercept_ + w[1] * nb.intercept_)
    return T.set_params(T.new_model(), *g)


def sgd_fit(X, y, seed):
    m = T.new_model()
    r = np.random.default_rng(seed)
    for _ in range(T.ROUNDS * T.LOCAL_EPOCHS):
        o = r.permutation(len(y))
        m.partial_fit(X[o], y[o], classes=T.CLASSES)
    return m


def main():
    print("[*] Downloading corpora", flush=True)
    raw = {k: T.fetch(v) for k, v in T.SRC.items()}
    per_seed, boots = {}, {}
    for seed in T.SEEDS:
        T.SEED = seed
        rng = np.random.default_rng(seed)
        P = {k: T.split_pool(raw[k], rng) for k in T.SRC}
        (sq_tr, sq_te), (xs_tr, xs_te) = P["sqli"], P["xss"]
        (web_tr, web_te), (api_tr, api_te) = P["web"], P["api"]
        half = T.N_ATTACK // 2
        a = T.draw(web_tr, T.N_BENIGN, 0, rng) + T.draw(xs_tr, half, 1, rng) + T.draw(sq_tr, half, 1, rng)
        b = T.draw(api_tr, T.N_BENIGN, 0, rng) + T.draw(xs_tr, half, 1, rng) + T.draw(sq_tr, half, 1, rng)
        t_web = T.draw(web_te, T.N_TEST_BENIGN // 2, 0, rng)
        t_api = T.draw(api_te, T.N_TEST_BENIGN // 2, 0, rng)
        t_xss = T.draw(xs_te, T.N_TEST_ATTACK, 1, rng)
        t_sql = T.draw(sq_te, T.N_TEST_ATTACK, 1, rng)
        test = t_web + t_api + t_xss + t_sql
        n = [len(t_web), len(t_api), len(t_xss), len(t_sql)]
        y = np.array([l for _, l in test])
        m_xss = np.zeros(len(y), bool); m_xss[sum(n[:2]):sum(n[:3])] = True
        m_sql = np.zeros(len(y), bool); m_sql[sum(n[:3]):] = True
        texts = [p for p, _ in test]
        X_a, y_a = T.build(a)
        X_b, y_b = T.build(b)
        X_t, _ = T.build(test)
        X_p, y_p = np.vstack([X_a, X_b]), np.concatenate([y_a, y_b])

        scores = {}
        scores["pooled_linear"] = sgd_fit(X_p, y_p, seed).decision_function(X_t)
        scores["fedavg_sgd"] = fedavg_sgd(X_a, y_a, X_b, y_b, seed).decision_function(X_t)
        for mu in MUS:
            w, bb = fed_np([X_a, X_b], [y_a, y_b], mu, seed)
            scores["fedavg_np" if mu == 0 else f"fedprox_mu{mu}"] = X_t @ w + bb
        scores["isolated_A"] = sgd_fit(X_a, y_a, seed).decision_function(X_t)
        scores["isolated_B"] = sgd_fit(X_b, y_b, seed).decision_function(X_t)
        scores["regex"] = s_regex(texts)
        scores["charclass"] = s_charclass(texts)
        if HAVE_LIBINJ:
            scores["libinjection"] = s_libinj(texts)
        g = HistGradientBoostingClassifier(max_iter=200, random_state=seed).fit(X_p, y_p)
        scores["gbt"] = g.decision_function(X_t)
        mlp = MLPClassifier((64, 32), max_iter=300, random_state=seed).fit(X_p, y_p)
        scores["mlp"] = mlp.predict_proba(X_t)[:, 1]

        brng = np.random.default_rng(10_000 + seed)
        for nm, sc in scores.items():
            per_seed.setdefault(nm, {})[seed] = metrics(sc, y, m_xss, m_sql)
            boots.setdefault(nm, []).append(boot(sc, y, brng))
        print(f"[seed {seed}] " + " ".join(
            f"{k}={v[seed]['roc_auc']:.3f}" for k, v in per_seed.items()), flush=True)

    keys = ["roc_auc", "recall@fpr0.001", "recall@fpr0.01"]
    summary = {}
    for nm in per_seed:
        bm = np.mean(np.stack(boots[nm]), axis=0)  # B x 3, mean over seeds
        s = {}
        for j, k in enumerate(keys):
            v = [per_seed[nm][sd][k] for sd in T.SEEDS]
            s[k] = {"mean": float(np.mean(v)), "std_over_seeds": float(np.std(v)),
                    "ci95_bootstrap": [float(np.percentile(bm[:, j], 2.5)),
                                       float(np.percentile(bm[:, j], 97.5))]}
        for k in ("xss_recall@fpr0.001", "sqli_recall@fpr0.001",
                  "xss_recall@fpr0.01", "sqli_recall@fpr0.01",
                  "actual_fpr@0.001", "actual_fpr@0.01"):
            v = [per_seed[nm][sd][k] for sd in T.SEEDS]
            s[k] = {"mean": float(np.mean(v)), "std_over_seeds": float(np.std(v))}
        summary[nm] = s

    not_run = {"modsecurity_crs": "ModSecurity + OWASP CRS (paranoia 1-2) skipped: needs libmodsecurity "
                                  "plus a rule-set checkout and a WAF harness; not cheap in this environment."}
    if not HAVE_LIBINJ:
        not_run["libinjection"] = "libinjection-python not installable here."
    out = {"config": {"seeds": T.SEEDS, "rounds": T.ROUNDS, "local_epochs": T.LOCAL_EPOCHS,
                      "n_benign_train_per_node": T.N_BENIGN, "n_attack_train_per_node": T.N_ATTACK,
                      "n_test_benign": T.N_TEST_BENIGN, "n_test_attack_per_class": T.N_TEST_ATTACK,
                      "features": "fedzta_features.extract (poly 3-gram D=256 + 3 syntactic)",
                      "bootstrap_resamples": B_BOOT, "fedprox_mus": list(MUS),
                      "fed_numpy_solver": FEDNP, "not_run": not_run,
                      "fpr_note": "test benign n=%d so 0.1%% FPR is a threshold at the %d-th highest "
                                  "benign score (1-2 samples); recall@0.1%% is high-variance. Binary/tied "
                                  "detectors (regex, libinjection) can have actual FPR != nominal; see "
                                  "actual_fpr@*." % (T.N_TEST_BENIGN, int(0.001 * T.N_TEST_BENIGN) + 1)},
           "summary": summary, "per_seed": per_seed}
    with open("baselines_results.json", "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"\n{'model':<16}{'AUC':>8}{'R@0.1%':>9}{'R@1%':>9}{'  AUC 95% CI'}")
    for nm, s in summary.items():
        print(f"{nm:<16}{s['roc_auc']['mean']:>8.4f}{s['recall@fpr0.001']['mean']:>9.3f}"
              f"{s['recall@fpr0.01']['mean']:>9.3f}  [{s['roc_auc']['ci95_bootstrap'][0]:.4f},"
              f"{s['roc_auc']['ci95_bootstrap'][1]:.4f}]")


if __name__ == "__main__":
    sys.exit(main())
