"""
Federated Learning simulation for Zero-Trust Edge Gateways -- corrected build.

Fixes over fl_simulation_v2.py:
  * 3-feature vector, matching the paper and the deployed continuous_waf.py inferencer.
  * Disjoint train/test split performed on UNIQUE payloads before any resampling,
    so no test payload is ever seen during training.
  * XSS corpus widened from 17 unique strings to the full SecLists robot-friendly set.
  * Per-attack-class recall reported, not just aggregate F1.
  * Genuine iterative FedAvg: R communication rounds, each node restarting from the
    broadcast global model. v2 performed a single average of two independently
    trained models, which is one-shot model averaging, not FedAvg.
  * Learned parameters exported to fed_model.json so every downstream component
    (edge_profiler.py, continuous_waf.py, robust_cloud.py) shares one provenance.
"""
import json
import math
import urllib.request

import numpy as np
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import (average_precision_score, f1_score,
                             precision_score, recall_score, roc_auc_score)

SEED = 42
RAW = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"

SQLI_SOURCES = ["Fuzzing/Databases/SQLi/Generic-SQLi.txt"]
XSS_SOURCES = [
    "Fuzzing/XSS/robot-friendly/XSS-BruteLogic.txt",
    "Fuzzing/XSS/robot-friendly/XSS-Bypass-Strings-BruteLogic.txt",
    "Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt",
    "Fuzzing/XSS/robot-friendly/XSS-RSNAKE.txt",
    "Fuzzing/XSS/robot-friendly/XSS-Somdev.txt",
    "Fuzzing/XSS/robot-friendly/XSS-Vectors-Mario.txt",
    "Fuzzing/XSS/robot-friendly/XSS-EnDe-xssAttacks.txt",
    "Fuzzing/XSS/robot-friendly/xss-without-parentheses-semi-colons-portswigger.txt",
]
NORMAL_SOURCES = ["Discovery/Web-Content/raft-small-words.txt"]

# Fixed normalisation constants. Chosen a priori from the expected dynamic range of
# HTTP request lines, NOT fitted on the data, so no test-set statistics leak into
# training and the Edge inferencer can apply them without shipping a scaler.
NORM = [100.0, 20.0, 5.0]

TRAIN_FRAC = 0.7
N_TRAIN_NORMAL, N_TRAIN_ATTACK = 2000, 1000
N_TEST_NORMAL, N_TEST_ATTACK = 1000, 500
LOCAL_EPOCHS = 50      # E: local passes between synchronisations
ROUNDS = 20            # R: federated communication rounds


def fetch(paths):
    out = []
    for p in paths:
        try:
            with urllib.request.urlopen(RAW + p, timeout=60) as r:
                lines = [ln.decode("utf-8", "ignore").strip() for ln in r.readlines()]
            kept = [ln for ln in lines if ln]
            print(f"    {len(kept):>6} lines  {p}")
            out += kept
        except Exception as exc:
            print(f"    FAILED {p}: {exc}")
    return out


def split_pool(pool, rng, frac=TRAIN_FRAC):
    """Deduplicate, then split on unique payloads so train and test never overlap."""
    uniq = sorted(set(pool))
    idx = rng.permutation(len(uniq))
    cut = int(len(uniq) * frac)
    return [uniq[i] for i in idx[:cut]], [uniq[i] for i in idx[cut:]]


def make_traffic(pool, n, label, rng):
    """Benign and malicious requests share an IDENTICAL template.

    v2 emitted benign traffic as `GET /<word>?v=<int>` and attacks as
    `<METHOD> /search?q=<payload>`. Those templates differ systematically, so a
    classifier separates URL shape rather than maliciousness -- the label leaks
    through the request structure. Here only the value of q varies.
    """
    return [(f"GET /search?q={pool[i]}", label) for i in rng.integers(0, len(pool), n)]


def extract_features(payload):
    """3 features, identical to continuous_waf.py and edge_profiler.py."""
    length = len(payload)
    special = sum(1 for c in payload if not c.isalnum())
    if length > 0:
        prob = [float(payload.count(c)) / length for c in dict.fromkeys(payload)]
        entropy = -sum(p * math.log(p, 2) for p in prob)
    else:
        entropy = 0.0
    return [length / NORM[0], special / NORM[1], entropy / NORM[2]]


def build(traffic):
    X = np.array([extract_features(p) for p, _ in traffic])
    y = np.array([lbl for _, lbl in traffic])
    return X, y


CLASSES = np.array([0, 1])


def new_model(seed):
    return SGDClassifier(loss="log_loss", penalty="l2", alpha=1e-4,
                         learning_rate="constant", eta0=0.01, random_state=seed)


def local_train(model, X, y, rng, epochs):
    """E local epochs of SGD, shuffling each pass."""
    for _ in range(epochs):
        order = rng.permutation(len(y))
        model.partial_fit(X[order], y[order], classes=CLASSES)
    return model


def set_params(model, coef, intercept):
    model.classes_ = CLASSES.copy()
    model.coef_ = np.array(coef, dtype=float).reshape(1, -1)
    model.intercept_ = np.array(intercept, dtype=float).reshape(1)
    return model


def fedavg(models, weights):
    """Sample-count weighted average, i.e. sum_k (n_k / n_total) * w_k."""
    w = np.asarray(weights, dtype=float)
    w = w / w.sum()
    coef = sum(wi * m.coef_ for wi, m in zip(w, models))
    intercept = sum(wi * m.intercept_ for wi, m in zip(w, models))
    return coef, intercept


def recall_at_fpr(score, y, mask_cls, is_norm, target_fpr):
    """Recall on one attack class at a decision threshold pinned to target_fpr.

    Comparing detectors at their default threshold is meaningless when they sit at
    different operating points, so every model is re-thresholded to the same
    false-positive budget before its recall is read off.
    """
    benign = np.sort(score[is_norm])[::-1]
    k = int(np.floor(target_fpr * len(benign)))
    thr = benign[k] if k < len(benign) else benign[-1]
    return float((score[mask_cls] > thr).mean())


def evaluate(model, X, y, masks):
    pred = model.predict(X)
    is_xss, is_sqli, is_norm = masks
    score = model.decision_function(X)
    out_matched = {}
    for tgt in (0.001, 0.01):
        tag = f"{tgt:g}"
        out_matched[f"xss_recall@fpr{tag}"] = recall_at_fpr(score, y, is_xss, is_norm, tgt)
        out_matched[f"sqli_recall@fpr{tag}"] = recall_at_fpr(score, y, is_sqli, is_norm, tgt)
    return {
        "roc_auc": float(roc_auc_score(y, score)),
        "pr_auc": float(average_precision_score(y, score)),
        **out_matched,
        "f1": float(f1_score(y, pred)),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred)),
        "xss_recall": float(recall_score(y[is_xss], pred[is_xss], zero_division=0)),
        "sqli_recall": float(recall_score(y[is_sqli], pred[is_sqli], zero_division=0)),
        "fpr": float((pred[is_norm] == 1).mean()),
    }


def main():
    rng = np.random.default_rng(SEED)

    print("[*] Downloading SecLists corpora")
    print("  SQLi:")
    sqli_raw = fetch(SQLI_SOURCES)
    print("  XSS:")
    xss_raw = fetch(XSS_SOURCES)
    print("  Normal:")
    norm_raw = fetch(NORMAL_SOURCES)

    sqli_tr, sqli_te = split_pool(sqli_raw, rng)
    xss_tr, xss_te = split_pool(xss_raw, rng)
    norm_tr, norm_te = split_pool(norm_raw, rng)

    print("\n[*] Unique payloads after deduplication and disjoint split")
    print(f"    {'class':<8}{'total':>8}{'train':>8}{'test':>8}")
    for name, tr, te in (("SQLi", sqli_tr, sqli_te), ("XSS", xss_tr, xss_te),
                         ("Normal", norm_tr, norm_te)):
        print(f"    {name:<8}{len(tr)+len(te):>8}{len(tr):>8}{len(te):>8}")

    overlap = (set(sqli_tr) & set(sqli_te)) | (set(xss_tr) & set(xss_te)) | \
              (set(norm_tr) & set(norm_te))
    assert not overlap, f"train/test overlap: {len(overlap)} payloads"
    print("    [OK] zero train/test payload overlap")

    edge_a = make_traffic(norm_tr, N_TRAIN_NORMAL, 0, rng) + \
        make_traffic(xss_tr, N_TRAIN_ATTACK, 1, rng)
    edge_b = make_traffic(norm_tr, N_TRAIN_NORMAL, 0, rng) + \
        make_traffic(sqli_tr, N_TRAIN_ATTACK, 1, rng)
    test_norm = make_traffic(norm_te, N_TEST_NORMAL, 0, rng)
    test_xss = make_traffic(xss_te, N_TEST_ATTACK, 1, rng)
    test_sqli = make_traffic(sqli_te, N_TEST_ATTACK, 1, rng)
    test = test_norm + test_xss + test_sqli

    X_a, y_a = build(edge_a)
    X_b, y_b = build(edge_b)
    X_t, y_t = build(test)

    n_n, n_x, n_s = len(test_norm), len(test_xss), len(test_sqli)
    is_xss = np.array([False]*n_n + [True]*n_x + [False]*n_s)
    is_sqli = np.array([False]*n_n + [False]*n_x + [True]*n_s)
    is_norm = y_t == 0

    masks = (is_xss, is_sqli, is_norm)
    n_a, n_b = len(y_a), len(y_b)

    print(f"\n[*] Isolated baselines: {LOCAL_EPOCHS * ROUNDS} epochs, no communication")
    iso_a = local_train(new_model(SEED), X_a, y_a,
                        np.random.default_rng(SEED), LOCAL_EPOCHS * ROUNDS)
    iso_b = local_train(new_model(SEED), X_b, y_b,
                        np.random.default_rng(SEED), LOCAL_EPOCHS * ROUNDS)

    print(f"[*] Federated training: R={ROUNDS} rounds x E={LOCAL_EPOCHS} local epochs")
    rng_a, rng_b = np.random.default_rng(SEED), np.random.default_rng(SEED + 1)
    node_a, node_b = new_model(SEED), new_model(SEED)
    glob = new_model(SEED)
    history = []
    g_coef = g_int = None

    for rnd in range(1, ROUNDS + 1):
        if g_coef is not None:          # broadcast: every node restarts from the global model
            set_params(node_a, g_coef, g_int)
            set_params(node_b, g_coef, g_int)
        local_train(node_a, X_a, y_a, rng_a, LOCAL_EPOCHS)
        local_train(node_b, X_b, y_b, rng_b, LOCAL_EPOCHS)
        g_coef, g_int = fedavg([node_a, node_b], [n_a, n_b])
        set_params(glob, g_coef, g_int)
        m = evaluate(glob, X_t, y_t, masks)
        history.append({"round": rnd, **m})
        if rnd <= 3 or rnd % 5 == 0 or rnd == ROUNDS:
            print(f"    round {rnd:>2}  F1 {m['f1']:.3f}  XSS {m['xss_recall']:.3f}"
                  f"  SQLi {m['sqli_recall']:.3f}  FPR {m['fpr']:.3f}")

    rows = {
        "Edge A (XSS only)": evaluate(iso_a, X_t, y_t, masks),
        "Edge B (SQLi only)": evaluate(iso_b, X_t, y_t, masks),
        "Federated (FedAvg)": evaluate(glob, X_t, y_t, masks),
    }

    print("\n" + "=" * 78)
    print("EVALUATION -- disjoint test set, payloads never seen in training")
    print("=" * 78)
    print(f"{'model':<22}{'F1':>8}{'Prec':>8}{'Recall':>8}"
          f"{'XSS rec':>10}{'SQLi rec':>10}{'FPR':>8}")
    print("-" * 78)
    for name, r in rows.items():
        print(f"{name:<22}{r['f1']:>8.3f}{r['precision']:>8.3f}{r['recall']:>8.3f}"
              f"{r['xss_recall']:>10.3f}{r['sqli_recall']:>10.3f}{r['fpr']:>8.3f}")
    print("-" * 78)
    worst = {n: min(r["xss_recall"], r["sqli_recall"]) for n, r in rows.items()}
    for n, v in worst.items():
        print(f"    worst-class recall (default threshold)  {n:<22} {v:.3f}")

    print("\n" + "=" * 78)
    print("THRESHOLD-MATCHED COMPARISON -- every model pinned to the same FPR budget")
    print("=" * 78)
    print(f"{'model':<22}{'ROC-AUC':>9}{'PR-AUC':>9}"
          f"{'XSS@0.1%':>10}{'SQLi@0.1%':>11}{'XSS@1%':>9}{'SQLi@1%':>10}")
    print("-" * 78)
    for name, r in rows.items():
        print(f"{name:<22}{r['roc_auc']:>9.4f}{r['pr_auc']:>9.4f}"
              f"{r['xss_recall@fpr0.001']:>10.3f}{r['sqli_recall@fpr0.001']:>11.3f}"
              f"{r['xss_recall@fpr0.01']:>9.3f}{r['sqli_recall@fpr0.01']:>10.3f}")
    print("=" * 78)

    fed = glob
    coef = fed.coef_[0].tolist()
    model = {
        "features": ["length", "special_chars", "shannon_entropy"],
        "normalisation": NORM,
        "coefficients": coef,
        "intercept": float(fed.intercept_[0]),
        "seed": SEED,
        "local_epochs": LOCAL_EPOCHS,
        "rounds": ROUNDS,
        "unique_payloads": {
            "sqli": {"train": len(sqli_tr), "test": len(sqli_te)},
            "xss": {"train": len(xss_tr), "test": len(xss_te)},
            "normal": {"train": len(norm_tr), "test": len(norm_te)},
        },
        "samples": {
            "edge_a": {"normal": N_TRAIN_NORMAL, "xss": N_TRAIN_ATTACK, "sqli": 0},
            "edge_b": {"normal": N_TRAIN_NORMAL, "xss": 0, "sqli": N_TRAIN_ATTACK},
            "test": {"normal": N_TEST_NORMAL, "xss": N_TEST_ATTACK, "sqli": N_TEST_ATTACK},
        },
        "metrics": rows,
        "worst_class_recall": worst,
        "convergence": history,
    }
    with open("fed_model.json", "w") as fh:
        json.dump(model, fh, indent=2)
    print(f"\n[+] fed_model.json written")
    print(f"    coefficients {[round(c, 4) for c in coef]}")
    print(f"    intercept    {model['intercept']:.4f}")

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        names = list(rows)
        x = np.arange(len(names))
        w = 0.26
        fig, ax = plt.subplots(figsize=(8, 5))
        for off, key, lbl, col in ((-w, "xss_recall", "XSS recall", "#ff9999"),
                                   (0.0, "sqli_recall", "SQLi recall", "#66b3ff"),
                                   (w, "f1", "Overall F1", "#99ff99")):
            vals = [rows[n][key] for n in names]
            ax.bar(x + off, vals, w, label=lbl, color=col, edgecolor="black", linewidth=0.5)
            for xi, v in zip(x + off, vals):
                ax.text(xi, v + 0.02, f"{v:.2f}", ha="center", fontsize=8, fontweight="bold")
        ax.set_xticks(x)
        ax.set_xticklabels(names)
        ax.set_ylabel("Score (disjoint SecLists test set)", fontsize=12)
        ax.set_title("Per-Class Detection on Unseen Payloads", fontsize=14)
        ax.set_ylim(0, 1.15)
        ax.legend(loc="lower right")
        ax.grid(True, axis="y", linestyle="--", alpha=0.5)
        fig.tight_layout()
        fig.savefig("fl_metrics.pdf")
        print("[+] fl_metrics.pdf written")
    except Exception as exc:
        print(f"[!] plot skipped: {exc}")


if __name__ == "__main__":
    main()
