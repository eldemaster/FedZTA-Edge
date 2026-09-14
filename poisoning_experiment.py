"""Byzantine poisoning experiment -- measured, not illustrated.

Replaces poisoning_sim.py, which plotted three hardcoded arrays with no model,
no data and no aggregation behind them.

Setup: K nodes, each a real SGD classifier trained on its own SecLists shard with
the deployed n-gram feature transform. From ROUND_ATTACK onward, f of them turn
Byzantine and upload scaled sign-flipped weights. Every round the server
aggregates the SAME uploads three ways -- arithmetic mean, coordinate-wise median
and trimmed mean -- and each resulting global model is scored on a held-out test
set whose payloads appear in no node's training data.

Coordinate-wise median tolerates f Byzantine nodes only when K >= 2f+1, so K is
set well above the two-node cluster of the physical testbed.
"""
import json
import urllib.request

import numpy as np
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import roc_auc_score

import fedzta_features as F

SEED = 42
K_NODES = 7
F_BYZANTINE = 2          # K >= 2f+1  ->  7 >= 5, satisfied
ROUNDS = 12
ROUND_ATTACK = 4
LOCAL_EPOCHS = 20
BOOST = 12.0             # scaling applied by the attacker
N_BENIGN, N_ATTACK = 1200, 400
N_TEST_BENIGN, N_TEST_ATTACK = 1500, 500
CLASSES = np.array([0, 1])

RAW = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
SRC = {
    "sqli": ["Fuzzing/Databases/SQLi/Generic-SQLi.txt"],
    "xss": ["Fuzzing/XSS/robot-friendly/XSS-BruteLogic.txt",
            "Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt",
            "Fuzzing/XSS/robot-friendly/XSS-RSNAKE.txt",
            "Fuzzing/XSS/robot-friendly/XSS-Somdev.txt",
            "Fuzzing/XSS/robot-friendly/XSS-Vectors-Mario.txt",
            "Fuzzing/XSS/robot-friendly/XSS-EnDe-xssAttacks.txt"],
    "web": ["Discovery/Web-Content/raft-small-words.txt"],
    "api": ["Discovery/Web-Content/api/api-seen-in-wild.txt",
            "Discovery/Web-Content/api/api-endpoints.txt",
            "Discovery/Web-Content/graphql.txt"],
}


def fetch(paths):
    out = []
    for p in paths:
        with urllib.request.urlopen(RAW + p, timeout=90) as r:
            out += [l.decode("utf-8", "ignore").strip() for l in r if l.strip()]
    return out


def split_pool(pool, rng, frac=0.7):
    uniq = sorted(set(pool))
    idx = rng.permutation(len(uniq))
    cut = int(len(uniq) * frac)
    return [uniq[i] for i in idx[:cut]], [uniq[i] for i in idx[cut:]]


def draw(pool, n, label, rng):
    return [(f"GET /search?q={pool[i]}", label) for i in rng.integers(0, len(pool), n)]


def build(traffic):
    return (np.array([F.extract(p) for p, _ in traffic]),
            np.array([l for _, l in traffic]))


def new_model():
    return SGDClassifier(loss="log_loss", penalty="l2", alpha=1e-4,
                         learning_rate="constant", eta0=0.01, random_state=SEED)


def set_params(m, coef, inter):
    m.classes_ = CLASSES.copy()
    m.coef_ = np.array(coef, dtype=float).reshape(1, -1)
    m.intercept_ = np.array(inter, dtype=float).reshape(1)
    return m


def trimmed_mean(stack, f):
    """Discard the f highest and f lowest values per coordinate, then average."""
    s = np.sort(stack, axis=0)
    return s[f:len(s) - f].mean(axis=0) if len(s) > 2 * f else s.mean(axis=0)


def main():
    rng = np.random.default_rng(SEED)
    print("[*] Downloading corpora")
    pools = {k: split_pool(fetch(v), rng) for k, v in SRC.items()}
    for k, (tr, te) in pools.items():
        print(f"    {k:<5} {len(tr)} train / {len(te)} test unique payloads")

    (sqli_tr, sqli_te), (xss_tr, xss_te) = pools["sqli"], pools["xss"]
    (web_tr, web_te), (api_tr, api_te) = pools["web"], pools["api"]

    # Domain-split benign traffic: nodes alternate between a public web profile and
    # an API gateway profile, matching the deployed non-IID configuration.
    print(f"\n[*] Building {K_NODES} nodes ({F_BYZANTINE} will turn Byzantine)")
    nodes = []
    for k in range(K_NODES):
        benign = web_tr if k % 2 == 0 else api_tr
        traffic = draw(benign, N_BENIGN, 0, rng) + \
            draw(xss_tr, N_ATTACK // 2, 1, rng) + draw(sqli_tr, N_ATTACK // 2, 1, rng)
        X, y = build(traffic)
        nodes.append({"id": k, "X": X, "y": y, "n": len(y),
                      "byz": k >= K_NODES - F_BYZANTINE,
                      "model": new_model(),
                      "rng": np.random.default_rng(SEED + k)})
        print(f"    node {k}  {'BYZANTINE' if nodes[-1]['byz'] else 'honest   '}  "
              f"benign={'web' if k % 2 == 0 else 'api'}  samples={len(y)}")

    test = draw(web_te, N_TEST_BENIGN // 2, 0, rng) + draw(api_te, N_TEST_BENIGN // 2, 0, rng) + \
        draw(xss_te, N_TEST_ATTACK, 1, rng) + draw(sqli_te, N_TEST_ATTACK, 1, rng)
    X_t, y_t = build(test)
    print(f"    test  {len(y_t)} samples, payloads disjoint from every node")

    schemes = ["mean", "median", "trimmed"]
    globals_ = {s: None for s in schemes}
    history = {s: [] for s in schemes}
    probe = new_model()

    print(f"\n[*] {ROUNDS} rounds, attack begins at round {ROUND_ATTACK}, boost x{BOOST}")
    print(f"    {'round':>6}{'mean':>10}{'median':>10}{'trimmed':>10}   note")
    for rnd in range(1, ROUNDS + 1):
        uploads = {s: [] for s in schemes}
        for nd in nodes:
            for s in schemes:
                m = nd["model"] if s == "median" else new_model()
                if globals_[s] is not None:
                    set_params(m, *globals_[s])
                elif s != "median":
                    set_params(m, np.zeros(F.DIM), np.zeros(1))
                r = np.random.default_rng(SEED + nd["id"] + 1000 * rnd)
                for _ in range(LOCAL_EPOCHS):
                    o = r.permutation(nd["n"])
                    m.partial_fit(nd["X"][o], nd["y"][o], classes=CLASSES)
                coef, inter = m.coef_[0].copy(), m.intercept_.copy()
                if nd["byz"] and rnd >= ROUND_ATTACK:
                    # sign-flip and amplify: drives the boundary to label everything benign
                    coef, inter = -BOOST * coef, -BOOST * inter
                uploads[s].append((coef, inter, nd["n"]))

        row = {}
        for s in schemes:
            C = np.stack([u[0] for u in uploads[s]])
            I = np.stack([u[1] for u in uploads[s]])
            w = np.array([u[2] for u in uploads[s]], dtype=float)
            w = w / w.sum()
            if s == "mean":
                gc, gi = (C * w[:, None]).sum(0), (I * w[:, None]).sum(0)
            elif s == "median":
                gc, gi = np.median(C, axis=0), np.median(I, axis=0)
            else:
                gc, gi = trimmed_mean(C, F_BYZANTINE), trimmed_mean(I, F_BYZANTINE)
            globals_[s] = (gc, gi)
            set_params(probe, gc, gi)
            auc = float(roc_auc_score(y_t, probe.decision_function(X_t)))
            history[s].append({"round": rnd, "roc_auc": auc})
            row[s] = auc

        note = "<-- poisoning starts" if rnd == ROUND_ATTACK else ""
        print(f"    {rnd:>6}{row['mean']:>10.4f}{row['median']:>10.4f}"
              f"{row['trimmed']:>10.4f}   {note}")

    final = {s: history[s][-1]["roc_auc"] for s in schemes}
    print(f"\n    final  mean {final['mean']:.4f} | median {final['median']:.4f} | "
          f"trimmed {final['trimmed']:.4f}")
    print(f"    median advantage over mean: {final['median'] - final['mean']:+.4f} ROC-AUC")

    cfg = {"k_nodes": K_NODES, "f_byzantine": F_BYZANTINE, "rounds": ROUNDS,
           "round_attack": ROUND_ATTACK, "boost": BOOST, "local_epochs": LOCAL_EPOCHS,
           "dim": F.DIM, "seed": SEED, "final": final, "history": history}
    with open("poisoning_results.json", "w") as fh:
        json.dump(cfg, fh, indent=2)
    print("[+] poisoning_results.json written")

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        rounds = [h["round"] for h in history["mean"]]
        fig, ax = plt.subplots(figsize=(8, 5))
        for s, style, col, lbl in (
                ("mean", "s--", "#d62728", "Arithmetic mean (FedAvg)"),
                ("median", "o-", "#1f77b4", "Coordinate-wise median"),
                ("trimmed", "^-", "#2ca02c", f"Trimmed mean (beta={F_BYZANTINE})")):
            ax.plot(rounds, [h["roc_auc"] for h in history[s]], style, color=col, label=lbl)
        ax.axvline(ROUND_ATTACK, color="gray", ls=":",
                   label=f"{F_BYZANTINE} of {K_NODES} nodes turn Byzantine")
        ax.set_xlabel("Federated communication round", fontsize=12)
        ax.set_ylabel("Global model ROC-AUC (held-out test set)", fontsize=12)
        ax.set_title(f"Byzantine resilience, K={K_NODES} nodes, f={F_BYZANTINE}", fontsize=13)
        ax.legend(loc="lower left", fontsize=9)
        ax.grid(True, ls="--", alpha=0.5)
        fig.tight_layout()
        fig.savefig("poisoning_defense.pdf")
        print("[+] poisoning_defense.pdf written (measured, replaces the hardcoded plot)")
    except Exception as exc:
        print(f"[!] plot skipped: {exc}")


if __name__ == "__main__":
    main()
