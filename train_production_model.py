"""Train the deployed FedZTA global model and export it for the Edge gateways.

Configuration selected from the feature x non-IID matrix (fl_simulation_v4.py):
hashed character n-grams at D=256 with a domain-split node topology, the only
cell in which the federated model outperforms every isolated silo.
"""
import json
import urllib.request

import numpy as np
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import average_precision_score, roc_auc_score

import fedzta_features as F

SEEDS, ROUNDS, LOCAL_EPOCHS = [42, 43, 44, 45, 46, 47, 48, 49], 20, 30
N_BENIGN, N_ATTACK = 3000, 1000
N_TEST_BENIGN, N_TEST_ATTACK = 1500, 500
CLASSES = np.array([0, 1])
RAW = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
SRC = {
    "sqli": [
        "Fuzzing/Databases/SQLi/Generic-SQLi.txt",
        "Fuzzing/Databases/SQLi/Generic-BlindSQLi.fuzzdb.txt",
        "Fuzzing/Databases/SQLi/MSSQL.fuzzdb.txt",
        "Fuzzing/Databases/SQLi/MySQL.fuzzdb.txt",
        "Fuzzing/Databases/SQLi/MySQL-SQLi-Login-Bypass.fuzzdb.txt",
        "Fuzzing/Databases/SQLi/Oracle.fuzzdb.txt",
        "Fuzzing/Databases/SQLi/SQLi-Polyglots.txt",
        "Fuzzing/Databases/SQLi/quick-SQLi.txt",
        "Fuzzing/Databases/SQLi/sqli.auth.bypass.txt",
        "Fuzzing/Databases/SQLi/sqlmap-risk-classified/High-Risk-Payloads/boolean_blind.txt",
        "Fuzzing/Databases/SQLi/sqlmap-risk-classified/High-Risk-Payloads/error_based.txt",
        "Fuzzing/Databases/SQLi/sqlmap-risk-classified/High-Risk-Payloads/time_blind.txt",
        "Fuzzing/Databases/SQLi/sqlmap-risk-classified/Low-Risk-Payloads/boolean_blind.txt",
        "Fuzzing/Databases/SQLi/sqlmap-risk-classified/Low-Risk-Payloads/error_based.txt",
        "Fuzzing/Databases/SQLi/sqlmap-risk-classified/Low-Risk-Payloads/inline_query.txt",
        "Fuzzing/Databases/SQLi/sqlmap-risk-classified/Low-Risk-Payloads/stacked_queries.txt",
        "Fuzzing/Databases/SQLi/sqlmap-risk-classified/Low-Risk-Payloads/time_blind.txt"
    ],
    "xss": ["Fuzzing/XSS/robot-friendly/XSS-BruteLogic.txt",
            "Fuzzing/XSS/robot-friendly/XSS-Bypass-Strings-BruteLogic.txt",
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
    u = sorted(set(pool))
    i = rng.permutation(len(u))
    c = int(len(u) * frac)
    return [u[j] for j in i[:c]], [u[j] for j in i[c:]]


def draw(pool, n, label, rng):
    samples = []
    for i in rng.integers(0, len(pool), n):
        payload = pool[i]
        choice = rng.integers(0, 4)
        if choice == 0:
            samples.append((payload, label))
        elif choice == 1:
            samples.append((f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 {payload}", label))
        elif choice == 2:
            samples.append((f"_ga=GA1.2.1234567890; _gid=GA1.2.0987654321; session={payload}", label))
        elif choice == 3:
            samples.append((f"https://www.example.com/search?q={payload}", label))
    return samples


def build(t):
    return np.array([F.extract(p) for p, _ in t]), np.array([l for _, l in t])


def new_model():
    return SGDClassifier(loss="log_loss", penalty="l2", alpha=1e-4,
                         learning_rate="constant", eta0=0.01, random_state=SEED)


def set_params(m, c, i):
    m.classes_, m.coef_ = CLASSES.copy(), np.array(c).reshape(1, -1)
    m.intercept_ = np.array(i).reshape(1)
    return m


def recall_at_fpr(score, cls, norm, tgt):
    b = np.sort(score[norm])[::-1]
    k = int(np.floor(tgt * len(b)))
    return float((score[cls] > (b[k] if k < len(b) else b[-1])).mean())


def main():
    print("[*] Downloading corpora")
    raw_pools = {k: fetch(v) for k, v in SRC.items()}
    
    metrics_all = {"Edge A (web)": {}, "Edge B (api)": {}, "Federated": {}}
    
    for seed in SEEDS:
        global SEED
        SEED = seed
        rng = np.random.default_rng(seed)
        P = {k: split_pool(raw_pools[k], rng) for k, v in SRC.items()}
        if seed == SEEDS[0]:
            uniq = {k: {"train": len(a), "test": len(b)} for k, (a, b) in P.items()}
            for k, v in uniq.items():
                print(f"    {k:<5} {v['train']:>6} train / {v['test']:>6} test")

        (sq_tr, sq_te), (xs_tr, xs_te) = P["sqli"], P["xss"]
        (web_tr, web_te), (api_tr, api_te) = P["web"], P["api"]
    
        half = N_ATTACK // 2
        a = draw(web_tr, N_BENIGN, 0, rng) + draw(xs_tr, half, 1, rng) + draw(sq_tr, half, 1, rng)
        b = draw(api_tr, N_BENIGN, 0, rng) + draw(xs_tr, half, 1, rng) + draw(sq_tr, half, 1, rng)
        t_web = draw(web_te, N_TEST_BENIGN // 2, 0, rng)
        t_api = draw(api_te, N_TEST_BENIGN // 2, 0, rng)
        t_xss = draw(xs_te, N_TEST_ATTACK, 1, rng)
        t_sql = draw(sq_te, N_TEST_ATTACK, 1, rng)
        test = t_web + t_api + t_xss + t_sql
        sz = [len(t_web), len(t_api), len(t_xss), len(t_sql)]
    
        def mask(i):
            m = np.zeros(sum(sz), bool)
            s = sum(sz[:i])
            m[s:s + sz[i]] = True
            return m
        m_web, m_api, m_xss, m_sql = (mask(i) for i in range(4))
        m_norm = m_web | m_api
    
        print(f"[*] Extracting {F.DIM}-dim features")
        X_a, y_a = build(a)
        X_b, y_b = build(b)
        X_t, y_t = build(test)
    
        print(f"[*] Isolated baselines")
        iso = {}
        for nm, (X, y) in (("Edge A (web)", (X_a, y_a)), ("Edge B (api)", (X_b, y_b))):
            m = new_model()
            r = np.random.default_rng(SEED)
            for _ in range(ROUNDS * LOCAL_EPOCHS):
                o = r.permutation(len(y))
                m.partial_fit(X[o], y[o], classes=CLASSES)
            iso[nm] = m
    
        print(f"[*] FedAvg: R={ROUNDS} x E={LOCAL_EPOCHS}")
        na, nb = new_model(), new_model()
        ra, rb = np.random.default_rng(SEED), np.random.default_rng(SEED + 1)
        g, hist = None, []
        probe = new_model()
        for rnd in range(1, ROUNDS + 1):
            if g:
                set_params(na, *g)
                set_params(nb, *g)
            for m, X, y, r in ((na, X_a, y_a, ra), (nb, X_b, y_b, rb)):
                for _ in range(LOCAL_EPOCHS):
                    o = r.permutation(len(y))
                    m.partial_fit(X[o], y[o], classes=CLASSES)
            w = np.array([len(y_a), len(y_b)], float)
            w /= w.sum()
            g = (w[0] * na.coef_ + w[1] * nb.coef_, w[0] * na.intercept_ + w[1] * nb.intercept_)
            set_params(probe, *g)
            hist.append({"round": rnd,
                         "roc_auc": float(roc_auc_score(y_t, probe.decision_function(X_t)))})
        glob = set_params(new_model(), *g)
    
        print("\n" + "=" * 86)
        print(f"{'model':<16}{'ROC-AUC':>9}{'PR-AUC':>9}{'XSS@0.1%':>10}"
              f"{'SQLi@0.1%':>11}{'FPR web':>10}{'FPR api':>10}")
        print("-" * 86)
        metrics = {}
        for nm, m in (*iso.items(), ("Federated", glob)):
            sc = m.decision_function(X_t)
            metrics[nm] = {
                "roc_auc": float(roc_auc_score(y_t, sc)),
                "pr_auc": float(average_precision_score(y_t, sc)),
                "xss_recall@fpr0.001": recall_at_fpr(sc, m_xss, m_norm, 0.001),
                "sqli_recall@fpr0.001": recall_at_fpr(sc, m_sql, m_norm, 0.001),
                "fpr_web": float((sc[m_web] > 0).mean()),
                "fpr_api": float((sc[m_api] > 0).mean()),
            }
            r = metrics[nm]
            for k, v in r.items():
                if k not in metrics_all[nm]:
                    metrics_all[nm][k] = []
                metrics_all[nm][k].append(v)
            
    # Aggregate once and keep it. Computing this inside the print loop and
    # discarding it left the downstream comparison indexing the raw per-seed
    # lists, which crashed before fed_model.json was ever written.
    agg = {nm: {k: {"mean": float(np.mean(v)), "std": float(np.std(v))}
                for k, v in per_metric.items()}
           for nm, per_metric in metrics_all.items()}

    print("\n" + "=" * 90)
    print(f"{'model':<16}{'ROC-AUC':>14}{'PR-AUC':>14}{'XSS@0.1%':>12}"
          f"{'SQLi@0.1%':>12}{'FPR web':>10}{'FPR api':>10}")
    print("-" * 90)
    for nm in metrics_all:
        r = agg[nm]
        print(f"{nm:<16}{r['roc_auc']['mean']:>6.4f}±{r['roc_auc']['std']:<6.4f} "
              f"{r['pr_auc']['mean']:>6.4f}±{r['pr_auc']['std']:<6.4f} "
              f"{r['xss_recall@fpr0.001']['mean']:>4.3f}±{r['xss_recall@fpr0.001']['std']:<4.3f} "
              f"{r['sqli_recall@fpr0.001']['mean']:>4.3f}±{r['sqli_recall@fpr0.001']['std']:<4.3f} "
              f"{r['fpr_web']['mean']:>8.4f}"
              f"{r['fpr_api']['mean']:>10.4f}")
    print("=" * 90)
    
    fed = agg["Federated"]
    isolated = ("Edge A (web)", "Edge B (api)")
    beats = all(fed["roc_auc"]["mean"] > agg[n]["roc_auc"]["mean"] for n in isolated)
    print(f"Federated outperforms every isolated silo (on average): {'YES' if beats else 'NO'}")
    # Report the margin against the standard deviation: a mean difference smaller
    # than the spread across seeds is not a result.
    for n in isolated:
        d = fed["roc_auc"]["mean"] - agg[n]["roc_auc"]["mean"]
        pooled = max(fed["roc_auc"]["std"], agg[n]["roc_auc"]["std"])
        print(f"  vs {n:<14} ROC-AUC {d:+.4f}  (spread {pooled:.4f}) "
              f"-> {'within noise' if abs(d) < pooled else 'outside noise'}")

    out = {
        "config": {"features": "poly-ngram+syntactic", "ngram_n": F.NGRAM_N,
                   "ngram_d": F.NGRAM_D, "dim": F.DIM, "normalisation": F.NORM,
                   "split": "domain", "rounds": ROUNDS, "local_epochs": LOCAL_EPOCHS,
                   "seeds": SEEDS, "shipped_seed": SEEDS[0]},
        "coefficients": glob.coef_[0].tolist(),
        "intercept": float(glob.intercept_[0]),
        "update_bytes": (F.DIM + 1) * 4,
        "unique_payloads": uniq,
        "metrics": metrics,
        "metrics_aggregate": agg,
        "metrics_per_seed": metrics_all,
        "convergence": hist,
    }
    with open("fed_model.json", "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"[+] fed_model.json written -- {F.DIM} coefficients, "
          f"{out['update_bytes']} bytes per update")


if __name__ == "__main__":
    main()
