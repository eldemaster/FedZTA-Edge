"""
Federated Zero-Trust simulation -- feature set x non-IID axis matrix.

Evaluates two independent design choices against each other:

  FEATURES
    syntactic : the paper's 3 features (length, special-char count, Shannon entropy)
    ngram     : hashed character 3-grams (D buckets, L2-normalised) + the 3 syntactic

  NON-IID AXIS
    attack : nodes differ by threat campaign  (A sees only XSS, B sees only SQLi)
    domain : nodes differ by benign traffic profile (A = public web, B = API gateway),
             both seeing the full attack mix

All four cells use disjoint unique-payload train/test splits, an identical request
template for benign and malicious traffic, and genuine iterative FedAvg.
"""
import hashlib
import json
import math
import sys
import urllib.request

import numpy as np
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import average_precision_score, roc_auc_score

SEEDS, TRAIN_FRAC = [42, 43, 44, 45, 46, 47, 48, 49], 0.7
ROUNDS, LOCAL_EPOCHS = 20, 30
N_TRAIN_BENIGN, N_TRAIN_ATTACK = 3000, 1000
N_TEST_BENIGN, N_TEST_ATTACK = 1500, 500
NGRAM_N, NGRAM_D = 3, 64
NORM = [100.0, 20.0, 5.0]
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
        try:
            with urllib.request.urlopen(RAW + p, timeout=90) as r:
                out += [l.decode("utf-8", "ignore").strip() for l in r if l.strip()]
        except Exception as exc:
            print(f"    FAILED {p}: {exc}", file=sys.stderr)
    return out


def split_pool(pool, rng, frac=TRAIN_FRAC):
    uniq = sorted(set(pool))
    idx = rng.permutation(len(uniq))
    cut = int(len(uniq) * frac)
    return [uniq[i] for i in idx[:cut]], [uniq[i] for i in idx[cut:]]


def request(value):
    """One template for every request, benign or malicious."""
    return f"GET /search?q={value}"


def syntactic(p):
    n = len(p)
    special = sum(1 for c in p if not c.isalnum())
    if n:
        prob = [float(p.count(c)) / n for c in dict.fromkeys(p)]
        ent = -sum(q * math.log(q, 2) for q in prob)
    else:
        ent = 0.0
    return [n / NORM[0], special / NORM[1], ent / NORM[2]]


def ngram(p, d=NGRAM_D, n=NGRAM_N):
    """Hashed character n-grams. md5 keeps bucketing stable across processes and
    architectures, unlike Python's randomised str hash."""
    v = [0.0] * d
    s = p.lower()
    for i in range(len(s) - n + 1):
        v[int(hashlib.md5(s[i:i + n].encode()).hexdigest()[:8], 16) % d] += 1.0
    norm = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / norm for x in v]


FEATS = {"syntactic": syntactic, "ngram": lambda p: ngram(p) + syntactic(p)}


def build(traffic, feat):
    return (np.array([feat(p) for p, _ in traffic]),
            np.array([l for _, l in traffic]))


UAS = [
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
]

PROSE = [
    "The quick brown fox jumps over the lazy dog. This is a standard test string used to pad out length.",
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.",
    '{"name":"widget","qty":12,"desc":"standard equipment assembly","metadata":{"id":"1234567890","timestamp":"2023-10-27T10:00:00Z"}}'
]

def draw(pool, n, label, rng):
    samples = []
    for i in rng.integers(0, len(pool), n):
        payload = pool[i]
        choice = rng.integers(0, 7)
        if choice == 0:
            samples.append((payload, label))
        elif choice == 1:
            samples.append((f"{rng.choice(UAS)} {payload}", label))
        elif choice == 2:
            samples.append((f"_ga=GA1.2.{rng.integers(100000, 999999)}; _gid=GA1.2.{rng.integers(100000, 999999)}; session={payload}", label))
        elif choice == 3:
            samples.append((f"https://{rng.choice(['example.com', 'google.com', 'yahoo.com'])}/search?q={payload}", label))
        elif choice == 4:
            samples.append((f'{{"{rng.choice(["data","input","query"])}":"{payload}", "pad":{rng.choice(PROSE)}}}', label))
        elif choice == 5:
            samples.append((f"form_data={payload}&submit=true&csrf_token={rng.integers(1000000, 9999999)}", label))
        elif choice == 6:
            samples.append((f"{rng.choice(PROSE)} {payload}", label))
    return samples


def new_model():
    return SGDClassifier(loss="log_loss", penalty="l2", alpha=1e-4,
                         learning_rate="constant", eta0=0.01, random_state=SEED)


def local_train(m, X, y, rng, epochs):
    for _ in range(epochs):
        o = rng.permutation(len(y))
        m.partial_fit(X[o], y[o], classes=CLASSES)
    return m


def set_params(m, coef, inter):
    m.classes_, m.coef_, m.intercept_ = CLASSES.copy(), np.array(coef), np.array(inter)
    return m


def recall_at_fpr(score, mask_cls, is_norm, target):
    benign = np.sort(score[is_norm])[::-1]
    k = int(np.floor(target * len(benign)))
    thr = benign[k] if k < len(benign) else benign[-1]
    return float((score[mask_cls] > thr).mean())


def run_cell(features, axis, pools, rng):
    feat = FEATS[features]
    (sqli_tr, sqli_te), (xss_tr, xss_te) = pools["sqli"], pools["xss"]
    (web_tr, web_te), (api_tr, api_te) = pools["web"], pools["api"]

    if axis == "attack":
        # identical benign profile, disjoint threat campaigns
        a = draw(web_tr, N_TRAIN_BENIGN, 0, rng) + draw(xss_tr, N_TRAIN_ATTACK, 1, rng)
        b = draw(web_tr, N_TRAIN_BENIGN, 0, rng) + draw(sqli_tr, N_TRAIN_ATTACK, 1, rng)
    else:
        # disjoint benign profiles, identical threat mix
        half = N_TRAIN_ATTACK // 2
        a = draw(web_tr, N_TRAIN_BENIGN, 0, rng) + \
            draw(xss_tr, half, 1, rng) + draw(sqli_tr, half, 1, rng)
        b = draw(api_tr, N_TRAIN_BENIGN, 0, rng) + \
            draw(xss_tr, half, 1, rng) + draw(sqli_tr, half, 1, rng)

    t_web = draw(web_te, N_TEST_BENIGN // 2, 0, rng)
    t_api = draw(api_te, N_TEST_BENIGN // 2, 0, rng)
    t_xss = draw(xss_te, N_TEST_ATTACK, 1, rng)
    t_sqli = draw(sqli_te, N_TEST_ATTACK, 1, rng)
    test = t_web + t_api + t_xss + t_sqli
    sizes = [len(t_web), len(t_api), len(t_xss), len(t_sqli)]

    def mask(i):
        m = np.zeros(sum(sizes), bool)
        s = sum(sizes[:i])
        m[s:s + sizes[i]] = True
        return m

    m_web, m_api, m_xss, m_sqli = (mask(i) for i in range(4))
    m_norm = m_web | m_api

    X_a, y_a = build(a, feat)
    X_b, y_b = build(b, feat)
    X_t, y_t = build(test, feat)

    iso = {}
    for name, (X, y) in (("A", (X_a, y_a)), ("B", (X_b, y_b))):
        iso[name] = local_train(new_model(), X, y,
                                np.random.default_rng(SEED), ROUNDS * LOCAL_EPOCHS)

    node_a, node_b, glob = new_model(), new_model(), new_model()
    rng_a, rng_b = np.random.default_rng(SEED), np.random.default_rng(SEED + 1)
    g = None
    for _ in range(ROUNDS):
        if g:
            set_params(node_a, *g)
            set_params(node_b, *g)
        local_train(node_a, X_a, y_a, rng_a, LOCAL_EPOCHS)
        local_train(node_b, X_b, y_b, rng_b, LOCAL_EPOCHS)
        n_a, n_b = len(y_a), len(y_b)
        tot = n_a + n_b
        g = ((n_a * node_a.coef_ + n_b * node_b.coef_) / tot,
             (n_a * node_a.intercept_ + n_b * node_b.intercept_) / tot)
    set_params(glob, *g)

    out = {}
    for name, m in (("Edge A", iso["A"]), ("Edge B", iso["B"]), ("Federated", glob)):
        sc = m.decision_function(X_t)
        out[name] = {
            "roc_auc": float(roc_auc_score(y_t, sc)),
            "pr_auc": float(average_precision_score(y_t, sc)),
            "xss@0.1": recall_at_fpr(sc, m_xss, m_norm, 0.001),
            "sqli@0.1": recall_at_fpr(sc, m_sqli, m_norm, 0.001),
            "fpr_web": float((sc[m_web] > 0).mean()),
            "fpr_api": float((sc[m_api] > 0).mean()),
        }
    out["_dim"] = X_t.shape[1]
    return out


def main():
    print("[*] Downloading corpora")
    raw_pools = {}
    for k, paths in SRC.items():
        raw_pools[k] = fetch(paths)
        print(f"    {k:<6} {len(set(raw_pools[k])):>7} unique")

    results = {}
    for features in ("syntactic", "ngram"):
        for axis in ("attack", "domain"):
            key = f"{features}/{axis}"
            print(f"\n[*] {key}")
            results[key] = {"Edge A": {}, "Edge B": {}, "Federated": {}}
            for seed in SEEDS:
                rng = np.random.default_rng(seed)
                pools = {}
                for k, raw in raw_pools.items():
                    tr, te = split_pool(raw, rng)
                    pools[k] = (tr, te)
                
                # We need to pass seed to new_model... wait, new_model uses SEED global.
                # Let's fix new_model locally.
                global SEED
                SEED = seed
                
                res = run_cell(features, axis, pools, np.random.default_rng(seed))
                
                for name in ("Edge A", "Edge B", "Federated"):
                    for metric, val in res[name].items():
                        if metric not in results[key][name]:
                            results[key][name][metric] = []
                        results[key][name][metric].append(val)
                results[key]["_dim"] = res["_dim"]
            
            # Compute mean and std
            for name in ("Edge A", "Edge B", "Federated"):
                for metric in results[key][name]:
                    vals = results[key][name][metric]
                    results[key][name][metric] = {"mean": float(np.mean(vals)), "std": float(np.std(vals))}

    print("\n" + "=" * 92)
    print("FEATURE SET x NON-IID AXIS      (recall at a 0.1% false-positive budget)")
    print("=" * 92)
    print(f"{'cell':<20}{'dim':>5}{'model':<12}{'ROC-AUC':>9}"
          f"{'XSS':>8}{'SQLi':>8}{'FPR web':>10}{'FPR api':>10}")
    print("-" * 92)
    for key, cell in results.items():
        for name in ("Edge A", "Edge B", "Federated"):
            r = cell[name]
            lead = key if name == "Edge A" else ""
            dim = str(cell["_dim"]) if name == "Edge A" else ""
            print(f"{lead:<20}{dim:>5}{name:<12}{r['roc_auc']['mean']:>6.4f}±{r['roc_auc']['std']:<6.4f}"
                  f"{r['xss@0.1']['mean']:>6.3f}±{r['xss@0.1']['std']:<5.3f}"
                  f"{r['sqli@0.1']['mean']:>6.3f}±{r['sqli@0.1']['std']:<5.3f}"
                  f"{r['fpr_web']['mean']:>8.4f}"
                  f"{r['fpr_api']['mean']:>10.4f}")
        print("-" * 92)

    print("\nFEDERATION GAIN over the WEAKER silo, worst attack class, at 0.1% FPR")
    for key, cell in results.items():
        worst_iso = min(min(cell[n]["xss@0.1"]["mean"], cell[n]["sqli@0.1"]["mean"]) for n in ("Edge A", "Edge B"))
        best_iso = max(min(cell[n]["xss@0.1"]["mean"], cell[n]["sqli@0.1"]["mean"]) for n in ("Edge A", "Edge B"))
        fed = min(cell["Federated"]["xss@0.1"]["mean"], cell["Federated"]["sqli@0.1"]["mean"])
        print(f"    {key:<20} weaker silo {worst_iso:.3f} | stronger silo {best_iso:.3f} "
              f"| federated {fed:.3f}   (vs weaker {fed - worst_iso:+.3f}, vs stronger {fed - best_iso:+.3f})")

    with open("matrix_results.json", "w") as fh:
        json.dump(results, fh, indent=2)
    print("\n[+] matrix_results.json written")


if __name__ == "__main__":
    main()
