"""Why does a model trained on one attack class already detect the other?

Compares the 3 syntactic features against a richer lexical set, measuring the
cross-class generalisation gap that the federated narrative depends on.
"""
import math, urllib.request
import numpy as np
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import roc_auc_score

RAW = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
XSS_SRC = ["Fuzzing/XSS/robot-friendly/XSS-BruteLogic.txt",
           "Fuzzing/XSS/robot-friendly/XSS-Bypass-Strings-BruteLogic.txt",
           "Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt",
           "Fuzzing/XSS/robot-friendly/XSS-RSNAKE.txt",
           "Fuzzing/XSS/robot-friendly/XSS-Somdev.txt",
           "Fuzzing/XSS/robot-friendly/XSS-Vectors-Mario.txt",
           "Fuzzing/XSS/robot-friendly/XSS-EnDe-xssAttacks.txt"]

def get(paths):
    out = []
    for p in paths:
        with urllib.request.urlopen(RAW + p, timeout=60) as r:
            out += [l.decode("utf-8", "ignore").strip() for l in r if l.strip()]
    return sorted(set(out))

def entropy(s):
    if not s: return 0.0
    return -sum((s.count(c)/len(s)) * math.log2(s.count(c)/len(s)) for c in dict.fromkeys(s))

SQL_KW = ["select", "union", "insert", "drop", "or ", "and ", "--", "/*", "sleep", "benchmark", "=", "'"]
XSS_KW = ["<", ">", "script", "onerror", "onload", "javascript:", "alert", "img", "svg", "iframe", '"']

def f3(p):
    return [len(p)/100.0, sum(1 for c in p if not c.isalnum())/20.0, entropy(p)/5.0]

def f_rich(p):
    lo = p.lower()
    return f3(p) + [lo.count(k)/3.0 for k in SQL_KW] + [lo.count(k)/3.0 for k in XSS_KW]

def run(feat, name, sqli, xss, norm, rng):
    def split(pool):
        i = rng.permutation(len(pool)); c = int(len(pool)*0.7)
        return [pool[j] for j in i[:c]], [pool[j] for j in i[c:]]
    s_tr, s_te = split(sqli); x_tr, x_te = split(xss); n_tr, n_te = split(norm)
    # IDENTICAL template for benign and malicious traffic: only the value of q
    # differs, so the classifier cannot separate on URL shape.
    def mk(pool, n, lbl):
        return [(f"GET /search?q={pool[i]}", lbl) for i in rng.integers(0, len(pool), n)]
    A = mk(n_tr, 2000, 0) + mk(x_tr, 1000, 1)
    B = mk(n_tr, 2000, 0) + mk(s_tr, 1000, 1)
    T_x = mk(x_te, 500, 1); T_s = mk(s_te, 500, 1); T_n = mk(n_te, 1000, 0)
    T = T_n + T_x + T_s
    def build(d): return np.array([feat(p) for p,_ in d]), np.array([l for _,l in d])
    XA,yA = build(A); XB,yB = build(B); XT,yT = build(T)
    mx = np.array([False]*len(T_n) + [True]*len(T_x) + [False]*len(T_s))
    ms = np.array([False]*len(T_n) + [False]*len(T_x) + [True]*len(T_s))
    res = {}
    for lbl,(X,y) in (("A(XSS-only)",(XA,yA)), ("B(SQLi-only)",(XB,yB))):
        m = SGDClassifier(loss="log_loss", alpha=1e-4, learning_rate="constant", eta0=0.01, random_state=42)
        r2 = np.random.default_rng(42)
        for _ in range(200):
            o = r2.permutation(len(y)); m.partial_fit(X[o], y[o], classes=np.array([0,1]))
        sc = m.decision_function(XT)
        seen_auc = roc_auc_score(yT[mx|(yT==0)], sc[mx|(yT==0)]) if "XSS" in lbl else roc_auc_score(yT[ms|(yT==0)], sc[ms|(yT==0)])
        unseen_auc = roc_auc_score(yT[ms|(yT==0)], sc[ms|(yT==0)]) if "XSS" in lbl else roc_auc_score(yT[mx|(yT==0)], sc[mx|(yT==0)])
        res[lbl] = (seen_auc, unseen_auc)
    print(f"\n{name} ({len(feat('GET /x'))} features)")
    print(f"  {'node':<14}{'AUC seen class':>16}{'AUC unseen class':>18}{'gap':>8}")
    for k,(s_,u) in res.items():
        print(f"  {k:<14}{s_:>16.4f}{u:>18.4f}{s_-u:>8.4f}")
    return res

if __name__ == "__main__":
    rng = np.random.default_rng(42)
    print("[*] downloading")
    sqli = get(["Fuzzing/Databases/SQLi/Generic-SQLi.txt"])
    xss = get(XSS_SRC)
    with urllib.request.urlopen(RAW+"Discovery/Web-Content/raft-small-words.txt", timeout=60) as r:
        norm = sorted(set(l.decode("utf-8","ignore").strip() for l in r if l.strip()))
    print(f"    sqli={len(sqli)} xss={len(xss)} normal={len(norm)}")
    run(f3,   "BASELINE: 3 syntactic features", sqli, xss, norm, np.random.default_rng(42))
    run(f_rich,"PROPOSED: 3 syntactic + 23 lexical", sqli, xss, norm, np.random.default_rng(42))
