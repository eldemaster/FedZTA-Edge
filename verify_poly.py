"""Confirm the polynomial rolling hash matches md5 bucketing quality, at D=256,
domain split -- the configuration selected for deployment."""
import numpy as np
import fl_simulation_v4 as S

def ngram_poly(p, d, n=3):
    v = [0.0] * d
    b = p.lower().encode("utf-8", "ignore")
    for i in range(len(b) - n + 1):
        h = 0
        for j in range(i, i + n):
            h = (h * 131 + b[j]) & 0xFFFFFFFF
        v[h % d] += 1.0
    nrm = (sum(x * x for x in v) ** 0.5) or 1.0
    return [x / nrm for x in v]

def main():
    rng = np.random.default_rng(S.SEED)
    pools = {k: S.split_pool(S.fetch(p), rng) for k, p in S.SRC.items()}
    D = 256
    print(f"{'hash':<14}{'model':<12}{'ROC-AUC':>9}{'PR-AUC':>9}"
          f"{'XSS@0.1%':>10}{'SQLi@0.1%':>11}{'FPR web':>10}{'FPR api':>10}")
    print("-" * 85)
    out = {}
    for name, fn in (("md5", lambda p: S.ngram(p, D) + S.syntactic(p)),
                     ("polynomial", lambda p: ngram_poly(p, D) + S.syntactic(p))):
        S.FEATS["ngram"] = fn
        r = S.run_cell("ngram", "domain", pools, np.random.default_rng(S.SEED))
        out[name] = r
        for m in ("Edge A", "Edge B", "Federated"):
            v = r[m]
            print(f"{name if m=='Edge A' else '':<14}{m:<12}{v['roc_auc']:>9.4f}"
                  f"{v['pr_auc']:>9.4f}{v['xss@0.1']:>10.3f}{v['sqli@0.1']:>11.3f}"
                  f"{v['fpr_web']:>10.4f}{v['fpr_api']:>10.4f}")
        print("-" * 85)
    d = abs(out["md5"]["Federated"]["roc_auc"] - out["polynomial"]["Federated"]["roc_auc"])
    print(f"\nFederated ROC-AUC difference between hashes: {d:.4f}")
    for name, r in out.items():
        f, a, b = r["Federated"], r["Edge A"], r["Edge B"]
        print(f"  {name:<12} federated beats both silos: "
              f"{'YES' if f['roc_auc'] > a['roc_auc'] and f['roc_auc'] > b['roc_auc'] else 'no'}")

if __name__ == "__main__":
    main()
