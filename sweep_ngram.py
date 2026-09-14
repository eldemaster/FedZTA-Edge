"""Sweep the n-gram hashing dimension D for the ngram/domain configuration."""
import numpy as np
import fl_simulation_v4 as S

def main():
    rng = np.random.default_rng(S.SEED)
    pools = {}
    for k, paths in S.SRC.items():
        tr, te = S.split_pool(S.fetch(paths), rng)
        pools[k] = (tr, te)

    print(f"{'D':>5}{'dim':>6}{'bytes':>8}  "
          f"{'A auc':>8}{'B auc':>8}{'Fed auc':>9}"
          f"{'Fed XSS':>9}{'Fed SQLi':>10}{'beats both?':>13}")
    print("-" * 78)
    for d in (32, 64, 128, 256, 512):
        S.NGRAM_D = d
        S.FEATS["ngram"] = lambda p, _d=d: S.ngram(p, _d) + S.syntactic(p)
        r = S.run_cell("ngram", "domain", pools, np.random.default_rng(S.SEED))
        a, b, f = r["Edge A"], r["Edge B"], r["Federated"]
        wins = f["roc_auc"] > a["roc_auc"] and f["roc_auc"] > b["roc_auc"]
        print(f"{d:>5}{r['_dim']:>6}{(r['_dim']+1)*4:>8}  "
              f"{a['roc_auc']:>8.4f}{b['roc_auc']:>8.4f}{f['roc_auc']:>9.4f}"
              f"{f['xss@0.1']:>9.3f}{f['sqli@0.1']:>10.3f}{'YES' if wins else 'no':>13}")

if __name__ == "__main__":
    main()
