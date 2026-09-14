"""Is 'federation beats every isolated silo' a stable result or seed noise?

train_production_model.py and fl_simulation_v4.py run the same nominal
configuration (ngram features, domain split, R=20, E=30) and reach opposite
conclusions about whether the federated model beats Edge B. This runs the cell
across independent seeds and reports the spread.
"""
import statistics as st

import numpy as np

import fl_simulation_v4 as S

SEEDS = [42, 7, 13, 101, 2024, 31337, 8, 55]


def main():
    rng = np.random.default_rng(12345)
    pools = {k: S.split_pool(S.fetch(p), rng) for k, p in S.SRC.items()}
    print(f"  corpora: " + ", ".join(f"{k}={len(v[0])}+{len(v[1])}" for k, v in pools.items()))
    print()
    print(f"  {'seed':>7}{'EdgeA':>9}{'EdgeB':>9}{'Fed':>9}   "
          f"{'Fed-best':>9}  {'winner':<10}{'Fed SQLi':>10}{'B SQLi':>9}")
    print("  " + "-" * 76)

    rows = []
    for seed in SEEDS:
        S.SEED = seed
        r = S.run_cell("ngram", "domain", pools, np.random.default_rng(seed))
        a, b, f = r["Edge A"], r["Edge B"], r["Federated"]
        best_iso = max(a["roc_auc"], b["roc_auc"])
        delta = f["roc_auc"] - best_iso
        winner = "Federated" if delta > 0 else ("Edge B" if b["roc_auc"] >= a["roc_auc"] else "Edge A")
        rows.append({"seed": seed, "a": a["roc_auc"], "b": b["roc_auc"], "f": f["roc_auc"],
                     "delta": delta, "fed_sqli": f["sqli@0.1"], "b_sqli": b["sqli@0.1"],
                     "fed_xss": f["xss@0.1"], "b_xss": b["xss@0.1"], "a_sqli": a["sqli@0.1"]})
        print(f"  {seed:>7}{a['roc_auc']:>9.4f}{b['roc_auc']:>9.4f}{f['roc_auc']:>9.4f}   "
              f"{delta:>+9.4f}  {winner:<10}{f['sqli@0.1']:>10.3f}{b['sqli@0.1']:>9.3f}")

    print("  " + "-" * 76)
    d = [r["delta"] for r in rows]
    wins = sum(1 for x in d if x > 0)
    print(f"  federated ROC-AUC minus best silo: mean {st.mean(d):+.4f}  "
          f"stdev {st.stdev(d):.4f}  min {min(d):+.4f}  max {max(d):+.4f}")
    print(f"  federated wins on ROC-AUC in {wins}/{len(d)} seeds")

    fs = [r["fed_sqli"] for r in rows]
    bs = [r["b_sqli"] for r in rows]
    as_ = [r["a_sqli"] for r in rows]
    sq_wins = sum(1 for r in rows if r["fed_sqli"] >= max(r["b_sqli"], r["a_sqli"]))
    print(f"  SQLi@0.1%: fed {st.mean(fs):.3f}+-{st.stdev(fs):.3f} | "
          f"EdgeB {st.mean(bs):.3f}+-{st.stdev(bs):.3f} | EdgeA {st.mean(as_):.3f}+-{st.stdev(as_):.3f}")
    print(f"  federated >= every silo on SQLi recall in {sq_wins}/{len(rows)} seeds")

    xw = sum(1 for r in rows if r["fed_xss"] >= r["b_xss"])
    print(f"  federated >= Edge B on XSS recall in {xw}/{len(rows)} seeds")


if __name__ == "__main__":
    main()
