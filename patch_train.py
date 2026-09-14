import re

with open('train_production_model.py', 'r') as f:
    code = f.read()

# Add SEEDS
code = code.replace("SEED, ROUNDS, LOCAL_EPOCHS = 42, 20, 30", "SEEDS, ROUNDS, LOCAL_EPOCHS = [42, 43, 44, 45, 46, 47, 48, 49], 20, 30")

old_main = """def main():
    rng = np.random.default_rng(SEED)
    print("[*] Downloading corpora")
    P = {k: split_pool(fetch(v), rng) for k, v in SRC.items()}
    uniq = {k: {"train": len(a), "test": len(b)} for k, (a, b) in P.items()}
    for k, v in uniq.items():
        print(f"    {k:<5} {v['train']:>6} train / {v['test']:>6} test")"""

new_main = """def main():
    print("[*] Downloading corpora")
    raw_pools = {k: fetch(v) for k, v in SRC.items()}
    
    metrics_all = {"Edge A (web)": {}, "Edge B (API)": {}, "Federated": {}}
    
    for seed in SEEDS:
        global SEED
        SEED = seed
        rng = np.random.default_rng(seed)
        P = {k: split_pool(raw_pools[k], rng) for k, v in SRC.items()}
        if seed == SEEDS[0]:
            uniq = {k: {"train": len(a), "test": len(b)} for k, (a, b) in P.items()}
            for k, v in uniq.items():
                print(f"    {k:<5} {v['train']:>6} train / {v['test']:>6} test")"""

code = code.replace(old_main, new_main)

# Indent everything after `new_main`
lines = code.split('\n')
in_main = False
for i, line in enumerate(lines):
    if line.startswith("    (sq_tr, sq_te), (xs_tr, xs_te) = P[\"sqli\"], P[\"xss\"]"):
        in_main = True
    if line.startswith("    print(\"\\n\" + \"=\" * 86)"):
        in_main = False
    
    if in_main:
        lines[i] = "    " + line

code = '\n'.join(lines)

# Collect metrics
old_print_metrics = """        print(f"{nm:<16}{r['roc_auc']:>9.4f}{r['pr_auc']:>9.4f}"
              f"{r['xss_recall@fpr0.001']:>10.3f}{r['sqli_recall@fpr0.001']:>11.3f}"
              f"{r['fpr_web']:>10.4f}{r['fpr_api']:>10.4f}")
    print("=" * 86)
    fed = metrics["Federated"]
    beats = all(fed["roc_auc"] > metrics[n]["roc_auc"] for n in iso)
    print(f"Federated outperforms every isolated silo: {'YES' if beats else 'NO'}")"""

new_print_metrics = """        for k, v in r.items():
            if k not in metrics_all[nm]:
                metrics_all[nm][k] = []
            metrics_all[nm][k].append(v)
        
    print("\\n" + "=" * 90)
    print(f"{'model':<16}{'ROC-AUC':>14}{'PR-AUC':>14}{'XSS@0.1%':>12}"
          f"{'SQLi@0.1%':>12}{'FPR web':>10}{'FPR api':>10}")
    print("-" * 90)
    for nm in metrics_all:
        r = {k: {"mean": float(np.mean(v)), "std": float(np.std(v))} for k, v in metrics_all[nm].items()}
        print(f"{nm:<16}{r['roc_auc']['mean']:>6.4f}±{r['roc_auc']['std']:<6.4f} "
              f"{r['pr_auc']['mean']:>6.4f}±{r['pr_auc']['std']:<6.4f} "
              f"{r['xss_recall@fpr0.001']['mean']:>4.3f}±{r['xss_recall@fpr0.001']['std']:<4.3f} "
              f"{r['sqli_recall@fpr0.001']['mean']:>4.3f}±{r['sqli_recall@fpr0.001']['std']:<4.3f} "
              f"{r['fpr_web']['mean']:>8.4f}"
              f"{r['fpr_api']['mean']:>10.4f}")
    print("=" * 90)
    
    fed = metrics_all["Federated"]
    beats = all(fed["roc_auc"]["mean"] > metrics_all[n]["roc_auc"]["mean"] for n in ("Edge A (web)", "Edge B (API)"))
    print(f"Federated outperforms every isolated silo (on average): {'YES' if beats else 'NO'}")"""

code = code.replace(old_print_metrics, new_print_metrics)

with open('train_production_model.py', 'w') as f:
    f.write(code)
print("Train patched.")
