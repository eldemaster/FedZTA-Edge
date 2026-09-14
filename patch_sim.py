import re

with open('fl_simulation_v4.py', 'r') as f:
    code = f.read()

# Add SEEDS
code = code.replace("SEED, TRAIN_FRAC = 42, 0.7", "SEEDS, TRAIN_FRAC = [42, 43, 44, 45, 46, 47, 48, 49], 0.7")

# Change main to loop over seeds
old_main = """def main():
    rng = np.random.default_rng(SEED)
    print("[*] Downloading corpora")
    pools = {}
    for k, paths in SRC.items():
        raw = fetch(paths)
        tr, te = split_pool(raw, rng)
        pools[k] = (tr, te)
        print(f"    {k:<6} {len(set(raw)):>7} unique -> {len(tr)} train / {len(te)} test")

    results = {}
    for features in ("syntactic", "ngram"):
        for axis in ("attack", "domain"):
            key = f"{features}/{axis}"
            print(f"\\n[*] {key}")
            results[key] = run_cell(features, axis, pools, np.random.default_rng(SEED))"""

new_main = """def main():
    print("[*] Downloading corpora")
    raw_pools = {}
    for k, paths in SRC.items():
        raw_pools[k] = fetch(paths)
        print(f"    {k:<6} {len(set(raw_pools[k])):>7} unique")

    results = {}
    for features in ("syntactic", "ngram"):
        for axis in ("attack", "domain"):
            key = f"{features}/{axis}"
            print(f"\\n[*] {key}")
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
                    results[key][name][metric] = {"mean": float(np.mean(vals)), "std": float(np.std(vals))}"""

code = code.replace(old_main, new_main)

# Also fix the printing loop to handle mean and std
old_print = """    for key, cell in results.items():
        for name in ("Edge A", "Edge B", "Federated"):
            r = cell[name]
            lead = key if name == "Edge A" else ""
            dim = str(cell["_dim"]) if name == "Edge A" else ""
            print(f"{lead:<20}{dim:>5}{name:<12}{r['roc_auc']:>9.4f}"
                  f"{r['xss@0.1']:>8.3f}{r['sqli@0.1']:>8.3f}"
                  f"{r['fpr_web']:>10.4f}{r['fpr_api']:>10.4f}")
        print("-" * 92)"""

new_print = """    for key, cell in results.items():
        for name in ("Edge A", "Edge B", "Federated"):
            r = cell[name]
            lead = key if name == "Edge A" else ""
            dim = str(cell["_dim"]) if name == "Edge A" else ""
            print(f"{lead:<20}{dim:>5}{name:<12}{r['roc_auc']['mean']:>6.4f}±{r['roc_auc']['std']:<6.4f}"
                  f"{r['xss@0.1']['mean']:>6.3f}±{r['xss@0.1']['std']:<5.3f}"
                  f"{r['sqli@0.1']['mean']:>6.3f}±{r['sqli@0.1']['std']:<5.3f}"
                  f"{r['fpr_web']['mean']:>8.4f}"
                  f"{r['fpr_api']['mean']:>10.4f}")
        print("-" * 92)"""

code = code.replace(old_print, new_print)

# Fix FEDERATION GAIN print
old_gain = """    print("\\nFEDERATION GAIN over the WEAKER silo, worst attack class, at 0.1% FPR")
    for key, cell in results.items():
        worst_iso = min(min(cell[n]["xss@0.1"], cell[n]["sqli@0.1"]) for n in ("Edge A", "Edge B"))
        best_iso = max(min(cell[n]["xss@0.1"], cell[n]["sqli@0.1"]) for n in ("Edge A", "Edge B"))
        fed = min(cell["Federated"]["xss@0.1"], cell["Federated"]["sqli@0.1"])
        print(f"    {key:<20} weaker silo {worst_iso:.3f} | stronger silo {best_iso:.3f} "
              f"| federated {fed:.3f}   (vs weaker {fed - worst_iso:+.3f}, vs stronger {fed - best_iso:+.3f})")"""

new_gain = """    print("\\nFEDERATION GAIN over the WEAKER silo, worst attack class, at 0.1% FPR")
    for key, cell in results.items():
        worst_iso = min(min(cell[n]["xss@0.1"]["mean"], cell[n]["sqli@0.1"]["mean"]) for n in ("Edge A", "Edge B"))
        best_iso = max(min(cell[n]["xss@0.1"]["mean"], cell[n]["sqli@0.1"]["mean"]) for n in ("Edge A", "Edge B"))
        fed = min(cell["Federated"]["xss@0.1"]["mean"], cell["Federated"]["sqli@0.1"]["mean"])
        print(f"    {key:<20} weaker silo {worst_iso:.3f} | stronger silo {best_iso:.3f} "
              f"| federated {fed:.3f}   (vs weaker {fed - worst_iso:+.3f}, vs stronger {fed - best_iso:+.3f})")"""

code = code.replace(old_gain, new_gain)

with open('fl_simulation_v4.py', 'w') as f:
    f.write(code)
print("Simulation patched.")
