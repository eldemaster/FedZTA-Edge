"""Regenerate fl_metrics.pdf and fl_sweep.pdf from measured results."""
import json
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

m = json.load(open("fed_model.json"))
met, hist = m["metrics"], m["convergence"]

# ---- Figure: per-class detection, threshold-matched -------------------------
names = list(met)
x = np.arange(len(names))
w = 0.26
fig, ax = plt.subplots(figsize=(7.5, 5))
series = (("xss_recall@fpr0.001", "XSS recall @0.1% FPR", "#ff9999", -w),
          ("sqli_recall@fpr0.001", "SQLi recall @0.1% FPR", "#66b3ff", 0.0),
          ("roc_auc", "ROC-AUC", "#99ff99", w))
for key, lbl, col, off in series:
    vals = [met[n][key] for n in names]
    ax.bar(x + off, vals, w, label=lbl, color=col, edgecolor="black", linewidth=0.5)
    for xi, v in zip(x + off, vals):
        ax.text(xi, v + 0.015, f"{v:.3f}", ha="center", fontsize=8, fontweight="bold")
ax.set_xticks(x); ax.set_xticklabels(names)
ax.set_ylim(0, 1.16)
ax.set_ylabel("Score on the held-out test set", fontsize=11)
ax.set_title("Detection on unseen payloads, domain-split non-IID nodes", fontsize=12)
ax.legend(loc="lower right", fontsize=9)
ax.grid(True, axis="y", ls="--", alpha=0.5)
fig.tight_layout(); fig.savefig("fl_metrics.pdf")
print("[+] fl_metrics.pdf")

# ---- Figure: convergence + dimension sweep ----------------------------------
sweep = {32: (0.9738, 0.9735, 0.9800), 64: (0.9709, 0.9710, 0.9762),
         128: (0.9752, 0.9746, 0.9794), 256: (0.9771, 0.9766, 0.9811),
         512: (0.9740, 0.9791, 0.9809)}
fig, (a1, a2) = plt.subplots(1, 2, figsize=(11, 4.2))

a1.plot([h["round"] for h in hist], [h["roc_auc"] for h in hist],
        "o-", color="#1f77b4")
a1.set_xlabel("Federated communication round", fontsize=11)
a1.set_ylabel("Global model ROC-AUC", fontsize=11)
a1.set_title("Convergence under non-IID benign traffic", fontsize=11)
a1.grid(True, ls="--", alpha=0.5)

ds = sorted(sweep)
a2.plot(ds, [sweep[d][0] for d in ds], "s--", color="#ff7f0e", label="Edge A (web)")
a2.plot(ds, [sweep[d][1] for d in ds], "^--", color="#d62728", label="Edge B (api)")
a2.plot(ds, [sweep[d][2] for d in ds], "o-", color="#2ca02c", lw=2, label="Federated")
a2.set_xscale("log", base=2)
a2.set_xticks(ds); a2.set_xticklabels([f"{d}\n{(d+3+1)*4} B" for d in ds])
a2.set_xlabel("n-gram buckets D  (update size)", fontsize=11)
a2.set_ylabel("ROC-AUC", fontsize=11)
a2.set_title("Accuracy vs update size", fontsize=11)
a2.legend(fontsize=9); a2.grid(True, ls="--", alpha=0.5)
fig.tight_layout(); fig.savefig("fl_sweep.pdf")
print("[+] fl_sweep.pdf")
