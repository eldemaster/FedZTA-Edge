"""Regenerate the evaluation figures from committed result files.

Reads eval_deployed_results.json, real_data_results.json and
poisoning_v2_results.json from the repository root and writes
fig_deployed.pdf, fig_csic.pdf and fig_poison_v2.pdf next to this script.
No value is typed in by hand.

Usage (from anywhere): python make_eval_figures.py
"""
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))


def load(name):
    with open(os.path.join(ROOT, name)) as fh:
        return json.load(fh)


plt.rcParams.update({"font.size": 8, "axes.spines.top": False,
                     "axes.spines.right": False, "pdf.fonttype": 42})
BLUE, ORANGE, GREY, RED = "#1f77b4", "#d95f02", "#7f7f7f", "#b2182b"


# --------------------------------------------------------------- deployed ---
def fig_deployed():
    d = load("eval_deployed_results.json")["aggregate"]["cluster"]["models"]
    names = ["Edge A (web)", "Edge B (api)", "Federated", "Pooled"]
    x = np.arange(len(names))
    w = 0.38
    panels = (("fpr", "FPR at $\\tau$=0.15 (all benign)"),
              ("recall_sqli", "SQLi recall at $\\tau$=0.15"))
    fig, axes = plt.subplots(1, 2, figsize=(6.8, 2.5))
    for ax, (key, title) in zip(axes, panels):
        for off, view, col, hatch, lbl in ((-w / 2, "whole", BLUE, "", "whole string"),
                                           (w / 2, "gateway", ORANGE, "//", "gateway view")):
            m = [d[n][view]["ops"]["deployed_0.15"][key]["mean"] for n in names]
            lo = [d[n][view]["ops"]["deployed_0.15"][key]["ci95"][0] for n in names]
            hi = [d[n][view]["ops"]["deployed_0.15"][key]["ci95"][1] for n in names]
            ax.bar(x + off, m, w, color=col, hatch=hatch, edgecolor="white",
                   label=lbl, linewidth=0.5)
            ax.errorbar(x + off, m, yerr=[np.array(m) - lo, np.array(hi) - m],
                        fmt="none", ecolor="black", capsize=2, lw=0.8)
        ax.set_xticks(x)
        ax.set_xticklabels(["Edge A\n(web)", "Edge B\n(API)", "Fed.", "Pooled"])
        ax.set_title(title, fontsize=8)
        ax.set_ylim(0, 1.0)
        ax.grid(True, axis="y", ls=":", alpha=0.5)
    h, l = axes[0].get_legend_handles_labels()
    fig.legend(h, l, frameon=False, fontsize=7, loc="upper center", ncol=2)
    fig.tight_layout(rect=(0, 0, 1, 0.92))
    fig.savefig(os.path.join(HERE, "fig_deployed.pdf"))
    plt.close(fig)


# ------------------------------------------------------------------- CSIC ---
def fig_csic():
    c = load("real_data_results.json")["csic2010"]
    ctx = ["path", "query", "user-agent", "cookie", "body"]
    labels = ["path", "query", "User-\nAgent", "cookie", "body", "max over\ncontexts"]
    fig, ax = plt.subplots(figsize=(3.4, 2.5))
    x = np.arange(len(labels))
    w = 0.38
    for off, key, col, hatch, lbl in ((-w / 2, "normal_pooled", BLUE, "", "normal (72,000)"),
                                      (w / 2, "anomalous", RED, "//", "anomalous (25,065)")):
        r = c[key]["per_context_flag_rate@0.15"]
        vals = [r[k]["rate"] for k in ctx]
        vals.append(c[key]["gateway_all_contexts"]["flag_rate@0.15"]["rate"])
        ax.bar(x + off, vals, w, color=col, hatch=hatch, edgecolor="white", label=lbl,
               linewidth=0.5)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=7)
    ax.set_ylabel("flag rate at $\\tau$=0.15")
    ax.set_ylim(0, 1.0)
    ax.grid(True, axis="y", ls=":", alpha=0.5)
    ax.legend(frameon=False, fontsize=7, loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=2)
    fig.tight_layout()
    fig.savefig(os.path.join(HERE, "fig_csic.pdf"))
    plt.close(fig)


# -------------------------------------------------------------- poisoning ---
def fig_poison():
    p = load("poisoning_v2_results.json")
    S = {(r["K"], r["f"], r["attack"], r["agg"], r["gate"]): r for r in p["summary"]}
    ref = {(r["kind"], r["K"]): r for r in p["references"]}
    attacks = ["signflip", "alie", "fang", "labelflip", "normbound"]
    alabels = ["sign-\nflip", "ALIE", "Fang", "label-\nflip", "norm-\nbound"]
    series = (("mean", "off", "#9ecae1", "", "mean, gate off"),
              ("mean", "on", BLUE, "", "mean, gate on"),
              ("median", "off", "#fdbe85", "", "median, gate off"),
              ("median", "on", ORANGE, "", "median, gate on"))
    fig, axes = plt.subplots(1, 2, figsize=(6.8, 2.6), sharey=True)
    for ax, (K, f) in zip(axes, ((10, 4), (20, 8))):
        x = np.arange(len(attacks))
        w = 0.2
        for i, (agg, gate, col, hatch, lbl) in enumerate(series):
            rows = [S[(K, f, a, agg, gate)]["auc"] for a in attacks]
            ax.bar(x + (i - 1.5) * w, [r["mean"] for r in rows], w, color=col,
                   edgecolor="white", linewidth=0.4, label=lbl,
                   yerr=[r["ci95"] for r in rows], error_kw={"lw": 0.7, "capsize": 1.5})
        ax.axhline(ref[("pooled_reference", K)]["auc"]["mean"], color=GREY, ls="--", lw=0.8)
        ax.axhline(0.5, color="black", ls=":", lw=0.6)
        ax.set_xticks(x)
        ax.set_xticklabels(alabels, fontsize=7)
        ax.set_title(f"K={K}, f={f} ({int(round(100 * f / K))}% malicious)", fontsize=8)
        ax.set_ylim(0, 1.02)
        ax.grid(True, axis="y", ls=":", alpha=0.5)
    axes[0].set_ylabel("final-round ROC-AUC")
    h, l = axes[0].get_legend_handles_labels()
    fig.legend(h, l, frameon=False, fontsize=7, loc="upper center", ncol=4)
    fig.tight_layout(rect=(0, 0, 1, 0.92))
    fig.savefig(os.path.join(HERE, "fig_poison_v2.pdf"))
    plt.close(fig)


if __name__ == "__main__":
    fig_deployed()
    fig_csic()
    fig_poison()
    print("wrote fig_deployed.pdf fig_csic.pdf fig_poison_v2.pdf")
