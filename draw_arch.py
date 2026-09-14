"""Figure 1: the FedZTA architecture as evaluated.

Depicts the domain-split topology (web gateway vs API gateway, shared threat
landscape) and coordinate-wise median aggregation -- the configuration the paper
actually evaluates. The previous version drew an attack-split topology and plain
FedAvg, both of which the evaluation shows to be the weaker choices.
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as patches

fig, ax = plt.subplots(figsize=(8, 5.4))

CLOUD_FC, CLOUD_EC, CLOUD_TC = "#d9e3f0", "#4a86e8", "#1155cc"
A_FC, A_EC, A_TC = "#e2f0d9", "#6aa84f", "#38761d"
B_FC, B_EC, B_TC = "#fce5cd", "#e69138", "#b45f06"
UP, DOWN = "#cc0000", "#3c78d8"

cloud = patches.FancyBboxPatch((0.28, 0.70), 0.44, 0.20,
                               boxstyle="round,pad=0.02",
                               facecolor=CLOUD_FC, edgecolor=CLOUD_EC, lw=2)
ax.add_patch(cloud)
ax.text(0.50, 0.835, "Cloud Aggregator", ha="center", va="center",
        fontsize=12, fontweight="bold", color=CLOUD_TC)
ax.text(0.50, 0.762, "coordinate-wise median  ($K \\geq 2f{+}1$)",
        ha="center", va="center", fontsize=9.5, color=CLOUD_TC)

for x, fc, ec, tc, title, sub in (
        (0.045, A_FC, A_EC, A_TC, "Edge Gateway A", "benign profile: public web"),
        (0.615, B_FC, B_EC, B_TC, "Edge Gateway B", "benign profile: API traffic")):
    box = patches.FancyBboxPatch((x, 0.10), 0.34, 0.22, boxstyle="round,pad=0.02",
                                 facecolor=fc, edgecolor=ec, lw=2)
    ax.add_patch(box)
    ax.text(x + 0.17, 0.272, title, ha="center", va="center",
            fontsize=11, fontweight="bold", color=tc)
    ax.text(x + 0.17, 0.208, sub, ha="center", va="center", fontsize=9, color=tc)
    ax.text(x + 0.17, 0.148, "SGD over 256 hashed 3-grams\nshared threat landscape",
            ha="center", va="center", fontsize=8.5, color=tc)

ax.annotate("", xy=(0.34, 0.695), xytext=(0.20, 0.325),
            arrowprops=dict(arrowstyle="-|>", color=UP, lw=2,
                            connectionstyle="arc3,rad=-0.18"))
ax.text(0.135, 0.50, "$w_A$\n1,040 B", color=UP, fontsize=9,
        ha="center", fontweight="bold")
ax.annotate("", xy=(0.30, 0.325), xytext=(0.42, 0.695),
            arrowprops=dict(arrowstyle="-|>", color=DOWN, lw=2,
                            connectionstyle="arc3,rad=-0.18"))
ax.text(0.405, 0.50, "$W_{global}$", color=DOWN, fontsize=9,
        ha="center", fontweight="bold")

ax.annotate("", xy=(0.66, 0.695), xytext=(0.80, 0.325),
            arrowprops=dict(arrowstyle="-|>", color=UP, lw=2,
                            connectionstyle="arc3,rad=0.18"))
ax.text(0.868, 0.50, "$w_B$\n1,040 B", color=UP, fontsize=9,
        ha="center", fontweight="bold")
ax.annotate("", xy=(0.70, 0.325), xytext=(0.58, 0.695),
            arrowprops=dict(arrowstyle="-|>", color=DOWN, lw=2,
                            connectionstyle="arc3,rad=0.18"))
ax.text(0.596, 0.50, "$W_{global}$", color=DOWN, fontsize=9,
        ha="center", fontweight="bold")

ax.text(0.50, 0.475, "PQ-TLS (ML-KEM-512)\nparameters only --- no raw payloads",
        ha="center", va="center", fontsize=8.5, style="italic", color="#666666",
        bbox=dict(boxstyle="round,pad=0.3", facecolor="white",
                  edgecolor="#bbbbbb", lw=0.8))

ax.text(0.50, 0.035, "raw HTTP payloads never leave the site boundary",
        ha="center", va="center", fontsize=9, color="#444444")

ax.set_xlim(0, 1)
ax.set_ylim(0, 0.95)
ax.axis("off")
plt.tight_layout()
plt.savefig("fl_architecture.pdf", bbox_inches="tight", dpi=300)
print("[+] fl_architecture.pdf regenerated (domain split, median aggregation)")
