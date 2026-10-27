import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

d = json.load(open(sys.argv[1]))
OUT = sys.argv[2]
os.makedirs(OUT, exist_ok=True)
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8, "axes.linewidth": 0.8})
W = 6.69
STYLE = {"pca": dict(color="black", ls="--", marker="s", ms=3.5, lw=1.0, label="PCA backend"),
         "transformer": dict(color="black", ls="-", marker="o", ms=3.5, lw=1.0, label="Transformer backend")}
DEPLOYED = {"pca": 6, "transformer": 10}

# Fig 3: threshold
fig, (a, b) = plt.subplots(1, 2, figsize=(W, 2.7))
for e in ("pca", "transformer"):
    t = sorted(int(k) for k in d["threshold"][e])
    a.plot(t, [d["threshold"][e][str(k)]["ari_mean"] for k in t], **STYLE[e])
    b.plot(t, [d["threshold"][e][str(k)]["actors_mean"] for k in t], **STYLE[e])
    for ax in (a, b):
        ax.axvline(DEPLOYED[e], color="gray", lw=0.8, ls=":" if e == "pca" else "-.")
a.set_xlabel("Hamming threshold (bits)")
a.set_ylabel("Adjusted Rand index (mean of 10 draws)")
a.set_ylim(0, 1.03)
a.text(0.02, 0.04, "(a)", transform=a.transAxes, fontweight="bold")
b.set_xlabel("Hamming threshold (bits)")
b.set_ylabel("Predicted actors (true: 6)")
b.set_yscale("log")
b.set_yticks([5, 6, 10, 20, 50])
b.set_yticklabels(["5", "6", "10", "20", "50"])
b.axhline(6, color="gray", lw=0.6)
b.text(0.02, 0.04, "(b)", transform=b.transAxes, fontweight="bold")
a.legend(fontsize=6.5, loc="lower right", frameon=True)
fig.tight_layout()
fig.savefig(os.path.join(OUT, "fig3_threshold.png"), dpi=300, facecolor="white")
plt.close(fig)

# Fig 4: session length
order = ["6", "8", "10", "15", "20", "30", "full"]
x = list(range(len(order)))
fig, (a, b) = plt.subplots(1, 2, figsize=(W, 2.7))
for e in ("pca", "transformer"):
    a.plot(x, [d["length"][e][k]["ari_mean"] for k in order], **STYLE[e])
    b.plot(x, [d["length"][e][k]["actors_mean"] for k in order], **STYLE[e])
for ax in (a, b):
    ax.set_xticks(x)
    ax.set_xticklabels(order)
    ax.set_xlabel("Commands kept per session (first n)")
a.set_ylabel("Adjusted Rand index (mean of 5 draws)")
a.set_ylim(0.5, 1.02)
b.set_ylabel("Predicted actors (true: 6)")
b.axhline(6, color="gray", lw=0.6)
a.text(0.02, 0.04, "(a)", transform=a.transAxes, fontweight="bold")
b.text(0.02, 0.04, "(b)", transform=b.transAxes, fontweight="bold")
a.legend(fontsize=6.5, loc="lower right", frameon=True)
fig.tight_layout()
fig.savefig(os.path.join(OUT, "fig4_length.png"), dpi=300, facecolor="white")
print("ok")
