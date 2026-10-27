import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

OUT = sys.argv[1]
os.makedirs(OUT, exist_ok=True)
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8, "axes.linewidth": 0.8})
W = 6.69  # 170 mm

fig, ax = plt.subplots(figsize=(W, 3.0))
ax.set_xlim(0, 100)
ax.set_ylim(0, 46)
ax.axis("off")


def box(x, y, w, h, text, fc="white", bold=False, size=6.0):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.2,rounding_size=0.8", fc=fc, ec="black", lw=0.9))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=size, fontweight="bold" if bold else "normal")


def arrow(x0, y0, x1, y1):
    ax.annotate("", xy=(x1, y1), xytext=(x0, y0), arrowprops=dict(arrowstyle="-|>", lw=0.9, color="black"))


def group(x, w, title, dashed=False):
    ax.add_patch(FancyBboxPatch((x, 4), w, 38, boxstyle="round,pad=0.2,rounding_size=1", fc="none", ec="black", lw=1.2,
                                ls="--" if dashed else "-"))
    ax.text(x + w / 2, 39.2, title, ha="center", fontsize=6.4, fontweight="bold")


box(0.5, 18, 12, 10, "Attacker\n(SSH or\nHTTP client)", fc="#e6e6e6", bold=True)
group(17, 30, "Decoy listener (isolated host)", dashed=True)
box(19, 27, 26, 8, "SSH and HTTP services")
box(19, 16, 26, 8, "Emulated filesystem\nand command set")
box(19, 5.5, 26, 8, "Perturbation engine\n(R0 to R3; control arm)")
group(52, 21, "Telemetry")
box(54, 27, 17, 8, "Command events\n(reaction time, regime)")
box(54, 16, 17, 8, "Signals (HASSH, keys,\nheaders, User-Agent)")
box(54, 5.5, 17, 8, "Login attempts\nand alerts")
group(78, 21.5, "Analytics")
box(80, 27, 17.5, 8, "Features and 32-d\nembedding")
box(80, 16, 17.5, 8, "64-bit CERF hash,\nHamming clustering")
box(80, 5.5, 17.5, 8, "Actor registry and\ndashboard")
arrow(12.9, 23, 16.6, 23)
arrow(47.4, 23, 51.6, 23)
arrow(73.4, 23, 77.6, 23)
arrow(32, 26.6, 32, 24.4)
arrow(32, 15.6, 32, 13.6)
arrow(88.75, 26.6, 88.75, 24.4)
arrow(88.75, 15.6, 88.75, 13.6)
fig.savefig(os.path.join(OUT, "fig1_architecture.png"), dpi=300, bbox_inches="tight", facecolor="white")
