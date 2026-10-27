"""Graphical abstract: decoy varies delay -> reaction time net of delay -> 64-bit hash -> persistent actor ID."""
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Rectangle

OUT = sys.argv[1]
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9})
fig = plt.figure(figsize=(5.4, 2.5), dpi=300)  # 1620 x 750 px; text stays readable at 13 cm
ax = fig.add_axes([0, 0, 1, 1])
ax.set_xlim(0, 108)
ax.set_ylim(0, 50)
ax.axis("off")


def panel(x, w, title):
    ax.add_patch(FancyBboxPatch((x, 4), w, 38, boxstyle="round,pad=0.2,rounding_size=1.2", fc="white", ec="black", lw=1.0))
    ax.text(x + w / 2, 45, title, ha="center", va="center", fontsize=7.6, fontweight="bold")


def arrow(x0, x1):
    ax.add_patch(FancyArrowPatch((x0, 23), (x1, 23), arrowstyle="-|>", mutation_scale=9, lw=1.1, color="black"))


# 1 decoy delay schedule
panel(1, 32, "1. Delay is varied")
idx = np.arange(10)
delay = np.array([0, 0, 100, 100, 125, 125, 200, 200, 200, 200])
x0, y0, sx, sy = 5, 11, 2.6, 0.075
for i, d in zip(idx, delay):
    ax.add_patch(Rectangle((x0 + i * sx, y0), sx * 0.8, d * sy + 0.4, fc="#8c8c8c" if d else "#d9d9d9", ec="black", lw=0.5))
ax.text(17, 36, "delay added to each response", ha="center", fontsize=7)
for label, center in (("R0", 1), ("R1", 3), ("R2", 5), ("R3", 7.5)):
    ax.text(x0 + center * sx + sx * 0.4, 7.6, label, ha="center", fontsize=6.8)
ax.text(17, 5.0, "response delay by command", ha="center", fontsize=6.5)

# 2 reaction time
panel(38, 32, "2. Reaction time")
t = np.arange(1, 10)
rt = np.array([125, 109, 125, 109, 109, 109, 93, 110, 94])
ax.plot(42 + (t - 1) * 2.9, 11 + rt * 0.17, "k-o", ms=2.2, lw=0.9)
ax.text(54, 35.5, "time to the next command", ha="center", fontsize=7)
ax.text(54, 6.6, "excludes the decoy's own delay", ha="center", fontsize=7)

# 3 hash
panel(75, 32, "3. Hash and actor")
rng = np.random.default_rng(3)
bits = rng.integers(0, 2, size=(4, 16))
for r in range(4):
    for c in range(16):
        ax.add_patch(Rectangle((78 + c * 1.62, 28.5 - r * 1.9), 1.35, 1.6, fc="black" if bits[r, c] else "white", ec="black", lw=0.4))
ax.text(91, 35.5, "64-bit CERF hash", ha="center", fontsize=7)
ax.text(91, 18.5, "within a Hamming threshold", ha="center", fontsize=7)
ax.text(91, 14.5, "→ same actor", ha="center", fontsize=7)
ax.add_patch(FancyBboxPatch((83, 6.5), 16, 5, boxstyle="round,pad=0.1,rounding_size=1", fc="#e6e6e6", ec="black", lw=0.8))
ax.text(91, 9, "TA-003", ha="center", va="center", fontsize=8, fontweight="bold")
arrow(33.6, 37.4)
arrow(70.6, 74.4)
ax.text(54, 1.3, "Evaluated on simulated and scripted traffic, not on real attackers", ha="center", fontsize=6.8, style="italic")
fig.savefig(os.path.join(OUT, "graphical_abstract.png"), dpi=300, facecolor="white")
print("ok")
