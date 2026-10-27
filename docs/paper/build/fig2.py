import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.patches import FancyBboxPatch

OUT = sys.argv[1]
os.makedirs(OUT, exist_ok=True)
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8, "axes.linewidth": 0.8})
W = 6.69  # 170 mm

# ---------- Fig 2: one live bot session ----------
tel = pd.read_csv(sys.argv[2])
live = tel[tel["source_ip"] == "127.0.0.1"]
sid = live["session_id"].iloc[0]
s = live[live["session_id"] == sid].sort_values("command_index").reset_index(drop=True)
s["reacted_to"] = s["regime"].shift(1)
shade = {"baseline": "#f2f2f2", "slowdown": "#d9d9d9", "jitter": "#bfbfbf", "fs_latency": "#a6a6a6"}
fig, ax = plt.subplots(figsize=(W, 2.9))
ymax = s["delta_t_ns"].iloc[1:].max() / 1e6
for k in range(1, len(s)):
    ax.axvspan(k - 0.5, k + 0.5, color=shade[s.loc[k, "reacted_to"]], lw=0)
ax.plot(s["command_index"].iloc[1:], s["delta_t_ns"].iloc[1:] / 1e6, "k-o", ms=3.2, lw=0.9)
ax.set_xlabel("Command index (command 0 has no preceding response and is not plotted)")
ax.set_ylabel("Reaction time (ms)")
ax.set_xlim(0.5, len(s) - 0.5); ax.set_ylim(0, ymax * 1.18)
import matplotlib.patches as mp
handles = [mp.Patch(fc=shade[r], ec="black", lw=0.5, label=l) for r, l in
           [("baseline", "reacting to a baseline response"), ("slowdown", "to a slowdown response"),
            ("jitter", "to a jitter response"), ("fs_latency", "to a filesystem-latency response")]]
ax.legend(handles=handles, loc="upper right", fontsize=6.5, frameon=True, ncol=2, framealpha=1)
fig.savefig(os.path.join(OUT, "fig2_live_session.png"), dpi=300, bbox_inches="tight", facecolor="white")
plt.close(fig)
print("session", sid, "commands", len(s))
print(s[["command_index", "regime", "reacted_to", "delta_t_ns"]].assign(ms=lambda d: (d.delta_t_ns / 1e6).round(0)).to_string(index=False))
