"""Does a session's CERF hash depend on which other sessions are in the batch?

Run from the repo root: python -m scripts.hash_stability

Experiment 1 (hash stability): run the engine on a subset of sessions, then on a superset,
and compare the hashes of the sessions both runs contain.
Experiment 2 (registry): feed the subset and then the superset through one persistent
ActorRegistry, as the live analytics loop does, and score the result.
"""
import os
import sys
import tempfile
import warnings

import numpy as np
import pandas as pd
from sklearn.metrics import adjusted_rand_score

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
warnings.filterwarnings("ignore")

from src.analytics.benchmark import benchmark_scenarios, actor_label  # noqa: E402
from src.analytics.cerf_engine import CERFEngine  # noqa: E402
from src.analytics.clustering import hamming_distance  # noqa: E402


def run(df, embedding, registry=None):
    tmp = tempfile.mkdtemp()
    path = os.path.join(tmp, "telemetry.csv")
    df.to_csv(path, index=False)
    eng = CERFEngine(path, tmp, embedding=embedding, registry_path=registry)
    assert eng.embedding == embedding, f"{embedding} fell back to {eng.embedding}"
    return eng.run_pipeline().set_index("session_id")


full = benchmark_scenarios()["6 unseen archetypes"].reset_index(drop=True)
sids = full["session_id"].unique()
print("sessions:", len(sids), "| example ids:", list(sids[:3]), "| truth actors:", len({actor_label(s) for s in sids}))

# subset = first half of each family's sessions; superset = all
by_family = {}
for s in sids:
    by_family.setdefault(actor_label(s), []).append(s)
half = [s for fam in by_family.values() for s in fam[: len(fam) // 2]]
sub = full[full["session_id"].isin(half)].reset_index(drop=True)
# a third batch: only 2 of the 6 families (what a live analytics run sees on day one)
two = [s for f in list(by_family)[:2] for s in by_family[f]]
small = full[full["session_id"].isin(two)].reset_index(drop=True)

for embedding, thr in (("pca", 6), ("transformer", 10)):
    print(f"\n===== backend: {embedding} (threshold {thr}) =====")
    for name, batch in (("half of each family", sub), ("2 of 6 families only", small)):
        a = run(batch, embedding)
        b = run(full, embedding)
        common = a.index.intersection(b.index)
        d = np.array([hamming_distance(a.loc[s, "cerf"], b.loc[s, "cerf"]) for s in common])
        print(f"[1] same {len(common)} sessions, batch '{name}' vs full batch: "
              f"Hamming(hash_small, hash_full) mean {d.mean():.1f}, median {np.median(d):.0f}, "
              f"max {d.max()}, share > threshold {np.mean(d > thr):.0%}, share identical {np.mean(d == 0):.0%}")

    # experiment 2: registry across two runs
    tmp = tempfile.mkdtemp()
    reg = os.path.join(tmp, "actors.db")
    r1 = run(small, embedding, registry=reg)          # day one: 2 families
    r2 = run(full, embedding, registry=reg)           # later: all 6 families (the 2 are re-seen)
    truth = r2.index.map(actor_label)
    print(f"[2] registry, run 1 (2 families): actors {r1['threat_actor_id'].nunique()} (truth 2), "
          f"ARI {adjusted_rand_score(r1.index.map(actor_label), r1['threat_actor_id']):.2f}")
    print(f"[2] registry, run 2 (6 families): actors {r2['threat_actor_id'].nunique()} (truth 6), "
          f"ARI {adjusted_rand_score(truth, r2['threat_actor_id']):.2f}")
    # fresh stateless clustering on the same full batch, for reference
    r3 = run(full, embedding)
    print(f"[2] reference, stateless on full batch: actors {r3['threat_actor_id'].nunique()}, "
          f"ARI {adjusted_rand_score(r3.index.map(actor_label), r3['threat_actor_id']):.2f}")
    # did any session change actor between run 1 and run 2?
    common = r1.index.intersection(r2.index)
    changed = int((r1.loc[common, "threat_actor_id"] != r2.loc[common, "threat_actor_id"]).sum())
    print(f"[2] sessions present in both registry runs whose actor ID changed: {changed} of {len(common)}")
