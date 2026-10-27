"""Sensitivity of attribution on the synthetic six-archetype benchmark.

Three analyses, for both embedding backends, on benchmark draws 1001-1010 (held out from the
training seed 42 and the calibration seed 7):
  threshold: ARI and number of actors as the Hamming threshold varies (first-match clustering);
  order:     ARI over random arrival orders of the sessions, at the deployed threshold;
  length:    ARI when every session is cut to its first n commands.

Run from the repo root: python -m scripts.sensitivity [out.json]
"""
import json
import os
import sys
import tempfile
import warnings

import numpy as np
from sklearn.metrics import adjusted_rand_score

from src.analytics.benchmark import actor_label, benchmark_scenarios
from src.analytics.cerf_engine import CERFEngine
from src.analytics.clustering import CERFClusterer

warnings.filterwarnings("ignore")
SEEDS = range(1001, 1011)
LENGTH_SEEDS = range(1001, 1006)
THRESHOLDS = list(range(0, 25, 2))
LENGTHS = [6, 8, 10, 15, 20, 30, None]  # None = full session
SHUFFLES = 20


def hashes(df, embedding):
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "telemetry.csv")
        df.reset_index(drop=True).to_csv(path, index=False)
        sessions = CERFEngine(path, tmp, embedding=embedding).run_pipeline()
    return list(zip(sessions["session_id"], sessions["cerf"]))


def score(session_cerfs, threshold):
    assigned = CERFClusterer().cluster_sessions(session_cerfs, threshold=threshold)
    truth = [actor_label(s) for s, _ in session_cerfs]
    pred = [assigned[s] for s, _ in session_cerfs]
    return adjusted_rand_score(truth, pred), len(set(pred))


def main(out_path):
    deployed = CERFEngine.CLUSTER_THRESHOLDS
    result = {"threshold": {}, "order": {}, "length": {}}
    rng = np.random.default_rng(0)
    for embedding in ("pca", "transformer"):
        thr = {t: [] for t in THRESHOLDS}
        order = []
        for seed in SEEDS:
            df = benchmark_scenarios(seed)["6 unseen archetypes"]
            sc = hashes(df, embedding)
            for t in THRESHOLDS:
                thr[t].append(score(sc, t))
            for _ in range(SHUFFLES):
                perm = [sc[i] for i in rng.permutation(len(sc))]
                order.append(score(perm, deployed[embedding])[0])
        result["threshold"][embedding] = {
            str(t): {"ari_mean": float(np.mean([a for a, _ in v])), "ari_min": float(np.min([a for a, _ in v])),
                     "actors_mean": float(np.mean([n for _, n in v]))} for t, v in thr.items()}
        result["order"][embedding] = {"ari_mean": float(np.mean(order)), "ari_min": float(np.min(order)),
                                      "ari_max": float(np.max(order)), "share_below_1": float(np.mean(np.array(order) < 0.999)),
                                      "runs": len(order)}
        lengths = {}
        for n in LENGTHS:
            vals = []
            for seed in LENGTH_SEEDS:
                df = benchmark_scenarios(seed)["6 unseen archetypes"]
                if n is not None:
                    df = df[df["command_index"] < n]
                vals.append(score(hashes(df, embedding), deployed[embedding]))
            lengths["full" if n is None else str(n)] = {
                "ari_mean": float(np.mean([a for a, _ in vals])), "ari_min": float(np.min([a for a, _ in vals])),
                "actors_mean": float(np.mean([k for _, k in vals]))}
        result["length"][embedding] = lengths
        print(embedding, "done", flush=True)
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)
    print("wrote", out_path)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "sensitivity.json")
