"""Tools for judging CERF on real traffic, where no ground-truth actor labels exist.

weak_labels:      link sessions that share a strong indicator (same dropper URL / SSH key / captured payload).
score_clusters:   adjusted Rand index of CERF's actors against those weak labels.
ab_report:        score control sessions (perturbation off) vs treatment sessions (on).
operator_type:    uncalibrated scripted-vs-interactive guess from timing alone.
"""
import numpy as np
import pandas as pd
from sklearn.metrics import adjusted_rand_score


def weak_labels(sessions: pd.DataFrame) -> pd.Series:
    """Weak actor label per session (index = session_id), "" when the session has no strong indicator.

    Two sessions get the same label if they share a download URL, an offered SSH public key or the
    SHA-256 of a captured payload (directly or through a chain of such sessions). HASSH, user agent and header order are
    deliberately excluded: thousands of unrelated attackers share the same client library.
    """
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    linked = set()
    column = lambda name: sessions[name] if name in sessions else [""] * len(sessions)  # logs from older runs lack some
    for sid, urls, keys, hashes in zip(sessions["session_id"], column("download_urls"), column("pubkeys"),
                                       column("payload_hashes")):
        indicators = [f"url:{u}" for u in str(urls).split() if u != "nan"]
        indicators += [f"key:{k.split(':', 1)[-1]}" for k in str(keys).split() if k != "nan"]
        indicators += [f"sha:{h}" for h in str(hashes).split() if h != "nan"]
        for indicator in indicators:
            parent[find(indicator)] = find("session:" + sid)
            linked.add(sid)
    return pd.Series({sid: find("session:" + sid) if sid in linked else "" for sid in sessions["session_id"]})


def score_clusters(sessions: pd.DataFrame) -> dict:
    """ARI of threat_actor_id vs weak labels on the weakly-labelled sessions.

    "coverage" is the share of sessions that have a weak label; a score on a small
    coverage says little. ARI is None when fewer than 2 sessions are labelled.
    """
    labels = weak_labels(sessions)
    labelled = sessions[sessions["session_id"].map(labels) != ""]
    result = {"sessions": len(sessions), "labelled": len(labelled),
              "coverage": len(labelled) / len(sessions) if len(sessions) else 0.0, "ari": None}
    if len(labelled) >= 2:
        result["ari"] = float(adjusted_rand_score(labelled["session_id"].map(labels), labelled["threat_actor_id"]))
    return result


def ab_report(sessions: pd.DataFrame) -> dict:
    """Per arm ("control" = perturbation off, "treatment" = on): weak-label score and session length.

    Sessions need an `arm` column (the decoy logs it when DecoyConfig.control_fraction > 0).
    Cluster each arm on its own before comparing, so one arm's sessions can't merge the other's actors.
    """
    report = {}
    for arm, group in sessions.groupby("arm"):
        report[arm] = {**score_clusters(group), "mean_commands": float(group["num_commands"].mean())}
    return report


def operator_type(session_df: pd.DataFrame) -> str:
    """"script", "interactive" or "unknown" from the attacker's reaction times (delta_t_ns).

    UNCALIBRATED heuristic: a median reaction under 0.3 s, or very regular timing (CV < 0.25),
    is machine-like. Calibrate the thresholds on labelled real sessions before relying on it.
    """
    gaps = session_df.sort_values("command_index")["delta_t_ns"].to_numpy(dtype=float)[1:] / 1e9
    if len(gaps) < 3:
        return "unknown"
    if np.median(gaps) < 0.3 or (len(gaps) >= 5 and gaps.std() / max(gaps.mean(), 1e-9) < 0.25):
        return "script"
    return "interactive"


if __name__ == "__main__":
    import argparse
    import json
    import os

    from .clustering import ActorRegistry

    parser = argparse.ArgumentParser(description="Validation report for a real-traffic sessions.csv")
    parser.add_argument("sessions", nargs="?", default="sessions.csv")
    parser.add_argument("--registry", default="actors.db")
    args = parser.parse_args()
    df = pd.read_csv(args.sessions, keep_default_na=False)
    report = {"weak_label_score": score_clusters(df)}
    if "operator" in df:
        report["operators"] = df["operator"].value_counts().to_dict()
    if "arm" in df and (df["arm"] != "").any():
        report["ab"] = ab_report(df[df["arm"] != ""])
    if os.path.exists(args.registry):
        registry = ActorRegistry(args.registry)
        report["new_actors_per_day"] = registry.new_actors_per_day()
        registry.close()
    print(json.dumps(report, indent=2, default=str))
