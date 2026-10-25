"""Real-data validation tools: weak labels, A/B report, operator type, novelty / drift."""
import os
import tempfile

import pandas as pd

from src.analytics.clustering import ActorRegistry
from src.analytics.validation import ab_report, operator_type, score_clusters, weak_labels


def sessions_frame():
    return pd.DataFrame([
        # s1+s2 share a dropper URL, s2+s3 share an SSH key: one chain, one weak actor
        dict(session_id="s1", threat_actor_id="TA-001", download_urls="http://evil/x.sh", pubkeys="", num_commands=5),
        dict(session_id="s2", threat_actor_id="TA-001", download_urls="http://evil/x.sh", pubkeys="root:SHA256:K1", num_commands=7),
        dict(session_id="s3", threat_actor_id="TA-001", download_urls="", pubkeys="admin:SHA256:K1", num_commands=3),
        dict(session_id="s4", threat_actor_id="TA-002", download_urls="http://other/y.sh", pubkeys="", num_commands=4),
        dict(session_id="s5", threat_actor_id="TA-002", download_urls="http://other/y.sh", pubkeys="", num_commands=4),
        dict(session_id="s6", threat_actor_id="TA-003", download_urls="", pubkeys="", num_commands=2),  # no indicator
    ])


def test_b9_weak_labels_and_score():
    df = sessions_frame()
    labels = weak_labels(df)
    assert labels["s1"] == labels["s2"] == labels["s3"] != ""
    assert labels["s4"] == labels["s5"] and labels["s4"] != labels["s1"]
    assert labels["s6"] == ""
    score = score_clusters(df)
    assert score["labelled"] == 5 and abs(score["coverage"] - 5 / 6) < 1e-9 and score["ari"] == 1.0

    df.loc[df["session_id"] == "s3", "threat_actor_id"] = "TA-002"  # CERF disagrees with the weak label
    assert score_clusters(df)["ari"] < 1.0


def test_b10_ab_report_splits_arms():
    df = sessions_frame()
    df["arm"] = ["treatment"] * 3 + ["control"] * 3
    report = ab_report(df)
    assert set(report) == {"control", "treatment"}
    assert report["treatment"]["labelled"] == 3 and report["control"]["labelled"] == 2
    assert report["treatment"]["mean_commands"] == 5.0


def test_b11_operator_type():
    def session(gaps_s):
        gaps = [0] + [int(g * 1e9) for g in gaps_s]
        return pd.DataFrame({"command_index": range(len(gaps)), "delta_t_ns": gaps})
    assert operator_type(session([0.01, 0.02, 0.01, 0.02])) == "script"            # too fast for a person
    assert operator_type(session([2.0, 2.0, 2.0, 2.0, 2.0, 2.0])) == "script"      # slow but metronomic
    assert operator_type(session([1.5, 6.0, 3.2, 12.0, 0.9])) == "interactive"
    assert operator_type(session([1.0])) == "unknown"


def test_b12_registry_flags_new_actors_and_counts_per_day():
    path = os.path.join(tempfile.mkdtemp(), "actors.db")
    reg = ActorRegistry(path)
    reg.assign([("s1", "0" * 16, 3)], threshold=6)
    assert reg.new_actors == {"TA-001"}
    reg.assign([("s1", "0" * 16, 3), ("s2", "0" * 16, 3), ("s3", "f" * 16, 3)], threshold=6)
    assert reg.new_actors == {"TA-002"}  # s2 matched TA-001, s3 is a new attacker
    per_day = reg.new_actors_per_day()
    assert list(per_day.values()) == [2]
    reg.close()
