"""Attribution benchmark: run the CERF pipeline on labelled telemetry and score clustering."""
import tempfile

import numpy as np
import pandas as pd
from sklearn.metrics import adjusted_rand_score

from .cerf_engine import CERFEngine
from .synthetic import generate_synthetic_data, random_family, generate_family_sessions


def actor_label(session_id: str) -> str:
    """Synthetic session ids are session_<actor>_<n>."""
    return session_id.split("_")[1]


def score_attribution(telemetry: pd.DataFrame, embedding: str) -> dict:
    """Adjusted Rand index of predicted threat actors vs true actors, plus actor counts."""
    with tempfile.TemporaryDirectory() as tmp:
        path = f"{tmp}/telemetry.csv"
        telemetry.to_csv(path, index=False)
        sessions = CERFEngine(path, tmp, embedding=embedding).run_pipeline()
    truth = sessions["session_id"].map(actor_label)
    return {
        "ari": float(adjusted_rand_score(truth, sessions["threat_actor_id"])),
        "true_actors": int(truth.nunique()),
        "predicted_actors": int(sessions["threat_actor_id"].nunique()),
    }


def benchmark_scenarios(seed: int = 1000) -> dict:
    """Held-out scenarios: canonical scripts (equal and unequal length) and unseen random archetypes."""
    np.random.seed(seed)
    rng = np.random.default_rng(seed)
    a50, b50 = generate_synthetic_data(30, "A"), generate_synthetic_data(30, "B")
    a30 = generate_synthetic_data(30, "A", num_cmds=30)
    families = pd.concat([generate_family_sessions(random_family(rng), 20, rng, family_id=f"F{k}")
                          for k in range(6)])
    return {
        "A/B equal length": pd.concat([a50, b50]),
        "A/B unequal length": pd.concat([a30, b50]),
        "6 unseen archetypes": families,
    }


if __name__ == "__main__":
    for name, df in benchmark_scenarios().items():
        for embedding in ("pca", "transformer"):
            print(f"{name:22s} {embedding:12s} {score_attribution(df.reset_index(drop=True), embedding)}")


def regime_drop_rates(telemetry: "pd.DataFrame") -> dict:
    """Per regime: share of its commands after which the attacker never sent another one.

    A regime that drops far more sessions than baseline is too aggressive (bots hang up
    instead of revealing their behaviour). Compare against "baseline", not against zero:
    every session ends somewhere.
    """
    df = telemetry.sort_values(["session_id", "command_index"])
    last = df.groupby("session_id").tail(1)["regime"].value_counts()
    total = df["regime"].value_counts()
    return {regime: float(last.get(regime, 0)) / count for regime, count in total.items()}
