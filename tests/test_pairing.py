"""The regime / reaction-time pairing: a row's delta_t reacts to the PREVIOUS response.

The decoy logs, for command k, the regime applied to the response to command k and the attacker's
reaction time to the response to command k-1 (DecoySession.step). The analytics must pair each
delta_t with the previous row's regime, and the simulator and the decoy must share one schedule.
"""
import numpy as np
import pandas as pd

from src.analytics.features import FeatureExtractor
from src.analytics.synthetic import generate_synthetic_data, generate_family_sessions, random_family
from src.analytics.transformer_model import REGIMES, TransformerEmbeddingModel
from src.decoy.perturbation import PerturbationEngine, Regime
from src.decoy.server import DecoyConfig
from src.schedule import LIVE_SCHEDULE, reaction_regime, regime_at


def _session(regimes, dts):
    return pd.DataFrame({
        "session_id": "s", "command_index": range(len(regimes)), "command_raw": ["ls"] * len(regimes),
        "regime": regimes, "delta_t_ns": dts,
    })


def test_decoy_and_simulator_share_one_schedule():
    expected = [(start, Regime(name)) for start, name in LIVE_SCHEDULE]
    assert DecoyConfig().default_schedule == expected
    engine = PerturbationEngine()
    assert [(start, r) for start, r in engine.default_schedule] == expected
    for i in range(12):
        assert engine.get_regime_for_command(i).value == regime_at(i)


def test_simulator_uses_live_layout_and_offset():
    df = generate_synthetic_data(1, "A", num_cmds=10)
    assert df["regime"].tolist() == [regime_at(i) for i in range(10)]
    assert df["regime"].tolist()[:8] == ["baseline"] * 2 + ["slowdown"] * 2 + ["jitter"] * 2 + ["fs_latency"] * 2
    # script A reacts 1 ms to a baseline response, 100 ms to a slowdown response, 200 ms to fs_latency
    dt = df["delta_t_ns"].tolist()
    assert dt[0] == 0                                   # no preceding response
    assert dt[1] == 1_000_000 and dt[2] == 1_000_000    # reactions to the two baseline responses (rows 0, 1)
    assert dt[3] == 100_000_000                         # reaction to the response to command 2 (slowdown)
    assert dt[7] == 200_000_000                         # reaction to the response to command 6 (fs_latency)


def test_family_sessions_react_to_previous_regime():
    rng = np.random.default_rng(0)
    family = random_family(rng)
    family["noise"] = 0.0
    df = generate_family_sessions(family, 1, rng, min_cmds=12, max_cmds=12)
    for i in range(1, 12):
        assert df["delta_t_ns"].iloc[i] == int(family["median_dt"][reaction_regime(i)])
    assert df["delta_t_ns"].iloc[0] == 0


def test_sequence_features_pair_dt_with_previous_regime():
    regimes = ["baseline", "baseline", "slowdown", "slowdown", "jitter"]
    sdf = _session(regimes, [5_000_000_000, 1_000_000, 2_000_000, 100_000_000, 70_000_000])
    seq = TransformerEmbeddingModel(weights_path="").extract_sequence_features(sdf)
    onehot = seq[:, -len(REGIMES):]
    assert onehot[0].sum() == 0 and seq[0, 0] == 0.0    # command 0: no reaction (its 5 s is session set-up)
    for i in range(1, 5):
        assert REGIMES[int(onehot[i].argmax())] == regimes[i - 1]
    assert np.isclose(seq[3, 0], np.log1p(100_000_000) / 20.0)


def test_pca_features_group_by_reacted_to_regime():
    # reaction times chosen so each regime's median identifies which rows were grouped into it
    regimes = ["baseline", "baseline", "slowdown", "slowdown", "jitter", "jitter", "fs_latency", "fs_latency"]
    dts = [9_000_000_000, 10, 20, 30, 40, 50, 60, 70]
    f = FeatureExtractor().extract_session_features(_session(regimes, dts))
    # reaction regime of row k is regimes[k-1]; row 0 is excluded
    assert np.isclose(f["median_dt_baseline"], np.log1p(np.median([10, 20])))      # rows 1, 2
    assert np.isclose(f["median_dt_slowdown"], np.log1p(np.median([30, 40])))      # rows 3, 4
    assert np.isclose(f["median_dt_jitter"], np.log1p(np.median([50, 60])))        # rows 5, 6
    assert np.isclose(f["median_dt_fs_latency"], np.log1p(70))                     # row 7


def test_unsorted_rows_are_ordered_before_pairing():
    regimes = ["baseline", "slowdown", "slowdown"]
    sdf = _session(regimes, [0, 10, 20]).iloc[::-1]
    seq = TransformerEmbeddingModel(weights_path="").extract_sequence_features(sdf)
    assert REGIMES[int(seq[1, -len(REGIMES):].argmax())] == "baseline"
    assert REGIMES[int(seq[2, -len(REGIMES):].argmax())] == "slowdown"
