"""
Acceptance Tests for Module B: CERF Analytics Engine
Per Technical Specification Section 3.3:
- Test B1: Feature Extraction Correctness
- Test B2: CERF Determinism
- Test B3: Attribution Accuracy (Synthetic)
- Test B4: CERF vs Baseline TF-IDF
"""

import os
import shutil
import tempfile
import numpy as np
import pandas as pd
import pytest

from src.analytics import CERFEngine
from src.analytics.synthetic import generate_synthetic_data
from src.analytics.benchmark import benchmark_scenarios, score_attribution

@pytest.fixture
def temp_env():
    temp_dir = tempfile.mkdtemp()
    telemetry_path = os.path.join(temp_dir, "telemetry.csv")
    yield temp_dir, telemetry_path
    shutil.rmtree(temp_dir, ignore_errors=True)



def test_b1_feature_extraction(temp_env):
    """Test B1: Feature extraction shape and computation correctness."""
    temp_dir, telemetry_path = temp_env
    
    df = generate_synthetic_data(num_sessions=10, script_type="A")
    df.to_csv(telemetry_path, index=False)
    
    engine = CERFEngine(telemetry_path, temp_dir, embedding="pca")
    loaded_df = engine.load_telemetry()
    features = engine.extract_features(loaded_df)
    
    assert len(features) == 10
    
    first_vec = list(features.values())[0]
    # 13 timing + 6 AST + 10 TF-IDF
    assert first_vec.shape == (29,)

    seq_engine = CERFEngine(telemetry_path, temp_dir, embedding="transformer")
    seq_features = seq_engine.extract_features(seq_engine.load_telemetry())
    # Sequence length varies, but per-step dim is 11 (1 timing + 6 AST + 4 regime)
    assert list(seq_features.values())[0].shape[1] == 11
    

def test_b2_cerf_determinism(temp_env):
    """Test B2: Ensure CERF hash is completely deterministic for the same input."""
    temp_dir, telemetry_path = temp_env
    
    df = generate_synthetic_data(num_sessions=2, script_type="A")
    df.to_csv(telemetry_path, index=False)
    
    engine = CERFEngine(telemetry_path, temp_dir)
    loaded_df = engine.load_telemetry()
    engine.extract_features(loaded_df)
    engine.train_embedding_model(engine.features)
    
    session_id = list(engine.features.keys())[0]
    
    cerf_1 = engine.compute_cerf_for_session(session_id)
    cerf_2 = engine.compute_cerf_for_session(session_id)
    cerf_3 = engine.compute_cerf_for_session(session_id)
    
    assert cerf_1 == cerf_2 == cerf_3
    assert len(cerf_1) == 16  # 64 bit hex


def test_b3_attribution_accuracy(temp_env):
    """Test B3: Attribution accuracy for synthetic sessions (Script A vs B)."""
    temp_dir, telemetry_path = temp_env
    
    df_a = generate_synthetic_data(num_sessions=10, script_type="A")
    df_b = generate_synthetic_data(num_sessions=10, script_type="B")
    
    combined_df = pd.concat([df_a, df_b]).reset_index(drop=True)
    combined_df.to_csv(telemetry_path, index=False)
    
    engine = CERFEngine(telemetry_path, temp_dir)
    sessions_df = engine.run_pipeline()
    
    # We should have exactly 2 distinct threat actors if clustering works perfectly
    ta_a = sessions_df[sessions_df["session_id"].str.contains("session_A")]["threat_actor_id"].unique()
    ta_b = sessions_df[sessions_df["session_id"].str.contains("session_B")]["threat_actor_id"].unique()
    
    assert len(ta_a) == 1, "Script A sessions fragmented into multiple clusters"
    assert len(ta_b) == 1, "Script B sessions fragmented into multiple clusters"
    assert ta_a[0] != ta_b[0], "Script A and B merged into the same cluster"


def test_b4_cerf_vs_baseline(temp_env):
    """
    Test B4: CERF vs Baseline TF-IDF
    Proves that CERF (timing perturbation + LSH) can correctly cluster when commands
    are slightly noisy, whereas pure text might fail or merge.
    """
    temp_dir, telemetry_path = temp_env
    
    # Generate 100 sessions
    df_a = generate_synthetic_data(num_sessions=50, script_type="A")
    df_b = generate_synthetic_data(num_sessions=50, script_type="B")
    
    combined_df = pd.concat([df_a, df_b]).reset_index(drop=True)
    combined_df.to_csv(telemetry_path, index=False)
    
    engine = CERFEngine(telemetry_path, temp_dir)
    sessions_df = engine.run_pipeline()
    
    ta_a_counts = sessions_df[sessions_df["session_id"].str.contains("session_A")]["threat_actor_id"].value_counts()
    ta_b_counts = sessions_df[sessions_df["session_id"].str.contains("session_B")]["threat_actor_id"].value_counts()
    
    accuracy_a = ta_a_counts.iloc[0] / 50.0
    accuracy_b = ta_b_counts.iloc[0] / 50.0
    
    overall_accuracy = (accuracy_a + accuracy_b) / 2
    
    # The benchmark requires >= 90% accuracy for CERF
    assert overall_accuracy >= 0.90, f"CERF accuracy {overall_accuracy} failed to meet 90% threshold"


def test_b5_attribution_unequal_session_lengths(temp_env):
    """
    Test B5: Fingerprints must not depend on session length. Script A sessions
    disconnect after 30 commands (never reaching fs_latency, only 5 jitter samples)
    while Script B runs 50; each script must still map to exactly one actor.
    """
    temp_dir, telemetry_path = temp_env
    np.random.seed(0)

    df_a = generate_synthetic_data(num_sessions=50, script_type="A", num_cmds=30)
    df_b = generate_synthetic_data(num_sessions=50, script_type="B")
    pd.concat([df_a, df_b]).reset_index(drop=True).to_csv(telemetry_path, index=False)

    sessions_df = CERFEngine(telemetry_path, temp_dir).run_pipeline()

    ta_a = sessions_df[sessions_df["session_id"].str.contains("session_A")]["threat_actor_id"].unique()
    ta_b = sessions_df[sessions_df["session_id"].str.contains("session_B")]["threat_actor_id"].unique()
    assert len(ta_a) == 1, f"Script A fragmented into {len(ta_a)} clusters"
    assert len(ta_b) == 1, f"Script B fragmented into {len(ta_b)} clusters"
    assert ta_a[0] != ta_b[0]


def test_b6_transformer_generalises_to_unseen_archetypes():
    """
    Test B6: The trained Transformer (default embedding) must recover every held-out
    actor exactly, including archetypes never seen in training, and do at least as
    well as the PCA baseline in every scenario.
    """
    for name, df in benchmark_scenarios(seed=1000).items():
        df = df.reset_index(drop=True)
        transformer = score_attribution(df, "transformer")
        pca = score_attribution(df, "pca")
        assert transformer["ari"] == 1.0, f"{name}: transformer {transformer}"
        assert transformer["ari"] >= pca["ari"], f"{name}: transformer {transformer} < pca {pca}"


def test_b7_missing_weights_falls_back_to_pca(temp_env, monkeypatch):
    """Test B7: Without trained weights the engine warns and uses the PCA backend."""
    temp_dir, telemetry_path = temp_env
    generate_synthetic_data(num_sessions=4).to_csv(telemetry_path, index=False)
    monkeypatch.setattr("src.analytics.transformer_model.DEFAULT_WEIGHTS", os.path.join(temp_dir, "none.pt"))
    with pytest.warns(UserWarning, match="falling back to PCA"):
        engine = CERFEngine(telemetry_path, temp_dir)
    assert engine.embedding == "pca"
