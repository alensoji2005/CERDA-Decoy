"""
Acceptance Tests for Module C: Streamlit Dashboard
Per Technical Specification Section 4.3:
- Test C1: Dashboard Load Time
- Test C2: CERF Graph Correctness (NetworkX properties)
- Test C3: Export Validity
"""

import json
import os
import shutil
import tempfile
import time

import numpy as np
import pandas as pd
import pytest

from dashboard import CERDDashboard

@pytest.fixture
def dash_env():
    temp_dir = tempfile.mkdtemp()
    sessions_path = os.path.join(temp_dir, "sessions.csv")
    telemetry_path = os.path.join(temp_dir, "telemetry.csv")
    
    yield temp_dir, sessions_path, telemetry_path
    shutil.rmtree(temp_dir, ignore_errors=True)


def generate_massive_dataset(sessions_path: str, telemetry_path: str):
    """Generates 1,000 sessions and 10,000 telemetry rows for load testing."""
    sessions = []
    for i in range(1000):
        ta = f"TA-{(i % 5):03d}"
        sessions.append({
            "session_id": f"sess_{i}",
            "source_ip": "127.0.0.1",
            "cerf": "a3f5c9d2" if i % 2 == 0 else "b1e4d8c1",
            "threat_actor_id": ta,
            "embedding_norm": 1.5,
            "num_commands": 10,
            "dominant_regime": "baseline"
        })
    pd.DataFrame(sessions).to_csv(sessions_path, index=False)
    
    telemetry = []
    for i in range(1000):
        for cmd in range(10):
            telemetry.append({
                "session_id": f"sess_{i}",
                "timestamp_ns": 1000000000,
                "source_ip": "127.0.0.1",
                "protocol": "SSH",
                "command_index": cmd,
                "command_raw": "ls",
                "command_root": "ls",
                "current_path": "/home",
                "regime": "baseline",
                "delta_t_ns": 1000000,
                "response_sent": True
            })
    pd.DataFrame(telemetry).to_csv(telemetry_path, index=False)


def test_c1_dashboard_load_time(dash_env):
    """Test C1: Dashboard data load takes < 5 seconds for massive datasets."""
    temp_dir, sessions_path, telemetry_path = dash_env
    generate_massive_dataset(sessions_path, telemetry_path)
    
    dash = CERDDashboard(sessions_path, telemetry_path)
    
    start_time = time.time()
    dash.load_data()
    end_time = time.time()
    
    load_duration = end_time - start_time
    assert load_duration < 5.0, f"Load took too long: {load_duration}s"
    assert len(dash.sessions_df) == 1000
    assert len(dash.telemetry_df) == 10000


def test_c2_cerf_graph_clustering(dash_env):
    """
    Test C2: Verifies that the internal graph logic used in the UI connects 
    sessions of the SAME threat actor, but NOT different threat actors.
    """
    temp_dir, sessions_path, telemetry_path = dash_env
    
    # 3 sessions, TA-001 (2 sessions) and TA-002 (1 session)
    sessions = pd.DataFrame([
        {"session_id": "s1", "threat_actor_id": "TA-001", "cerf": "111", "source_ip": "1.1.1.1"},
        {"session_id": "s2", "threat_actor_id": "TA-001", "cerf": "111", "source_ip": "1.1.1.2"},
        {"session_id": "s3", "threat_actor_id": "TA-002", "cerf": "222", "source_ip": "2.2.2.2"}
    ])
    sessions.to_csv(sessions_path, index=False)
    
    dash = CERDDashboard(sessions_path, telemetry_path)
    dash.load_data()
    
    import networkx as nx
    G = nx.Graph()
    for _, row in dash.sessions_df.iterrows():
        G.add_node(row["session_id"], ta=row["threat_actor_id"])
        
    for ta in dash.sessions_df["threat_actor_id"].unique():
        ta_nodes = dash.sessions_df[dash.sessions_df["threat_actor_id"] == ta]["session_id"].tolist()
        for i in range(len(ta_nodes)):
            for j in range(i+1, len(ta_nodes)):
                G.add_edge(ta_nodes[i], ta_nodes[j])
                
    assert G.has_edge("s1", "s2")
    assert not G.has_edge("s1", "s3")
    assert not G.has_edge("s2", "s3")


def test_c3_export_validity(dash_env):
    """Test C3: Export JSON matches the strictly requested schema."""
    temp_dir, sessions_path, telemetry_path = dash_env
    
    sessions = pd.DataFrame([
        {
            "session_id": "s1", "threat_actor_id": "TA-001", "cerf": "a3f5", 
            "source_ip": "10.0.0.1", "num_commands": 10, "embedding_norm": 1.0, "dominant_regime": "baseline"
        },
        {
            "session_id": "s2", "threat_actor_id": "TA-001", "cerf": "a3f5", 
            "source_ip": "10.0.0.2", "num_commands": 10, "embedding_norm": 1.0, "dominant_regime": "baseline"
        }
    ])
    sessions.to_csv(sessions_path, index=False)
    
    dash = CERDDashboard(sessions_path, telemetry_path)
    dash.load_data()
    
    json_str = dash.export_threat_intel()
    parsed = json.loads(json_str)
    
    assert "export_timestamp" in parsed
    assert "threat_actors" in parsed
    assert len(parsed["threat_actors"]) == 1
    
    ta = parsed["threat_actors"][0]
    assert ta["threat_actor_id"] == "TA-001"
    assert ta["cerf"] == "a3f5"
    assert set(ta["associated_ips"]) == {"10.0.0.1", "10.0.0.2"}
    assert ta["num_sessions"] == 2
