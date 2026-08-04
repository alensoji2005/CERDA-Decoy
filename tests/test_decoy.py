"""
Acceptance Tests for Module A: Decoy Server & Telemetry
Per Technical Specification Section 2.3:
- Test A1: Telemetry Completeness
- Test A2: Perturbation Schedule Determinism
- Test A3: Host Isolation
"""

import os
import shutil
import tempfile
import time
import uuid
import pytest
import pandas as pd

from src.decoy import (
    DecoyServer,
    PseudoFilesystem,
    PerturbationEngine,
    Regime,
    TelemetryLogger,
    TelemetryEvent
)

@pytest.fixture
def temp_env():
    temp_dir = tempfile.mkdtemp()
    telemetry_path = os.path.join(temp_dir, "test_telemetry.csv")
    yield temp_dir, telemetry_path
    shutil.rmtree(temp_dir, ignore_errors=True)

def test_a1_telemetry_completeness(temp_env):
    temp_dir, telemetry_path = temp_env
    logger = TelemetryLogger(telemetry_path)
    
    sessions = [str(uuid.uuid4()) for _ in range(3)]
    commands = [
        "ls", "cd /tmp", "pwd", "whoami", "id",
        "ls", "cat /etc/passwd", "touch file.txt", "rm file.txt", "uname"
    ]
    
    for session_id in sessions:
        for idx, cmd in enumerate(commands):
            event = TelemetryEvent(
                session_id=session_id,
                timestamp_ns=time.monotonic_ns(),
                source_ip="127.0.0.1",
                protocol="SSH",
                command_index=idx,
                command_raw=cmd,
                command_root=cmd.split()[0],
                current_path="/home/user",
                regime="baseline" if idx < 3 else "slowdown",
                delta_t_ns=100000 if idx > 0 else 0,
                response_sent=True
            )
            logger.log_event(event)
            
    df = pd.read_csv(telemetry_path)
    assert len(df) == 30, f"Expected 30 rows, got {len(df)}"
    assert set(df["session_id"].unique()) == set(sessions)
    assert set(df["command_index"].unique()) == set(range(10))
    assert (df["timestamp_ns"] > 0).all()

def test_a2_perturbation_schedule_determinism():
    engine1 = PerturbationEngine(seed=42)
    engine2 = PerturbationEngine(seed=42)
    
    regimes1 = [engine1.get_regime_for_command(i).value for i in range(10)]
    regimes2 = [engine2.get_regime_for_command(i).value for i in range(10)]
    
    assert regimes1 == regimes2

def test_a3_host_isolation():
    pfs = PseudoFilesystem()
    out, new_path, weight = pfs.execute_command("rm -rf /")
    assert "command not found" in out or out == ""
    assert pfs.cwd == "/home/user"
