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

def decoy_config(temp_dir, telemetry_path, **kw):
    from src.decoy import DecoyConfig
    return DecoyConfig(ssh_port=0, http_port=0, telemetry_path=telemetry_path,
                       regime_schedule_path=os.path.join(temp_dir, "sched.csv"),
                       auth_path=os.path.join(temp_dir, "auth.csv"),
                       ssh_host_key_path=os.path.join(temp_dir, "host_key"), **kw)


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
    """Test A3: Attacker commands are not executed on host."""
    pfs = PseudoFilesystem("test-session")
    out, new_path, weight = pfs.execute_command("rm -rf /")
    assert "command not found" in out or out == ""
    assert pfs.cwd == "/home/user"


@pytest.mark.parametrize("tarpit", [False, True])
def test_a4_tcp_tarpit(temp_env, tarpit):
    """Test A4: Tarpit shrinks the receive buffer of accepted sockets; sessions still work."""
    import asyncio
    import socket
    from src.decoy import DecoyConfig
    temp_dir, telemetry_path = temp_env
    config = decoy_config(temp_dir, telemetry_path, tarpit=tarpit)

    async def scenario():
        server = DecoyServer(host="127.0.0.1", config=config)
        ssh, http = await server.start_listeners()
        port = http.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.readuntil(b"$ ")
        writer.write(b"whoami\n")
        await writer.drain()
        reply = await asyncio.wait_for(reader.readuntil(b"$ "), timeout=5)
        listen_buf = http.sockets[0].getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        writer.close()
        ssh.close()
        http.close()
        return reply, listen_buf

    reply, listen_buf = asyncio.run(scenario())
    assert b"root" in reply
    default_buf = socket.socket().getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
    if tarpit:
        assert listen_buf < default_buf
    else:
        assert listen_buf == default_buf


def _run_with_ssh_decoy(temp_dir, telemetry_path, client_fn):
    """Start the real SSH decoy, run blocking client_fn(port) in a thread, return its result."""
    import asyncio
    config = decoy_config(temp_dir, telemetry_path)

    async def scenario():
        server = DecoyServer(host="127.0.0.1", config=config)
        ssh, http = await server.start_listeners()
        port = ssh.sockets[0].getsockname()[1]
        try:
            return await asyncio.wait_for(asyncio.to_thread(client_fn, port), timeout=60)
        finally:
            ssh.close()
            http.close()
    return asyncio.run(scenario())


def test_a5_ssh_bruteforce_then_interactive_shell(temp_env):
    """Test A5: A paramiko bot brute-forces, logs in, and drives the decoy shell over real SSH."""
    import paramiko
    temp_dir, telemetry_path = temp_env

    def bot(port):
        attempts = []
        for password in ["hunter2", "letmein", "Winter2024!"]:  # none common: accepted on 3rd try
            t = paramiko.Transport(("127.0.0.1", port))
            t.connect()
            banner = t.remote_version
            try:
                t.auth_password("admin", password)
                attempts.append(True)
                break
            except paramiko.AuthenticationException:
                attempts.append(False)
                t.close()
        chan = t.open_session()
        chan.get_pty()
        chan.invoke_shell()
        out = b""

        def read_until_prompt():
            nonlocal out
            deadline = time.time() + 5
            start = len(out)
            while time.time() < deadline and not out[start:].rstrip().endswith(b"$"):
                if chan.recv_ready():
                    out += chan.recv(4096)
                else:
                    time.sleep(0.05)

        read_until_prompt()  # banner + first prompt
        for cmd in ["whoami", "cat ~/.aws/credentials"]:
            chan.send(cmd + "\n")
            read_until_prompt()
        chan.send("exit\n")
        t.close()
        return banner, attempts, out.decode(errors="ignore")

    banner, attempts, transcript = _run_with_ssh_decoy(temp_dir, telemetry_path, bot)

    assert banner.startswith("SSH-2.0-OpenSSH_8.9p1")
    assert attempts == [False, False, True]
    assert "admin@srv-prod-01" in transcript
    assert "AKIAIOSFODNN7EXAMPLE" in transcript

    auth = pd.read_csv(os.path.join(temp_dir, "auth.csv"))
    assert {"hunter2", "letmein"} & set(auth["password"])
    assert auth["accepted"].iloc[-1]
    assert auth["client_version"].str.startswith("SSH-2.0-paramiko").all()

    telemetry = pd.read_csv(telemetry_path)
    assert list(telemetry["command_raw"]) == ["whoami", "cat ~/.aws/credentials"]
    assert set(telemetry["protocol"]) == {"SSH"}


def test_a6_ssh_exec_command(temp_env):
    """Test A6: `ssh root@host 'uname -a; id'` with a common password runs both commands, non-interactively."""
    import paramiko
    temp_dir, telemetry_path = temp_env

    def bot(port):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect("127.0.0.1", port=port, username="root", password="123456",
                       look_for_keys=False, allow_agent=False)
        _, stdout, _ = client.exec_command("uname -a; whoami")
        out = stdout.read().decode()
        client.close()
        return out

    out = _run_with_ssh_decoy(temp_dir, telemetry_path, bot)
    assert "Linux" in out and "root" in out
    assert "srv-prod-01:" not in out  # no prompts in exec mode
    assert len(pd.read_csv(telemetry_path)) == 2
