"""Gap 4: Telnet decoy (src/decoy/telnet_server.py)."""
import asyncio
import csv
import hashlib
import json
import os
import socket
import time

import pandas as pd
import pytest

from src.decoy import DecoyServer
from src.decoy import ssh_server
from src.decoy.telnet_server import IAC, DO, DONT, WILL, WONT, ECHO, SGA, TelnetConnection, TelnetDecoy
from tests.test_decoy import _run_with_decoy, decoy_config, temp_env  # noqa: F401  (temp_env is a fixture)


@pytest.fixture(autouse=True)
def fresh_login_counters():
    ssh_server._attempts_by_ip.clear()
    ssh_server._fs_by_client.clear()


class Client:
    """Blocking Telnet client for tests: reads until a marker shows up."""

    def __init__(self, port):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        self.seen = b""

    def read_until(self, marker: str, timeout=10) -> str:
        deadline = time.time() + timeout
        while marker.encode() not in self.seen:
            if time.time() > deadline:
                raise AssertionError(f"timed out waiting for {marker!r}; got {self.seen!r}")
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            self.seen += chunk
        out, _, self.seen = self.seen.partition(marker.encode())
        return out.decode("utf-8", "replace") + marker

    def send(self, text: str):
        self.sock.sendall(text.encode("latin-1"))

    def login(self, user="root", password="123456") -> str:
        """Answer the prompts; returns what the server said before the login prompt (e.g. 'Login incorrect')."""
        before = self.read_until("login: ")
        self.send(user + "\r\n")
        self.read_until("Password: ")
        self.send(password + "\r\n")
        return before

    def run(self, command: str, prompt: str) -> str:
        self.send(command + "\r\n")
        return self.read_until(prompt)

    def closed(self, timeout=5) -> bool:
        self.sock.settimeout(timeout)
        try:
            while True:
                if not self.sock.recv(4096):
                    return True
        except (ConnectionError, OSError) as e:
            return not isinstance(e, socket.timeout)


def _rows(path):
    return list(csv.DictReader(open(path))) if os.path.exists(path) else []


def test_t1_bot_logs_in_and_runs_commands(temp_env):
    temp_dir, telemetry_path = temp_env

    def bot(ports):
        c = Client(ports["telnet"])
        c.login("root", "123456")
        c.read_until("root@srv-prod-01:~# ")
        out = c.run("uname -a", "root@srv-prod-01:~# ")
        c.send("exit\r\n")
        return out

    out = _run_with_decoy(temp_dir, telemetry_path, bot)
    assert "Linux srv-prod-01" in out and "\r\n" in out
    auth = _rows(os.path.join(temp_dir, "auth.csv"))
    assert [(r["protocol"], r["username"], r["password"], r["accepted"]) for r in auth] == \
           [("TELNET", "root", "123456", "True")]
    signals = {(r["kind"], r["value"]) for r in _rows(os.path.join(temp_dir, "signals.csv"))}
    assert ("telnet_opts", "none") in signals and ("login_attempt", "root:123456") in signals
    telemetry = pd.read_csv(telemetry_path)
    assert set(telemetry["protocol"]) == {"TELNET"} and telemetry["command_raw"].tolist() == ["uname -a"]


def test_t2_wrong_passwords_then_accepted_on_third_attempt(temp_env):
    temp_dir, telemetry_path = temp_env

    def bot(ports):
        c = Client(ports["telnet"])
        said = [c.login("admin", password) for password in ("hunter2", "letmein", "Winter2024!")]
        return said, c.read_until("admin@srv-prod-01:~$ ")

    said, shell = _run_with_decoy(temp_dir, telemetry_path, bot)
    assert "Login incorrect" not in said[0] and "Login incorrect" in said[1] and "Login incorrect" in said[2]
    assert "Welcome to Ubuntu" in shell
    assert [r["accepted"] for r in _rows(os.path.join(temp_dir, "auth.csv"))] == ["False", "False", "True"]


def test_t3_gives_up_after_too_many_failures(temp_env):
    temp_dir, telemetry_path = temp_env
    # the real policy accepts on the 3rd attempt, so refuse everything to reach the per-connection cap
    original = ssh_server.ACCEPT_AFTER_ATTEMPTS
    ssh_server.ACCEPT_AFTER_ATTEMPTS = 10_000
    try:
        def bot(ports):
            c = Client(ports["telnet"])
            for _ in range(5):
                c.login("root", "nope")
            return c.closed()
        assert _run_with_decoy(temp_dir, telemetry_path, bot) is True
    finally:
        ssh_server.ACCEPT_AFTER_ATTEMPTS = original
    assert len(_rows(os.path.join(temp_dir, "auth.csv"))) == 5


class _Writer:
    def __init__(self):
        self.data = b""

    def write(self, data):
        self.data += data


def _conn(payload: bytes):
    reader = asyncio.StreamReader()
    reader.feed_data(payload)
    reader.feed_eof()
    writer = _Writer()
    return TelnetConnection(reader, writer), writer


def test_t4_line_editing_and_negotiation():
    async def scenario():
        conn, writer = _conn(
            bytes([IAC, DO, ECHO, IAC, WILL, 24, IAC, DO, 31]) + b"rooX\x7ft\r\x00" +  # negotiation, backspace, CR NUL
            b"id\n" + bytes([IAC, IAC]) + b"\xc3\xa9\r\n" + b"abc\x03" + b"junk\x04")
        assert await conn.readline(echo=True) == "root"
        assert await conn.readline(echo=True) == "id"
        assert await conn.readline(echo=False) == "\xff\xc3\xa9".encode("latin-1").decode("utf-8", "replace")
        assert await conn.readline(echo=True) == ""  # Ctrl-C clears the line
        assert await conn.readline(echo=True) is None  # junk, then Ctrl-D only ends an EMPTY line: EOF follows
        return conn, writer

    conn, writer = asyncio.run(scenario())
    # DO ECHO is one we offered (no reply); WILL 24 is refused with DONT; DO 31 (NAWS) with WONT
    assert bytes([IAC, DONT, 24]) in writer.data and bytes([IAC, WONT, 31]) in writer.data
    assert bytes([IAC, WONT, ECHO]) not in writer.data
    assert conn.options == [(DO, ECHO), (WILL, 24), (DO, 31)]
    assert conn.opts_fingerprint() not in ("none", "")


def test_t5_option_fingerprint_is_logged_for_negotiating_clients(temp_env):
    temp_dir, telemetry_path = temp_env

    def client(ports):
        c = Client(ports["telnet"])
        c.sock.sendall(bytes([IAC, DO, ECHO, IAC, DO, SGA, IAC, WILL, 24, IAC, WILL, 31]))
        c.login("root", "root")
        c.read_until("root@srv-prod-01:~# ")
        return c.seen

    _run_with_decoy(temp_dir, telemetry_path, client)
    opts = [r["value"] for r in _rows(os.path.join(temp_dir, "signals.csv")) if r["kind"] == "telnet_opts"]
    assert len(opts) == 1 and opts[0] != "none"


def test_t6_mirai_dropper_binary_is_captured_byte_for_byte(temp_env):
    temp_dir, telemetry_path = temp_env
    elf = b"\x7fELF\x02\x01\x01\x00\xff\xfe\x80\x00"
    script = "".join(f"\\x{b:02x}" for b in elf)

    def bot(ports):
        c = Client(ports["telnet"])
        c.login("root", "xc3511")  # 1st attempt with a non-common password is refused ...
        c.login("root", "vizxv")
        c.login("root", "admin")  # ... and a common one is accepted
        prompt = "root@srv-prod-01:~# "
        c.read_until(prompt)
        busybox = c.run("/bin/busybox ZORRO", prompt)
        c.run(f'echo -ne "{script}" > /tmp/.d', prompt)
        c.run(f'echo -ne "\\x41\\x42" >> /tmp/.d', prompt)
        return busybox

    busybox = _run_with_decoy(temp_dir, telemetry_path, bot)
    assert "ZORRO: applet not found" in busybox
    samples = [json.loads(line) for line in open(os.path.join(temp_dir, "samples.jsonl"))]
    assert len(samples) == 1  # one sample for the finished file, not one per append
    sample = samples[0]
    assert sample["origin"] == "write" and sample["type"] == "elf" and sample["protocol"] == "TELNET"
    assert sample["sha256"] == hashlib.sha256(elf + b"AB").hexdigest()
    assert open(os.path.join(temp_dir, "quarantine", sample["sha256"]), "rb").read() == elf + b"AB"


def test_t7_banned_ip_is_refused_and_connection_limit_applies(temp_env):
    temp_dir, telemetry_path = temp_env
    config = decoy_config(temp_dir, telemetry_path, max_conns_per_ip=1)

    async def scenario():
        server = DecoyServer(host="127.0.0.1", config=config)
        telnet = await TelnetDecoy(server).start(server._listening_socket(0))
        port = telnet.sockets[0].getsockname()[1]
        try:
            def clients():
                first = Client(port)
                first.read_until("login: ")
                second = Client(port)  # over the per-IP limit: dropped without a banner
                limited = second.closed()
                first.sock.close()
                time.sleep(0.3)
                server.defense.block_actor("TA-001")
                server.defense.ban_ip("127.0.0.1", "TA-001")
                third = Client(port)
                return limited, third.closed(), third.seen
            return await asyncio.wait_for(asyncio.to_thread(clients), 30), server.defense.events()
        finally:
            telnet.close()

    (limited, banned, banner), events = asyncio.run(scenario())
    assert limited and banned and banner == b""
    refused = events[events["kind"] == "refused"]
    assert refused["protocol"].tolist() == ["TELNET"]


def test_t8_defence_can_cut_a_telnet_session(temp_env):
    temp_dir, telemetry_path = temp_env
    config = decoy_config(temp_dir, telemetry_path)

    async def scenario():
        server = DecoyServer(host="127.0.0.1", config=config)
        telnet = await TelnetDecoy(server).start(server._listening_socket(0))
        port = telnet.sockets[0].getsockname()[1]
        try:
            def attacker():
                c = Client(port)
                c.login("root", "root")
                prompt = "root@srv-prod-01:~# "
                c.read_until(prompt)
                for cmd in ("id", "uname -a", "ls"):
                    c.run(cmd, prompt)
                return c
            c = await asyncio.wait_for(asyncio.to_thread(attacker), 30)
            (sid, session), = server.active.items()
            server.defense.set_setting("min_commands", 3)
            server.defense.block_actor("TA-007")
            sessions = pd.DataFrame({"session_id": [sid], "threat_actor_id": ["TA-007"], "num_commands": [3]})
            cut = server.defense.enforce(sessions, server.active, set())
            closed = await asyncio.to_thread(c.closed)
            return cut, closed, server.defense.events()
        finally:
            telnet.close()

    cut, closed, events = asyncio.run(scenario())
    assert cut == 1 and closed
    assert set(events[events["kind"] == "cut"]["protocol"]) == {"TELNET"}
