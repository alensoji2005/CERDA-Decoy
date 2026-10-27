"""Defence tests: block an actor, cut its live sessions, ban its addresses, never touch other actors."""
import asyncio
import os
import shutil
import tempfile
import time

import pandas as pd
import pytest

from src.decoy.defense import DefenseStore


class FakeSession:
    def __init__(self, ip, cmds, protocol="SSH"):
        self.source_ip, self.cmd_index, self.protocol = ip, cmds, protocol
        self.cut, self.dropped = False, False
        self.last_activity = time.monotonic()
        self.terminate = lambda: setattr(self, "dropped", True)


@pytest.fixture
def store():
    d = tempfile.mkdtemp()
    yield DefenseStore(os.path.join(d, "defense.db"))
    shutil.rmtree(d, ignore_errors=True)


def sessions_df(rows):
    return pd.DataFrame(rows, columns=["session_id", "threat_actor_id", "num_commands"])


def test_d1_blocked_actor_is_cut_after_enough_commands_and_ip_banned(store):
    store.set_setting("min_commands", 15)
    store.block_actor("TA-001")
    df = sessions_df([("s1", "TA-001", 20), ("s2", "TA-002", 20), ("s3", "TA-001", 20)])
    active = {"s1": FakeSession("10.0.0.1", 20), "s2": FakeSession("10.0.0.2", 20), "s3": FakeSession("10.0.0.3", 5)}
    assert store.enforce(df, active, set()) == 1
    assert active["s1"].cut and active["s1"].dropped          # blocked actor, enough commands: cut
    assert not active["s2"].cut                               # another actor is left alone
    assert not active["s3"].cut                               # too few commands to trust the fingerprint yet
    assert store.banned_ips() == {"10.0.0.1": "TA-001"}
    ev = store.events()
    cut = ev[ev["kind"] == "cut"].iloc[0]
    assert cut["ip"] == "10.0.0.1" and cut["actor"] == "TA-001" and cut["commands"] == 20
    # a second pass does not cut the same session twice
    assert store.enforce(df, active, set()) == 0


def test_d1b_idle_sessions_are_not_cut(store):
    store.set_setting("min_commands", 10)
    store.block_actor("TA-001")
    idle = FakeSession("10.0.0.5", 20)
    idle.last_activity = time.monotonic() - 60               # finished long ago, still in memory
    assert store.enforce(sessions_df([("s9", "TA-001", 20)]), {"s9": idle}, set()) == 0
    assert not idle.cut and not idle.dropped


def test_d2_unblocking_lifts_the_ip_ban(store):
    store.block_actor("TA-001")
    store.ban_ip("10.0.0.1", "TA-001")
    store._banned_cache = (0.0, {})
    assert "10.0.0.1" in store.banned_ips()
    store.unblock_actor("TA-001")
    assert store.banned_ips() == {}


def test_d3_canary_rule_blocks_the_actor_only_when_enabled(store):
    store.set_setting("min_commands", 10)
    df = sessions_df([("s1", "TA-005", 12)])
    active = {"s1": FakeSession("10.0.0.9", 12)}
    store.enforce(df, active, {"s1"})
    assert store.blocked_actors() == {}                       # rule is off by default
    store.set_setting("auto_block_on_canary", 1)
    assert store.enforce(df, active, {"s1"}) == 1
    assert "TA-005" in store.blocked_actors()
    assert active["s1"].cut


def test_d4_policy_is_shared_between_processes_and_events_only_grow(store):
    other = DefenseStore(store.path)                          # a second handle, like the dashboard
    other.block_actor("TA-007", "analyst")
    assert "TA-007" in store.blocked_actors()
    n = len(store.events())
    store.block_actor("TA-007")                               # blocking twice must not duplicate or erase anything
    assert len(store.events()) == n


def test_d5_banned_address_is_refused_at_the_door_over_ssh_and_http(store):
    """End to end: once TA-001's address is banned, a new SSH or HTTP connection from it is dropped."""
    import http.client
    import paramiko
    from src.decoy import DecoyServer
    from tests.test_decoy import decoy_config
    temp_dir = tempfile.mkdtemp()
    config = decoy_config(temp_dir, os.path.join(temp_dir, "t.csv"))

    def clients(ports):
        refused = []
        for _ in range(2):
            try:
                t = paramiko.Transport(("127.0.0.1", ports["ssh"]))
                t.connect()
                refused.append(False)
                t.close()
            except (paramiko.SSHException, OSError, EOFError):
                refused.append(True)
        try:
            c = http.client.HTTPConnection("127.0.0.1", ports["http"], timeout=5)
            c.request("GET", "/")
            c.getresponse().read()
            http_refused = False
        except (http.client.HTTPException, OSError):
            http_refused = True
        return refused, http_refused

    async def scenario():
        server = DecoyServer(host="127.0.0.1", config=config)
        ssh, http_srv, telnet = await server.start_listeners()
        ports = {"ssh": ssh.sockets[0].getsockname()[1], "http": http_srv.sockets[0].getsockname()[1]}
        try:
            # first connection works, then the actor is blocked and its address banned
            def first():
                t = paramiko.Transport(("127.0.0.1", ports["ssh"]))
                t.connect()                                   # not banned yet: the handshake works
                t.close()
            await asyncio.to_thread(first)
            server.defense.block_actor("TA-001")
            server.defense.ban_ip("127.0.0.1", "TA-001")
            result = await asyncio.wait_for(asyncio.to_thread(clients, ports), timeout=60)
            return result, server.defense.events()
        finally:
            ssh.close()
            telnet.close()
            await http_srv.close()

    try:
        (refused, http_refused), events = asyncio.run(scenario())
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
    assert refused == [True, True]
    assert http_refused
    assert (events["kind"] == "refused").any()
