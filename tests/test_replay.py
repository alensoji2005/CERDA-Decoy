"""Gap 2: session recording (src/decoy/recorder.py) and the Replay tab (src/dashboard/replay.py)."""
import asyncio
import json
import os
import shutil
import subprocess
import urllib.request

import pandas as pd
import pytest

from src.dashboard.replay import clean, player_html, transcript
from src.decoy import DecoyServer
from src.decoy.recorder import SessionRecorder, cast_path, read_cast
from tests.test_decoy import _run_with_decoy, decoy_config, temp_env  # noqa: F401  (temp_env is a fixture)
from tests.test_telnet import Client


def test_p1_recorder_format_caps_and_filenames(temp_env):
    temp_dir, _ = temp_env
    rec = SessionRecorder(os.path.join(temp_dir, "rec"), max_session_bytes=400, max_total_bytes=10_000)
    rec.start("session_ab12", "SSH", "1.2.3.4")
    rec.start("session_ab12", "SSH", "1.2.3.4")  # idempotent: one header
    rec.output("session_ab12", "prompt$ ")
    rec.command("session_ab12", "ls -la")
    rec.output("session_ab12", "total 0\r\n")
    cast = read_cast(cast_path(rec.dir, "session_ab12"))
    assert cast["header"]["version"] == 2 and cast["header"]["env"]["CERDA_PROTOCOL"] == "SSH"
    assert [(k, t) for _, k, t in cast["events"]] == [("o", "prompt$ "), ("i", "ls -la\r"), ("o", "ls -la\r\n"), ("o", "total 0\r\n")]
    assert all(a[0] <= b[0] for a, b in zip(cast["events"], cast["events"][1:]))  # time only moves forward
    for _ in range(50):  # per-session cap: the file stops growing, nothing raises
        rec.output("session_ab12", "x" * 50)
    assert os.path.getsize(cast_path(rec.dir, "session_ab12")) <= 400
    # a hostile id cannot leave the recordings folder
    rec.start("../../evil", "SSH", "1.2.3.4")
    assert os.path.dirname(os.path.abspath(cast_path(rec.dir, "../../evil"))) == os.path.abspath(rec.dir)
    assert all(os.path.dirname(os.path.abspath(p.path)) == os.path.abspath(rec.dir) for p in os.scandir(rec.dir))
    # events for sessions that were never started or are closed are ignored
    rec.close("session_ab12")
    rec.output("session_ab12", "late")
    rec.output("never_started", "x")
    assert not os.path.exists(cast_path(rec.dir, "never_started"))
    # total cap
    small = SessionRecorder(os.path.join(temp_dir, "rec2"), max_total_bytes=200)
    small.start("s1", "SSH", "1.1.1.1")
    small.output("s1", "y" * 500)
    assert sum(e.stat().st_size for e in os.scandir(small.dir)) <= 200


def test_p2_reopened_session_continues_the_same_file(temp_env):
    temp_dir, _ = temp_env
    rec = SessionRecorder(os.path.join(temp_dir, "rec"))
    rec.start("http_1", "HTTP", "9.9.9.9")
    rec.output("http_1", "a")
    rec.close("http_1")
    rec2 = SessionRecorder(rec.dir)  # e.g. the decoy restarted, or the HTTP session went idle and came back
    rec2.start("http_1", "HTTP", "9.9.9.9")
    rec2.output("http_1", "b")
    cast = read_cast(cast_path(rec.dir, "http_1"))
    assert [e[2] for e in cast["events"]] == ["a", "b"] and cast["events"][1][0] >= cast["events"][0][0]
    assert open(cast_path(rec.dir, "http_1")).read().count('"version"') == 1


def _casts(temp_dir):
    folder = os.path.join(temp_dir, "recordings")
    return {f[:-5]: read_cast(os.path.join(folder, f)) for f in os.listdir(folder)}


def test_p3_shell_session_is_recorded_with_commands_and_output(temp_env):
    temp_dir, telemetry_path = temp_env
    decoy = DecoyServer(host="127.0.0.1", config=decoy_config(temp_dir, telemetry_path))

    async def scenario():
        async def lines():
            for cmd in ("whoami", "", "uname -a", "exit"):
                yield cmd

        async def drain():
            pass
        shown = []
        await decoy.run_session(lines(), shown.append, drain, "SSH", "203.0.113.5", prompt=lambda fs: "u@h:~$ ",
                                session_id="session_test0001")
        return "".join(shown)

    shown = asyncio.run(scenario())
    cast = _casts(temp_dir)["session_test0001"]
    kinds = [e[1] for e in cast["events"]]
    assert kinds.count("i") == 3  # whoami, uname -a, exit (the blank line is not a command)
    screen = transcript(cast["events"])
    assert "whoami\nuser" in screen and "Linux" in screen and "u@h:~$" in screen
    assert clean("".join(e[2] for e in cast["events"] if e[1] == "o")).replace("\n", "") != ""
    assert "Linux" in shown  # recording changes nothing the attacker sees


def test_p4_telnet_and_http_sessions_are_recorded(temp_env):
    temp_dir, telemetry_path = temp_env

    def attack(ports):
        c = Client(ports["telnet"])
        c.login("root", "root")
        c.read_until("root@srv-prod-01:~# ")
        c.run("id", "root@srv-prod-01:~# ")
        for path in ("/wp-login.php", "/nope"):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{ports['http']}{path}").close()
            except urllib.error.HTTPError:
                pass
        return True

    assert _run_with_decoy(temp_dir, telemetry_path, attack)
    casts = _casts(temp_dir)
    protocols = {c["header"]["env"]["CERDA_PROTOCOL"]: c for c in casts.values()}
    assert set(protocols) == {"TELNET", "HTTP"}
    assert "uid=0(root)" in transcript(protocols["TELNET"]["events"])
    http = transcript(protocols["HTTP"]["events"])
    assert "GET /wp-login.php" in http and "HTTP 200 text/html" in http and "HTTP 404" in http


def test_p5_recording_can_be_turned_off(temp_env):
    temp_dir, telemetry_path = temp_env
    decoy = DecoyServer(host="127.0.0.1", config=decoy_config(temp_dir, telemetry_path, recordings_dir=""))
    assert decoy.recorder is None

    async def scenario():
        async def lines():
            yield "id"

        async def drain():
            pass
        await decoy.run_session(lines(), lambda _: None, drain, "SSH", "203.0.113.5", prompt=None)
    asyncio.run(scenario())
    assert not os.path.exists(os.path.join(temp_dir, "recordings"))


def test_p6_player_does_not_let_recorded_text_break_the_page():
    hostile = [(0.0, "o", "</script><img src=x onerror=alert(1)>\u2028"), (1.0, "o", "\x1b[31mred\x1b[0m")]
    html = player_html(hostile)
    assert html.count("<script>") == 1 and html.count("</script>") == 1  # the payload could not close the tag
    assert "<img" not in html and "\\u003c/script\\u003e" in html
    assert clean("\x1b[31mred\x1b[0m\x07\x00 ok\r\nnext") == "red ok\nnext"


@pytest.mark.skipif(shutil.which("node") is None, reason="node is needed to run the player script")
def test_p7_player_script_replays_what_was_recorded(temp_env):
    """Run the real player script in node against a stubbed page and read the screen after seeking to the end."""
    temp_dir, _ = temp_env
    import re
    events = [(0.0, "o", "$ "), (0.5, "o", "lsx\b\r\n"), (1.0, "o", "\x1b[31mfile\x1b[0m\r\n$ ")]
    script = re.search(r"<script>(.*)</script>", player_html(events), re.S).group(1)
    harness = """
const els = {};
const el = (id) => els[id] || (els[id] = {id, textContent: "", value: "0", checked: true, scrollTop: 0, scrollHeight: 0});
global.document = {getElementById: el};
global.performance = {now: () => 0};
global.requestAnimationFrame = () => {};
""" + script + """
el("seek").value = "1000"; el("seek").oninput();
console.log(JSON.stringify(el("screen").textContent));
"""
    path = os.path.join(temp_dir, "player_test.js")
    open(path, "w", encoding="utf-8").write(harness)
    result = subprocess.run(["node", path], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == "$ ls\nfile\n$ "  # backspace applied, colour codes and CR dropped


def test_p8_replay_tab_renders(temp_env):
    from streamlit.testing.v1 import AppTest
    temp_dir, _ = temp_env
    rec = SessionRecorder(os.path.join(temp_dir, "recordings"))
    rec.start("session_demo0001", "SSH", "8.8.8.8")
    rec.output("session_demo0001", "u@h:~$ ")
    rec.command("session_demo0001", "id")
    rec.output("session_demo0001", "uid=1000(u)\r\nu@h:~$ ")
    script = f"""
import sys; sys.path.insert(0, r'{os.getcwd()}')
import pandas as pd
from src.dashboard.replay import render_replay_tab
s = pd.DataFrame({{'session_id': ['session_demo0001'], 'threat_actor_id': ['TA-0001'], 'source_ip': ['8.8.8.8'], 'num_commands': [1]}})
t = pd.DataFrame({{'session_id': ['session_demo0001'], 'command_index': [0], 'command_raw': ['id'], 'regime': ['baseline'], 'delta_t_ns': [5_000_000]}})
render_replay_tab(s, t, folder=r'{temp_dir}')
"""
    at = AppTest.from_string(script).run(timeout=60)
    assert not at.exception
    assert [(m.label, m.value) for m in at.metric] == [("Protocol", "SSH"), ("Commands", "1"), ("Duration", at.metric[2].value)]
    assert len(at.get("download_button")) == 1 and len(at.dataframe) == 1
    empty = AppTest.from_string(script.replace(temp_dir, os.path.join(temp_dir, "nothing"))).run(timeout=60)
    assert not empty.exception and "No recordings yet" in empty.info[0].value
