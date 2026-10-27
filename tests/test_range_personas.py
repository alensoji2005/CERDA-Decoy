"""The dashboard launches scripts/live_range.py; its Telnet and webshell attackers must work against the real decoy
and leave what the new features promise (quarantined binary, linked sessions)."""
import importlib.util
import json
import os

import pandas as pd

from tests.test_decoy import _run_with_decoy, temp_env  # noqa: F401  (temp_env is a fixture)

SPEC = importlib.util.spec_from_file_location("cerda_live_range_test", os.path.join(os.path.dirname(__file__), "..", "scripts", "live_range.py"))
RANGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RANGE)


def test_r1_iotbot_and_webshell_personas_against_the_real_decoy(temp_env):
    temp_dir, telemetry_path = temp_env
    iot, shell = RANGE.ALL["iotbot"], RANGE.ALL["webshell"]
    iot.prepare()
    shell.prepare()
    assert "iotbot" in RANGE.DEFAULT_KEYS and "webshell" in RANGE.DEFAULT_KEYS and iot.kind == "telnet"

    def attack(ports):
        RANGE.run_telnet(iot, "127.31.1.1", ports["telnet"])
        RANGE.run_http(shell, "127.31.1.2", ports["http"])
        return dict(RANGE.OUTCOMES)

    outcomes = _run_with_decoy(temp_dir, telemetry_path, attack, control_fraction=1.0)  # no perturbation: fast
    assert [outcomes[ip]["outcome"] for ip in ("127.31.1.1", "127.31.1.2")] == ["completed", "completed"]
    telemetry = pd.read_csv(telemetry_path)
    assert set(telemetry["protocol"]) == {"TELNET", "HTTP"}
    samples = pd.DataFrame([json.loads(line) for line in open(os.path.join(temp_dir, "samples.jsonl"))])
    elf = samples[(samples["protocol"] == "TELNET") & (samples["type"] == "elf")]
    assert len(elf) == 1 and elf["size"].iloc[0] == 512  # the binary the bot built with echo, byte for byte
    uploads = samples[samples["origin"] == "upload"]
    assert len(uploads) == 2 and uploads["sha256"].nunique() == 1  # PUT and multipart carry the same webshell
    assert os.path.exists(os.path.join(temp_dir, "quarantine", elf["sha256"].iloc[0]))


def test_r2_tunneler_persona_uploads_relays_and_runs_commands(temp_env):
    temp_dir, telemetry_path = temp_env
    tunneler = RANGE.ALL["tunneler"]
    tunneler.prepare()
    assert tunneler.kind == "tunnel" and "tunneler" in RANGE.DEFAULT_KEYS

    def attack(ports):
        RANGE.run_tunnel(tunneler, "127.32.1.1", ports["ssh"])
        return dict(RANGE.OUTCOMES)

    outcomes = _run_with_decoy(temp_dir, telemetry_path, attack, control_fraction=1.0)
    assert outcomes["127.32.1.1"]["outcome"] == "completed" and outcomes["127.32.1.1"]["sent"] == tunneler.planned() == len(tunneler.cmds)
    samples = pd.DataFrame([json.loads(line) for line in open(os.path.join(temp_dir, "samples.jsonl"))])
    assert (samples["origin"] == "upload").sum() == 1 and (samples["origin"] == "forward").sum() == 3
    assert set(samples[samples["origin"] == "forward"]["source"]) == {f"{h}:{p}" for h, p in tunneler.targets}
    telemetry = pd.read_csv(telemetry_path)
    assert telemetry["command_raw"].tolist() == tunneler.cmds  # the exec channel ran as one decoy session
