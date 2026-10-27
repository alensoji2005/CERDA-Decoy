"""The perturbation schedule the live decoy applies to treatment sessions.

One definition, imported by the decoy (as its default), by the synthetic simulator and by the
analytics, so the data the model is trained on has the layout the decoy actually produces.
Regime names are the values of `src.decoy.perturbation.Regime`.

Pairing convention in the telemetry: the row for command k carries the regime applied to the
response to command k, while its delta_t is the attacker's reaction to the response to command
k-1. The regime a delta_t reacts to is therefore the previous row's regime (`reaction_regime`).
Command 0 has no preceding response: its delta_t runs from the start of the session and is
treated as missing by the analytics.
"""

LIVE_SCHEDULE = ((0, "baseline"), (2, "slowdown"), (4, "jitter"), (6, "fs_latency"))


def regime_at(cmd_index: int) -> str:
    """Name of the regime applied to the response to command `cmd_index`."""
    regime = LIVE_SCHEDULE[0][1]
    for start, name in LIVE_SCHEDULE:
        if cmd_index >= start:
            regime = name
    return regime


def reaction_regime(cmd_index: int):
    """Regime of the response that command `cmd_index`'s delta_t reacts to (None for command 0)."""
    return regime_at(cmd_index - 1) if cmd_index > 0 else None
