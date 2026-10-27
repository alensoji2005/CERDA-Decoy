"""Replay tab: watch a recorded session the way the attacker saw it (recordings/<session>.cast, see decoy/recorder.py).

Attacker-controlled text is never interpreted: the player puts it on the page with `textContent` after dropping
terminal control sequences, and the event data is embedded as JSON with `<` escaped, so a recorded `</script>`
cannot break out of the page.
"""
import glob
import json
import os
import re

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from src.decoy.recorder import cast_path, read_cast

ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[@-Z\\-_]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
CONTROL = re.compile(r"[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]")


def clean(text: str) -> str:
    """Printable text: ANSI sequences and control characters (except newline and tab) removed, CR LF -> LF."""
    text = ANSI.sub("", text).replace("\r\n", "\n").replace("\r", "")
    return CONTROL.sub("", text)


def transcript(events) -> str:
    """The screen as plain text, with a `[mm:ss.s]` stamp before every command the attacker sent."""
    out = []
    for t, kind, text in events:
        if kind == "i":
            out.append(f"\n[{int(t // 60):02d}:{t % 60:04.1f}] ")
        elif kind == "o":
            out.append(clean(text))
    return "".join(out).strip("\n")


def _json_for_script(data) -> str:
    return json.dumps(data, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e").replace(
        "\u2028", "\\u2028").replace("\u2029", "\\u2029")


PLAYER = """<!doctype html><meta charset="utf-8">
<style>
 body{margin:0;font-family:system-ui,sans-serif;color:#e6e6e6;background:#101418}
 #bar{display:flex;gap:8px;align-items:center;padding:8px;background:#1b222b;flex-wrap:wrap}
 button,select{background:#2a3441;color:#e6e6e6;border:1px solid #3d4a5c;border-radius:4px;padding:4px 10px;cursor:pointer}
 #t{margin-left:auto;font-variant-numeric:tabular-nums;color:#9fb0c3}
 #screen{margin:0;padding:10px;height:__HEIGHT__px;overflow:auto;white-space:pre-wrap;word-break:break-all;
  font:13px/1.35 ui-monospace,Consolas,monospace}
 input[type=range]{flex:1;min-width:120px}
</style>
<div id="bar"><button id="play">Pause</button><button id="restart">Restart</button>
 <select id="speed"><option value="1">1x</option><option value="2">2x</option><option value="5" selected>5x</option>
 <option value="20">20x</option></select>
 <label><input type="checkbox" id="skip" checked> skip pauses over 2 s</label>
 <input type="range" id="seek" min="0" max="1000" value="0"><span id="t">0.0 / 0.0 s</span></div>
<pre id="screen"></pre>
<script>
const EVENTS = __EVENTS__;
const out = EVENTS.filter(e => e[1] === "o");
const total = out.length ? out[out.length - 1][0] : 0;
const ansi = /\\x1b\\[[0-9;?]*[ -\\/]*[@-~]|\\x1b[@-Z\\\\-_]|\\x1b\\][^\\x07\\x1b]*(?:\\x07|\\x1b\\\\)/g;
const screen = document.getElementById("screen"), seek = document.getElementById("seek"), label = document.getElementById("t");
let pos = 0, clock = 0, playing = true, last = performance.now(), shown = "";
function render(text) {
  text = text.replace(ansi, "");
  let buf = "";
  for (const ch of text) {
    if (ch === "\\b" || ch === "\\x7f") buf = buf.slice(0, -1);
    else if (ch === "\\r") continue;
    else if (ch === "\\n" || ch === "\\t" || ch >= " ") buf += ch;
  }
  return buf;
}
function draw(upTo) {
  let text = "";
  for (let i = 0; i < out.length && out[i][0] <= upTo; i++) text += out[i][2];
  shown = render(text);
  screen.textContent = shown;
  screen.scrollTop = screen.scrollHeight;
  label.textContent = Math.min(upTo, total).toFixed(1) + " / " + total.toFixed(1) + " s";
  seek.value = total ? Math.round(1000 * Math.min(upTo, total) / total) : 0;
}
function nextEventTime() { for (const e of out) if (e[0] > clock) return e[0]; return null; }
function tick(now) {
  const dt = (now - last) / 1000; last = now;
  if (playing && clock < total) {
    let step = dt * parseFloat(document.getElementById("speed").value);
    const upcoming = nextEventTime();
    if (document.getElementById("skip").checked && upcoming !== null && upcoming - clock > 2) clock = upcoming - 0.3;
    else clock += step;
    draw(clock);
    if (clock >= total) { playing = false; document.getElementById("play").textContent = "Play"; }
  }
  requestAnimationFrame(tick);
}
document.getElementById("play").onclick = () => {
  if (clock >= total) clock = 0;
  playing = !playing; document.getElementById("play").textContent = playing ? "Pause" : "Play";
};
document.getElementById("restart").onclick = () => { clock = 0; playing = true; document.getElementById("play").textContent = "Pause"; draw(0); };
seek.oninput = () => { clock = total * seek.value / 1000; draw(clock); };
draw(0); requestAnimationFrame(tick);
</script>"""


def player_html(events, height: int = 380) -> str:
    return PLAYER.replace("__EVENTS__", _json_for_script([list(e) for e in events])).replace("__HEIGHT__", str(height))


def recorded_sessions(folder=".") -> set:
    return {os.path.basename(p)[:-5] for p in glob.glob(os.path.join(folder, "recordings", "*.cast"))}


def render_replay_tab(sessions: pd.DataFrame, telemetry: pd.DataFrame, folder="."):
    st.subheader("Session replay")
    st.caption("Replays a recorded session as the attacker saw it, including the delays the decoy added. The decoy "
               "records whole command lines, not keystrokes, so typing speed inside a line is not shown. Files are "
               "standard asciinema `.cast`, openable in any asciinema player.")
    have = recorded_sessions(folder)
    if not have:
        st.info("No recordings yet. Every SSH, Telnet and HTTP session is recorded to recordings/ once the decoy runs.")
        return
    info = {}
    if not sessions.empty:
        info = {r.session_id: r for r in sessions.fillna("").itertuples() if r.session_id in have}
    order = sorted(have, key=lambda s: -os.path.getmtime(cast_path(os.path.join(folder, "recordings"), s)))

    def label(sid):
        r = info.get(sid)
        return sid if r is None else f"{sid} · {r.threat_actor_id} · {r.source_ip} · {r.num_commands} cmds"
    sid = st.selectbox("Session", order, format_func=label, key="replay_session")
    cast = read_cast(cast_path(os.path.join(folder, "recordings"), sid))
    if not cast or not cast["events"]:
        st.warning("This recording is empty or unreadable.")
        return
    duration = cast["events"][-1][0]
    c1, c2, c3 = st.columns(3)
    c1.metric("Protocol", cast["header"].get("env", {}).get("CERDA_PROTOCOL", "?"))
    c2.metric("Commands", sum(1 for e in cast["events"] if e[1] == "i"))
    c3.metric("Duration", f"{duration:.1f} s")
    components.html(player_html(cast["events"]), height=470, scrolling=False)
    with open(cast_path(os.path.join(folder, "recordings"), sid), "rb") as f:
        st.download_button("Download .cast", f.read(), f"{sid}.cast", "application/x-asciicast")
    if telemetry is not None and not telemetry.empty:
        rows = telemetry[telemetry["session_id"] == sid].sort_values("command_index")
        if not rows.empty:
            st.markdown("**What the decoy did to each command**")
            st.dataframe(pd.DataFrame({
                "#": rows["command_index"], "command": rows["command_raw"].map(clean), "regime": rows["regime"],
                "reaction to previous reply (ms)": (rows["delta_t_ns"] / 1e6).round(1)}),
                use_container_width=True, hide_index=True)
    with st.expander("Plain-text transcript"):
        st.code(transcript(cast["events"]), language="text")
