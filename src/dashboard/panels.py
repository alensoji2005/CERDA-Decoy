"""Dashboard panels for the live demo: launch simulated attacks, and block attackers.

Everything here works on the folder the dashboard was started in (the same folder as the decoy), and only ever
adds to it: attacks append to telemetry/auth/alerts and to range_truth.csv, every run gets its own record in
range_runs/, and the defence keeps an append-only event log in defense.db.
"""
import glob
import importlib.util
import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime

import pandas as pd
import streamlit as st

from src.analytics.blocklist import render_nft
from src.analytics.enrichment import ThreatFeeds, is_public, load_ip_database
from src.analytics.export import build_misp, build_stix
from src.decoy.defense import DefenseStore

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RANGE_SCRIPT = os.path.join(REPO, "scripts", "live_range.py")
HTTP_PORT = 8080
KIND_LABEL = {"cut": "session cut", "refused": "connection refused", "block": "actor blocked",
              "unblock": "actor unblocked"}


@st.cache_resource
def attacker_catalog() -> dict:
    """{key: persona} from scripts/live_range.py (loaded by path; scripts/ is not a package)."""
    spec = importlib.util.spec_from_file_location("cerda_live_range", RANGE_SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.ALL


def decoy_running() -> bool:
    try:
        socket.create_connection(("127.0.0.1", HTTP_PORT), timeout=0.3).close()   # a bare connect is not logged
        return True
    except OSError:
        return False


def _tail(path, n=28) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = [ln.rstrip() for ln in f.readlines() if ln.strip()]
        return "\n".join(lines[-n:])
    except OSError:
        return ""


def _env():
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONPATH=REPO + os.pathsep + os.environ.get("PYTHONPATH", ""))
    env.pop("GEMINI_API_KEY", None)   # the demo always uses the deterministic mock
    return env


def _persona_map(folder) -> dict:
    try:
        t = pd.read_csv(os.path.join(folder, "range_truth.csv"))
        return dict(zip(t["source_ip"], t["persona"]))
    except (OSError, ValueError, pd.errors.EmptyDataError):
        return {}


def with_personas(sdf: pd.DataFrame, folder=".") -> pd.DataFrame:
    """Adds the demo attacker each session really came from (ground truth known only because we scripted it)."""
    if sdf.empty:
        return sdf
    truth = _persona_map(folder)
    if truth:
        sdf = sdf.assign(demo_attacker=sdf["source_ip"].map(truth).fillna("(manual / unknown)"))
    return sdf


# ---------------------------------------------------------------------------------------------------
def render_range_tab(sdf: pd.DataFrame, folder: str = ".") -> None:
    st.subheader("Live Attack Range")
    if not os.path.exists(RANGE_SCRIPT):   # e.g. the Docker image ships no demo attackers (and no second decoy)
        st.info("The demo attack range (scripts/live_range.py) is not part of this installation, so there is nothing to "
                "launch here. Attacks come from the network; sessions appear in the other tabs.")
        return
    st.caption("Launch simulated attackers at the running decoy as many times as you like. Each wave uses new, never-used "
               "addresses and new credentials, and everything it produces is added to the existing data.")
    ss = st.session_state
    running = decoy_running()
    c1, c2, c3 = st.columns([2, 2, 3])
    c1.metric("Decoy", "Online" if running else "Offline")
    c2.metric("Sessions on record", len(sdf))
    own = ss.get("decoy_proc")
    if not running:
        starting = own is not None and own.poll() is None and time.time() - ss.get("decoy_started", 0) < 90
        if starting:
            c3.info("Decoy is starting (loading the models takes up to a minute)...")
        elif c3.button("Start the decoy in this folder", type="primary"):
            log = open(os.path.join(folder, "decoy.log"), "ab")
            ss.decoy_proc = subprocess.Popen([sys.executable, os.path.join(REPO, "decoy_server.py"), "--tarpit"],
                                             cwd=folder, stdout=log, stderr=subprocess.STDOUT, env=_env())
            ss.decoy_started = time.time()
            st.rerun()
    elif own is not None and own.poll() is None and c3.button("Stop the decoy"):
        own.terminate()
        st.rerun()

    catalog = attacker_catalog()
    keys = [k for k in catalog if k != "twin_fast"]
    chosen = st.multiselect("Attackers to send", list(catalog), default=keys,
                            format_func=lambda k: f"{k}: {catalog[k].label}", key="range_personas")
    a1, a2, a3 = st.columns(3)
    per = a1.number_input("Sessions per attacker (0 = random 2 to 4)", 0, 8, 0, key="range_per")
    waves = a2.number_input("Waves in this launch", 1, 4, 1, key="range_waves",
                            help="Waves in one launch run back to back; every wave uses new addresses.")
    reuse = a3.slider("Share returning from an old address", 0.0, 1.0, 0.25, 0.05, key="range_reuse",
                      help="Tests the address ban: a banned address is refused at the door.")

    proc = ss.get("range_proc")
    busy = proc is not None and proc.poll() is None
    b1, b2, _ = st.columns([1, 1, 3])
    if b1.button("Launch attack wave", type="primary", disabled=busy or not running or not chosen):
        os.makedirs(os.path.join(folder, "range_runs"), exist_ok=True)
        ss.range_log = os.path.join(folder, "range_runs", f"launch_{datetime.now():%Y%m%d-%H%M%S}.log")
        cmd = [sys.executable, RANGE_SCRIPT, "--data-dir", folder, "--waves", str(int(waves)), "--no-pause",
               "--personas", ",".join(chosen), "--per-persona", str(int(per)), "--reuse-ips", str(reuse)]
        ss.range_proc = subprocess.Popen(cmd, cwd=folder, stdout=open(ss.range_log, "ab"), stderr=subprocess.STDOUT, env=_env())
        st.rerun()
    if b2.button("Stop this attack", disabled=not busy):
        proc.terminate()
        st.rerun()

    if ss.get("range_log"):
        state = "running..." if busy else f"finished (exit code {proc.poll()})"
        st.markdown(f"**Current launch:** {state}")
        st.code(_tail(ss.range_log) or "(starting)", language="text")

    runs = []
    for path in sorted(glob.glob(os.path.join(folder, "range_runs", "*.json")), reverse=True):
        try:
            r = json.load(open(path, encoding="utf-8"))
            runs.append({"run": r["run_id"], "attackers": len(r["personas"]), "sessions": r["sessions"],
                         "actors found": r["actors"], "cut by defence": r["cut"], "refused": r["refused"],
                         "ARI vs true attackers": r["ari"]})
        except (OSError, ValueError, KeyError):
            continue
    if runs:
        st.markdown("**Earlier runs** (each is kept; none is overwritten)")
        st.dataframe(pd.DataFrame(runs), use_container_width=True, hide_index=True)
    st.caption("Honest note: these attackers are scripts we wrote, so this shows the mechanism working, not accuracy on "
               "real attackers. Web attackers with similar rhythms (the web scanner, exploit prober and WordPress "
               "brute-forcer) tend to merge into one actor; SSH attackers separate much better.")


# ---------------------------------------------------------------------------------------------------
def _alerts_by_session(folder) -> dict:
    out = {}
    try:
        for line in open(os.path.join(folder, "alerts.jsonl"), encoding="utf-8"):
            try:
                a = json.loads(line)
                out[a["session_id"]] = out.get(a["session_id"], 0) + 1
            except (ValueError, KeyError):
                pass
    except OSError:
        pass
    return out


def _cb_block(db_path, actors, ips_of):
    """Block actors and ban every address each has used so far."""
    store = DefenseStore(db_path)
    for a in actors:
        store.block_actor(a)
        for ip in ips_of.get(a, []):
            if ip != "127.0.0.1":   # do not lock out your own manual SSH test unless the defence has to cut it
                store.ban_ip(ip, a)


def _cb_unblock(db_path, actors):
    store = DefenseStore(db_path)
    for a in actors:
        store.unblock_actor(a)


def render_defense_tab(sdf: pd.DataFrame, tdf: pd.DataFrame, folder: str = ".") -> None:
    st.subheader("Defence: stopping an attacker, not just an address")
    store = DefenseStore(os.path.join(folder, "defense.db"))
    s1, s2, s3, s4 = st.columns(4)
    s1.markdown("**1. Observe**  \nThe decoy changes its response timing and records how each attacker's tool reacts.")
    s2.markdown("**2. Identify**  \nThe reaction rhythm becomes a 64-bit CERF hash and a persistent actor ID, even across new IPs.")
    s3.markdown("**3. Decide**  \nYou block an actor, or let a canary trip block it automatically.")
    s4.markdown("**4. Enforce**  \nLive sessions are cut, addresses banned, and the same actor is cut again on any new address.")
    st.caption("The decoy is an isolated sandbox, so enforcement here means evicting the actor from the decoy and producing "
               "the address list for your real firewall (below). Nothing on this computer's firewall is changed.")

    blocked = store.blocked_actors()
    ev = store.events()
    sdf = with_personas(sdf, folder)
    alerts = _alerts_by_session(folder)

    # ---- policy -------------------------------------------------------------------------------------
    st.markdown("### Policy")
    p1, p2 = st.columns(2)
    auto = p1.toggle("Auto-block an actor when it trips a canary (reads bait files or tries a download)",
                     value=store.get_setting("auto_block_on_canary") == "1", key="def_auto")
    if auto != (store.get_setting("auto_block_on_canary") == "1"):
        store.set_setting("auto_block_on_canary", int(auto))
    min_cmds = p2.slider("Commands an actor must run before its fingerprint is trusted", 8, 30,
                         int(store.get_setting("min_commands")), key="def_min",
                         help="The paper found fingerprints are unreliable below about 15 commands, so cutting earlier risks "
                              "cutting the wrong actor.")
    if min_cmds != int(store.get_setting("min_commands")):
        store.set_setting("min_commands", min_cmds)

    if sdf.empty:
        st.info("No attackers recorded yet. Launch a wave on the Live Range tab first.")
        return
    g = sdf.groupby("threat_actor_id")
    table = pd.DataFrame({
        "Sessions": g.size(),
        "Addresses used": g["source_ip"].nunique(),
        "Canary alerts": g["session_id"].apply(lambda s: sum(alerts.get(x, 0) for x in s)),
        "Cut so far": ev[ev["kind"] == "cut"].groupby("actor").size() if not ev.empty else 0,
    }).fillna(0).astype(int)
    if "demo_attacker" in sdf:
        table.insert(0, "Demo attacker (ground truth)", g["demo_attacker"].agg(lambda s: ", ".join(sorted(set(s)))))
    table["Status"] = ["BLOCKED" if a in blocked else "monitored" for a in table.index]
    table = table.sort_values(["Status", "Sessions"], ascending=[True, False])

    st.markdown("### Actors")
    ips_of = {a: list(g["source_ip"].unique()) for a, g in sdf.groupby("threat_actor_id")}
    db = os.path.join(folder, "defense.db")
    tripped = [a for a in table.index if table.loc[a, "Canary alerts"] > 0 and a not in blocked]
    b1, b2, _ = st.columns([2, 2, 3])
    b1.button(f"Block all {len(tripped)} actors that tripped a canary", type="primary", disabled=not tripped,
              on_click=_cb_block, args=(db, tripped, ips_of))
    b2.button("Unblock everything", disabled=not blocked, on_click=_cb_unblock, args=(db, list(blocked)))
    widths = [1.1, 2.6, 0.9, 1.0, 0.9, 0.8, 1.1, 1.1]
    for c, h in zip(st.columns(widths), ["Actor", "Demo attacker (ground truth)", "Sessions", "Addresses", "Canary alerts",
                                         "Cut", "Status", ""]):
        c.markdown(f"**{h}**")
    for a in table.index:
        c = st.columns(widths)
        c[0].write(a)
        c[1].write(table.loc[a, "Demo attacker (ground truth)"] if "Demo attacker (ground truth)" in table else "")
        c[2].write(int(table.loc[a, "Sessions"]))
        c[3].write(int(table.loc[a, "Addresses used"]))
        c[4].write(int(table.loc[a, "Canary alerts"]))
        c[5].write(int(table.loc[a, "Cut so far"]))
        c[6].write(table.loc[a, "Status"])
        if a in blocked:
            c[7].button("Unblock", key=f"unb_{a}", on_click=_cb_unblock, args=(db, [a]))
        else:
            c[7].button("Block", key=f"blk_{a}", on_click=_cb_block, args=(db, [a], ips_of))
    st.caption("Blocking an actor bans every address it has used so far. When it returns on a NEW address, it is let in, "
               "recognised by its rhythm after the minimum number of commands, cut, and that address is banned too. "
               "If a blocked actor includes your own 127.0.0.1 test session, the defence will cut and ban it as well: unblock to continue.")

    # ---- results ------------------------------------------------------------------------------------
    cuts, refused = ev[ev["kind"] == "cut"] if not ev.empty else ev, ev[ev["kind"] == "refused"] if not ev.empty else ev
    banned = store.banned_ips()
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Actors blocked", len(blocked))
    m2.metric("Addresses banned", len(banned))
    m3.metric("Sessions cut mid-attack", len(cuts))
    m4.metric("Connections refused at the door", len(refused))

    st.markdown("### What the defence did")
    if ev.empty:
        st.info("Nothing yet. Block an actor, then launch another wave.")
    else:
        e = ev.sort_values("id", ascending=False).head(200).copy()
        e["time"] = pd.to_datetime(e["ts"], unit="s").dt.strftime("%H:%M:%S")
        e["event"] = e["kind"].map(KIND_LABEL).fillna(e["kind"])
        truth = _persona_map(folder)
        e["demo attacker"] = e["ip"].map(truth).fillna("")
        st.dataframe(e[["time", "event", "actor", "ip", "protocol", "commands", "demo attacker", "detail"]]
                     .rename(columns={"ip": "address", "commands": "commands run"}),
                     use_container_width=True, hide_index=True)

    if not cuts.empty:
        st.markdown("### How much of each attack was prevented")
        first = tdf.groupby("session_id")["timestamp_ns"].min() / 1e9 if not tdf.empty else pd.Series(dtype=float)
        full = {}
        for a, grp in sdf.groupby("threat_actor_id"):
            done = grp[~grp["session_id"].isin(cuts["session_id"])]
            full[a] = done["num_commands"].median() if not done.empty else None
        rows = []
        for _, c in cuts.iterrows():
            f = full.get(c["actor"])
            since = blocked.get(c["actor"], (0, ""))[0]
            known = set(sdf[(sdf["threat_actor_id"] == c["actor"]) & (sdf["session_id"].map(first).fillna(0) < since)]["source_ip"])
            rows.append({"actor": c["actor"], "address": c["ip"], "commands run before cut": c["commands"],
                         "typical full attack": "unknown" if f is None or pd.isna(f) else int(f),
                         "attack prevented": "n/a" if f is None or pd.isna(f) or not f else f"{max(0, 100 - 100 * c['commands'] / f):.0f}%",
                         "address known before block?": "yes (an address list would catch it)" if c["ip"] in known
                         else "NO, new address: caught only by its rhythm"})
        r = pd.DataFrame(rows)
        st.dataframe(r, use_container_width=True, hide_index=True)
        new = int(r["address known before block?"].str.startswith("NO").sum())
        st.success(f"{new} of {len(r)} cuts were on addresses nobody had seen before the block. An IP blocklist built at the "
                   f"time would have missed all {new} of them.")

    # ---- export -------------------------------------------------------------------------------------
    st.markdown("### Take it to the real firewall")
    by_actor = {}
    for ip, a in banned.items():
        by_actor.setdefault(a, []).append(ip)
    rules = render_nft(by_actor)
    st.code(rules, language="text")
    st.download_button("Download nftables rules", rules, file_name="cerda_banned.nft", mime="text/plain")
    st.caption("Review, then apply on a real perimeter yourself (sudo nft -f cerda_banned.nft). The addresses in this demo are "
               "loopback addresses; on a real deployment they are the attackers' public addresses.")


# ---------------------------------------------------------------------------------------------------
def render_malware_tab(sessions: pd.DataFrame, folder="."):
    """Files attackers dropped or uploaded, grouped by SHA-256 (samples.jsonl; the files sit in quarantine/)."""
    st.subheader("Captured malware")
    st.caption("Files an attacker downloaded, uploaded or wrote are stored read-only in quarantine/ under their SHA-256 "
               "and are never executed. The same hash in two sessions is a strong link between them.")
    try:
        rows = [json.loads(line) for line in open(os.path.join(folder, "samples.jsonl"), encoding="utf-8")]
    except (OSError, ValueError):
        rows = []
    if not rows:
        st.info("No samples yet. Shell writes and HTTP uploads are captured; wget/curl targets are only fetched when "
                "the decoy runs with fetch_payloads on (off by default).")
        return
    df = pd.DataFrame(rows)
    kept = df[df["sha256"] != ""]
    failed = df[df["sha256"] == ""]
    actor = dict(zip(sessions["session_id"], sessions["threat_actor_id"])) if not sessions.empty else {}
    c1, c2, c3 = st.columns(3)
    c1.metric("Distinct samples", kept["sha256"].nunique())
    c2.metric("Sightings", len(kept))
    c3.metric("Downloads that failed or were blocked", len(failed))
    if not kept.empty:
        kept = kept.assign(actor=kept["session_id"].map(actor).fillna("?"))
        table = kept.groupby("sha256").agg(
            type=("type", "first"), size=("size", "first"), first_seen=("time", "min"), sightings=("time", "size"),
            sessions=("session_id", "nunique"), actors=("actor", lambda x: ", ".join(sorted(set(x)))),
            sources=("source", lambda x: " | ".join(list(dict.fromkeys(x))[:3]))).reset_index()
        table["lookup"] = "https://www.virustotal.com/gui/file/" + table["sha256"]
        st.dataframe(table.sort_values("first_seen", ascending=False), use_container_width=True, hide_index=True,
                     column_config={"lookup": st.column_config.LinkColumn("VirusTotal", display_text="open")})
    if not failed.empty:
        st.markdown("**Not kept**")
        st.dataframe(failed[["time", "source", "reason", "source_ip"]], use_container_width=True, hide_index=True)


# ---------------------------------------------------------------------------------------------------
def _reputation_cache(ips) -> dict:
    """Answers already stored in enrichment.db for these addresses; makes no request."""
    if not os.path.exists("enrichment.db"):
        return {}
    feeds = ThreatFeeds()
    return {ip: feeds.cached(ip) for ip in ips if is_public(ip) and feeds.cached(ip)}


def render_enrichment_tab(sessions: pd.DataFrame):
    """Country / ASN per actor (offline) and, only when asked, reputation from AbuseIPDB / GreyNoise."""
    st.subheader("Who is behind the addresses")
    db = load_ip_database()
    if db:
        st.caption(f"Offline GeoIP/ASN tables loaded: {', '.join(os.path.basename(p) for p in db.loaded)}. "
                   "Nothing here leaves this computer.")
    else:
        st.warning("No GeoIP/ASN tables installed, so country and ASN stay blank. Run "
                   "`python -m scripts.fetch_enrichment_data` once (public-domain data from iptoasn.com, about 9 MB).")
    if sessions.empty:
        st.info("No sessions yet.")
        return
    sessions = sessions.fillna("")
    for col in ("country", "asn", "as_org"):
        if col not in sessions:
            sessions[col] = ""
    join = lambda x: ", ".join(sorted({str(v) for v in x if str(v)}))
    table = sessions.groupby("threat_actor_id").agg(
        sessions=("session_id", "nunique"), addresses=("source_ip", "nunique"), countries=("country", join),
        asns=("asn", join), organisations=("as_org", join)).reset_index()
    st.dataframe(table, use_container_width=True, hide_index=True)

    st.markdown("**Reputation (optional, sends addresses to third parties)**")
    public = [ip for ip in dict.fromkeys(sessions["source_ip"].astype(str)) if is_public(ip)]
    feeds = ThreatFeeds()
    if not public:
        st.caption("No public addresses in the data (demo traffic comes from loopback), so there is nothing to look up.")
        return
    st.caption(f"{len(public)} public address(es). A lookup sends them to: {', '.join(feeds.feeds)}. "
               "Answers are cached for 7 days and capped at 500 requests per feed per day. "
               "Keys: $ABUSEIPDB_KEY (required for AbuseIPDB), $GREYNOISE_KEY (optional).")
    if st.button(f"Look up {min(len(public), 50)} address(es) now"):
        feeds.lookup_many(public, limit=50)
        for err in dict.fromkeys(feeds.errors):
            st.warning(err)
    cached = _reputation_cache(public)
    if cached:
        st.dataframe(pd.DataFrame([{"ip": ip, **rep} for ip, rep in cached.items()]),
                     use_container_width=True, hide_index=True)


def render_export_tab(sessions: pd.DataFrame, telemetry: pd.DataFrame, cerda_json: str):
    """STIX 2.1, MISP and CERDA-JSON downloads."""
    st.subheader("Threat intelligence output")
    include_private = st.checkbox("Include private / loopback addresses (demo traffic only; never share these)", value=False)
    public = [str(ip) for ip in sessions.get("source_ip", []) if is_public(str(ip))] if not sessions.empty else []
    reputation = _reputation_cache(list(dict.fromkeys(public))) if public else {}
    bundle = build_stix(sessions, telemetry, include_private, reputation)
    stix = json.dumps(bundle, indent=2)
    misp = json.dumps(build_misp(sessions, telemetry, include_private, reputation), indent=2)
    shared = [o for o in bundle["objects"] if o["type"] == "indicator"]
    st.caption(f"{len(shared)} indicator(s) in this export.")
    if not shared:
        st.info("Nothing shareable yet: no public addresses, URLs or payload hashes. Tick the box above to export the "
                "demo (loopback) addresses.")
    c1, c2, c3 = st.columns(3)
    c1.download_button("Download STIX 2.1 bundle", stix, "cerda_stix21.json", "application/json")
    c2.download_button("Download MISP event", misp, "cerda_misp_event.json", "application/json")
    c3.download_button("Download CERDA JSON", cerda_json, "cerda_threat_intel.json", "application/json")
    st.caption("Attribution is statistical (execution rhythm): treat each actor as a lead. The MISP event is tagged "
               "tlp:amber and carries client fingerprints (HASSH, user agent) as context only, not as detections.")
    with st.expander("Preview STIX bundle"):
        st.code(stix[:6000], language="json")
