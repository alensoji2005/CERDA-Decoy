"""Actor-level defence: block a threat actor, not just an address.

An IP blocklist stops an attacker only while they keep the same address. CERDA identifies the
*actor* from the rhythm of their session, so a blocked actor can be recognised again on a brand
new address, cut off mid-session, and have that new address banned as well.

State lives in one SQLite file (defense.db) that the decoy and the dashboard both open:
  blocked_actors  actors the analyst (or the canary rule) blocked
  banned_ips      addresses banned because a blocked actor was seen on them
  settings        auto-block switch and the minimum commands before an actor is trusted
  events          append-only log of everything the defence did (never rewritten)

The decoy is an isolated sandbox, so "stopping" here means evicting the actor from the decoy and
producing the address list for the real perimeter firewall (see analytics/blocklist.py). Nothing
touches the host firewall.
"""
import sqlite3
import threading
import time

import pandas as pd

IDLE_S = 10  # a session silent for longer than this is not "live"
DEFAULTS = {"auto_block_on_canary": "0", "min_commands": "15"}


class DefenseStore:
    def __init__(self, path: str = "defense.db"):
        self.path = path
        self._lock = threading.Lock()
        self._banned_cache = (0.0, {})
        self._refused_at = {}
        with self._db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS blocked_actors (actor TEXT PRIMARY KEY, since REAL, source TEXT);
                CREATE TABLE IF NOT EXISTS banned_ips (ip TEXT PRIMARY KEY, actor TEXT, since REAL);
                CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
                CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, kind TEXT,
                    session_id TEXT, ip TEXT, actor TEXT, protocol TEXT, commands INTEGER, detail TEXT);
            """)

    def _db(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.execute("PRAGMA journal_mode=WAL")
        return db

    # -- settings ----------------------------------------------------------------------------
    def get_setting(self, key: str) -> str:
        with self._db() as db:
            row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row[0] if row else DEFAULTS[key]

    def set_setting(self, key: str, value) -> None:
        with self._db() as db:
            db.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                       (key, str(value)))

    # -- policy ------------------------------------------------------------------------------
    def block_actor(self, actor: str, source: str = "analyst") -> bool:
        with self._db() as db:
            cur = db.execute("INSERT OR IGNORE INTO blocked_actors(actor,since,source) VALUES(?,?,?)",
                             (actor, time.time(), source))
            new = cur.rowcount > 0
        if new:
            self.log("block", actor=actor, detail=source)
        return new

    def unblock_actor(self, actor: str) -> None:
        with self._db() as db:
            db.execute("DELETE FROM blocked_actors WHERE actor=?", (actor,))
        self.log("unblock", actor=actor)
        self._banned_cache = (0.0, {})

    def blocked_actors(self) -> dict:
        with self._db() as db:
            return {a: (since, src) for a, since, src in db.execute("SELECT actor,since,source FROM blocked_actors")}

    def banned_ips(self) -> dict:
        """{ip: actor} for addresses whose actor is still blocked. Cached for half a second."""
        now = time.monotonic()
        if now - self._banned_cache[0] < 0.5:
            return self._banned_cache[1]
        with self._db() as db:
            rows = db.execute("SELECT b.ip, b.actor FROM banned_ips b JOIN blocked_actors a ON a.actor=b.actor").fetchall()
        self._banned_cache = (now, dict(rows))
        return self._banned_cache[1]

    def ban_ip(self, ip: str, actor: str) -> None:
        with self._db() as db:
            db.execute("INSERT INTO banned_ips(ip,actor,since) VALUES(?,?,?) "
                       "ON CONFLICT(ip) DO UPDATE SET actor=excluded.actor", (ip, actor, time.time()))
        self._banned_cache = (0.0, {})

    # -- log ---------------------------------------------------------------------------------
    def log(self, kind: str, session_id: str = "", ip: str = "", actor: str = "", protocol: str = "",
            commands: int = 0, detail: str = "") -> None:
        with self._db() as db:
            db.execute("INSERT INTO events(ts,kind,session_id,ip,actor,protocol,commands,detail) VALUES(?,?,?,?,?,?,?,?)",
                       (time.time(), kind, session_id, ip, actor, protocol, commands, detail))

    def log_refused(self, ip: str, protocol: str) -> None:
        """A banned address tried to connect. Throttled to one log row per address per 5 s."""
        now = time.monotonic()
        if now - self._refused_at.get(ip, -99) < 5:
            return
        if len(self._refused_at) > 10_000:
            self._refused_at.clear()
        self._refused_at[ip] = now
        self.log("refused", ip=ip, actor=self.banned_ips().get(ip, ""), protocol=protocol)

    def events(self) -> pd.DataFrame:
        with self._db() as db:
            return pd.read_sql_query("SELECT * FROM events ORDER BY id", db)

    # -- enforcement ---------------------------------------------------------------------------
    def enforce(self, sessions: pd.DataFrame, active: dict, tripped: set) -> int:
        """Apply the policy to live sessions. `sessions` is the latest CERF result, `active` maps
        session_id -> DecoySession, `tripped` is the set of sessions that touched a canary.
        Returns the number of sessions cut."""
        if sessions is None or sessions.empty:
            return 0
        min_cmds = int(self.get_setting("min_commands"))
        actor_of = dict(zip(sessions["session_id"], sessions["threat_actor_id"]))
        n_cmds = dict(zip(sessions["session_id"], sessions["num_commands"]))
        blocked = self.blocked_actors()
        if self.get_setting("auto_block_on_canary") == "1":
            for sid in tripped:
                actor = actor_of.get(sid)
                if actor and actor not in blocked and n_cmds.get(sid, 0) >= min_cmds:
                    if self.block_actor(actor, "auto: canary tripped"):
                        blocked[actor] = (time.time(), "auto")
        cut = 0
        for sid, session in list(active.items()):
            actor = actor_of.get(sid)
            if time.monotonic() - session.last_activity > IDLE_S:
                continue   # a finished session that only lingers in memory (HTTP): the address ban is enough
            if actor in blocked and not session.cut and session.cmd_index >= min_cmds:
                session.cut = True
                self.ban_ip(session.source_ip, actor)
                self.log("cut", sid, session.source_ip, actor, session.protocol, session.cmd_index,
                         f"actor {actor} blocked; identified from rhythm after {session.cmd_index} commands")
                if session.terminate:
                    session.terminate()
                cut += 1
        return cut
