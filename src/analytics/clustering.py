import sqlite3
import time
from typing import List, Tuple, Dict

def hamming_distance(h1: str, h2: str) -> int:
    b1 = bin(int(h1, 16))[2:].zfill(64)
    b2 = bin(int(h2, 16))[2:].zfill(64)
    return sum(c1 != c2 for c1, c2 in zip(b1, b2))

class CERFClusterer:
    def cluster_sessions(self, session_cerfs: List[Tuple[str, str]], threshold: int = 4) -> Dict[str, str]:
        """Clusters session IDs into Threat Actor IDs based on CERF hash Hamming distance <= 4."""
        clusters = {}
        ta_counter = 1
        session_to_ta = {}
        
        for session_id, cerf in session_cerfs:
            assigned = False
            for c_id, c_cerf in clusters.items():
                if hamming_distance(cerf, c_cerf) <= threshold:
                    session_to_ta[session_id] = c_id
                    assigned = True
                    break
            if not assigned:
                new_ta_id = f"TA-{ta_counter:03d}"
                clusters[new_ta_id] = cerf
                session_to_ta[session_id] = new_ta_id
                ta_counter += 1
                
        return session_to_ta


class ActorRegistry:
    """Persistent threat-actor IDs (SQLite).

    Stateless clustering renumbers actors whenever the data or session order changes.
    The registry fixes an actor's leader hash when it is created and keeps each session's
    assignment, so a TA-xxx ID means the same actor across runs and restarts. A session is
    only re-matched while it is still growing (its command count changed); if that leaves
    its old actor empty, the empty actor is dropped.
    """

    def __init__(self, path: str):
        self.db = sqlite3.connect(path)
        self.new_actors = set()  # actors created by the latest assign() call: novel attackers
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS actors (id TEXT PRIMARY KEY, cerf TEXT NOT NULL, created_at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY, actor_id TEXT NOT NULL, num_commands INTEGER NOT NULL);
        """)

    def assign(self, sessions: List[Tuple[str, str, int]], threshold: int) -> Dict[str, str]:
        """sessions: (session_id, cerf, num_commands) -> {session_id: actor_id}."""
        result = {}
        self.new_actors = set()
        with self.db:
            for session_id, cerf, n in sessions:
                row = self.db.execute("SELECT actor_id, num_commands FROM sessions WHERE session_id=?",
                                      (session_id,)).fetchone()
                if row and row[1] == n:
                    result[session_id] = row[0]
                    continue
                if row:
                    self.db.execute("DELETE FROM sessions WHERE session_id=?", (session_id,))
                    self.db.execute("DELETE FROM actors WHERE id=? AND NOT EXISTS "
                                    "(SELECT 1 FROM sessions WHERE actor_id=?)", (row[0], row[0]))
                actor = self._match(cerf, threshold) or self._create(cerf)
                self.db.execute("INSERT INTO sessions VALUES (?,?,?)", (session_id, actor, n))
                result[session_id] = actor
        return result

    def _match(self, cerf: str, threshold: int):
        for actor_id, leader in self.db.execute("SELECT id, cerf FROM actors ORDER BY id"):
            if hamming_distance(cerf, leader) <= threshold:
                return actor_id
        return None

    def _create(self, cerf: str) -> str:
        last = self.db.execute("SELECT MAX(id) FROM actors").fetchone()[0]
        actor_id = f"TA-{(int(last[3:]) + 1 if last else 1):03d}"
        self.db.execute("INSERT INTO actors VALUES (?,?,?)", (actor_id, cerf, time.time()))
        self.new_actors.add(actor_id)
        return actor_id

    def new_actors_per_day(self) -> Dict[str, int]:
        """UTC date -> actors first seen that day. A rising rate means attackers the model has not
        seen before (a new campaign, or drift in how known attackers behave)."""
        rows = self.db.execute("SELECT strftime('%Y-%m-%d', created_at, 'unixepoch') AS d, COUNT(*) "
                               "FROM actors GROUP BY d ORDER BY d")
        return dict(rows)

    def close(self):
        self.db.close()
