"""Session recording: one asciinema-v2 `.cast` file per session, so an analyst can replay what the attacker saw.

Format: first line a JSON header, then one JSON array per event `[seconds_since_start, "o" | "i", text]`
(https://docs.asciinema.org/manual/asciicast/v2/). `o` is what the terminal showed, `i` is what the attacker sent.
Any asciinema player opens the file, and so does the dashboard's Replay tab.

Shell sessions (SSH, Telnet) are recorded at DecoySession level: each command line is one `i` event (the decoy sees
whole lines, not keystrokes, so per-key typing times are not available) followed by an `o` event with the echoed
command and the output. HTTP has no terminal: each request becomes a `$ METHOD /path` line and its reply a status line.

Files are named after the server-generated session id, written append-only, capped per session and in total.
"""
import json
import os
import re
import threading
import time
from typing import Dict, Optional

SAFE_ID = re.compile(r"[^A-Za-z0-9_.-]")


def cast_path(directory: str, session_id: str) -> str:
    return os.path.join(directory, SAFE_ID.sub("_", session_id) + ".cast")


class SessionRecorder:
    def __init__(self, directory: str = "recordings", max_session_bytes: int = 1024 * 1024,
                 max_total_bytes: int = 500 * 1024 * 1024):
        self.dir = directory
        self.max_session_bytes, self.max_total_bytes = max_session_bytes, max_total_bytes
        self._lock = threading.Lock()
        self._open: Dict[str, dict] = {}  # session_id -> {start, bytes}
        self._total = 0
        if os.path.isdir(self.dir):
            self._total = sum(e.stat().st_size for e in os.scandir(self.dir) if e.is_file())

    def start(self, session_id: str, protocol: str, source_ip: str, width: int = 80, height: int = 24):
        """Begin a recording (idempotent: a session that is already open, or already has a file, is left alone)."""
        with self._lock:
            if session_id in self._open:
                return
            path = cast_path(self.dir, session_id)
            os.makedirs(self.dir, exist_ok=True)
            self._open[session_id] = {"start": time.monotonic(), "bytes": 0}
            if os.path.exists(path):  # e.g. an HTTP session that was closed idle and came back: keep one file
                self._open[session_id]["start"] = time.monotonic() - self._last_time(path)
                return
            header = json.dumps({"version": 2, "width": width, "height": height, "timestamp": int(time.time()),
                                 "title": f"{protocol} session from {source_ip}",
                                 "env": {"TERM": "xterm", "CERDA_SESSION": session_id, "CERDA_PROTOCOL": protocol}})
            self._append(session_id, path, header + "\n")

    @staticmethod
    def _last_time(path: str) -> float:
        try:
            with open(path, "rb") as f:
                f.seek(max(0, os.path.getsize(path) - 4096))
                last = [ln for ln in f.read().splitlines() if ln.startswith(b"[")][-1]
            return float(json.loads(last)[0])
        except (OSError, ValueError, IndexError):
            return 0.0

    def _append(self, session_id: str, path: str, text: str) -> bool:
        size = len(text.encode("utf-8", "replace"))
        state = self._open[session_id]
        if state["bytes"] + size > self.max_session_bytes or self._total + size > self.max_total_bytes:
            return False
        with open(path, "a", encoding="utf-8", errors="replace", newline="") as f:
            f.write(text)
        state["bytes"] += size
        self._total += size
        return True

    def event(self, session_id: str, kind: str, text: str):
        """kind: "o" (shown to the attacker) or "i" (sent by the attacker)."""
        if not text:
            return
        with self._lock:
            state = self._open.get(session_id)
            if state is None:
                return
            line = json.dumps([round(time.monotonic() - state["start"], 6), kind, text], ensure_ascii=False)
            self._append(session_id, cast_path(self.dir, session_id), line + "\n")

    def output(self, session_id: str, text: str):
        self.event(session_id, "o", text)

    def command(self, session_id: str, line: str):
        """An attacker command line: recorded as input, and echoed to the screen as a terminal would."""
        self.event(session_id, "i", line + "\r")
        self.event(session_id, "o", line + "\r\n")

    def close(self, session_id: str):
        with self._lock:
            self._open.pop(session_id, None)


def read_cast(path: str) -> Optional[dict]:
    """{"header": dict, "events": [(t, kind, text)]} or None if the file is unreadable. Bad lines are skipped."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
        header = json.loads(lines[0])
    except (OSError, ValueError, IndexError):
        return None
    events = []
    for line in lines[1:]:
        try:
            t, kind, text = json.loads(line)
            events.append((float(t), str(kind), str(text)))
        except (ValueError, TypeError):
            continue
    return {"header": header, "events": events}
