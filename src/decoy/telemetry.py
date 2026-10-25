import os
import sqlite3
import time
from contextlib import closing
import pandas as pd
from dataclasses import dataclass
from typing import Optional
import threading

@dataclass
class TelemetryEvent:
    session_id: str
    timestamp_ns: int
    source_ip: str
    protocol: str
    command_index: int
    command_raw: str
    command_root: str
    current_path: str
    regime: str
    delta_t_ns: int
    response_sent: bool

class TelemetryLogger:
    """Appends command events to CSV, or to a SQLite table when filepath ends in ".db"
    (WAL mode; indexed by session, so analytics can read it while the decoy writes)."""

    COLUMNS = ["session_id", "timestamp_ns", "source_ip", "protocol", "command_index", "command_raw",
               "command_root", "current_path", "regime", "delta_t_ns", "response_sent"]

    def __init__(self, filepath: str = "telemetry.csv"):
        self.filepath = filepath
        self._lock = threading.Lock()
        self._sqlite = filepath.endswith(".db")
        if self._sqlite:
            with closing(sqlite3.connect(filepath)) as db:
                db.execute("PRAGMA journal_mode=WAL")
                db.execute("CREATE TABLE IF NOT EXISTS telemetry (session_id TEXT, timestamp_ns INTEGER, "
                           "source_ip TEXT, protocol TEXT, command_index INTEGER, command_raw TEXT, "
                           "command_root TEXT, current_path TEXT, regime TEXT, delta_t_ns INTEGER, "
                           "response_sent INTEGER)")
                db.execute("CREATE INDEX IF NOT EXISTS ix_telemetry_session ON telemetry (session_id, command_index)")
        else:
            self._ensure_header()
        
    def _ensure_header(self):
        if not os.path.exists(self.filepath):
            df = pd.DataFrame(columns=[
                "session_id", "timestamp_ns", "source_ip", "protocol",
                "command_index", "command_raw", "command_root",
                "current_path", "regime", "delta_t_ns", "response_sent"
            ])
            df.to_csv(self.filepath, index=False)
            
    def log_event(self, event: TelemetryEvent):
        if self._sqlite:
            row = tuple(event.__dict__[c] for c in self.COLUMNS)
            with self._lock, closing(sqlite3.connect(self.filepath)) as db, db:
                db.execute(f"INSERT INTO telemetry VALUES ({','.join('?' * len(row))})", row)
            return
        df = pd.DataFrame([event.__dict__])
        with self._lock:
            df.to_csv(self.filepath, mode='a', header=False, index=False)

@dataclass
class RegimeScheduleEvent:
    session_id: str
    seed: int
    command_index_start: int
    command_index_end: int
    regime: str

class RegimeScheduleLogger:
    def __init__(self, filepath: str = "regime_schedule.csv"):
        self.filepath = filepath
        self._lock = threading.Lock()
        self._ensure_header()
        
    def _ensure_header(self):
        if not os.path.exists(self.filepath):
            df = pd.DataFrame(columns=[
                "session_id", "seed", "command_index_start", 
                "command_index_end", "regime"
            ])
            with self._lock:
                df.to_csv(self.filepath, index=False)
            
    def log_event(self, event: RegimeScheduleEvent):
        df = pd.DataFrame([event.__dict__])
        with self._lock:
            df.to_csv(self.filepath, mode='a', header=False, index=False)


@dataclass
class AuthEvent:
    session_id: str
    timestamp_ns: int
    source_ip: str
    protocol: str
    username: str
    password: str
    client_version: str
    accepted: bool


class AuthLogger:
    """Appends every login attempt (credential intelligence) to a CSV."""
    COLUMNS = list(AuthEvent.__dataclass_fields__)

    def __init__(self, filepath: str = "auth.csv"):
        self.filepath = filepath
        self._lock = threading.Lock()
        if not os.path.exists(self.filepath):
            pd.DataFrame(columns=self.COLUMNS).to_csv(self.filepath, index=False)

    def log_event(self, event: AuthEvent):
        df = pd.DataFrame([event.__dict__])
        with self._lock:
            df.to_csv(self.filepath, mode='a', header=False, index=False)
