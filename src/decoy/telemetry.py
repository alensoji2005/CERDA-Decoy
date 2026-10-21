import os
import time
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
    def __init__(self, filepath: str = "telemetry.csv"):
        self.filepath = filepath
        self._lock = threading.Lock()
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
