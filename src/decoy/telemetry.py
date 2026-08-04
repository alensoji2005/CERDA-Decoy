import os
import time
import pandas as pd
from dataclasses import dataclass
from typing import Optional

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
        df.to_csv(self.filepath, mode='a', header=False, index=False)
