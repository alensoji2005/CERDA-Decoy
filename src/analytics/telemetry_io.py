"""Read decoy telemetry from either storage format (CSV, or SQLite when the path ends in .db)."""
import sqlite3
from contextlib import closing

import pandas as pd


def read_telemetry(path: str) -> pd.DataFrame:
    if path.endswith(".db"):
        with closing(sqlite3.connect(path)) as db:
            df = pd.read_sql("SELECT * FROM telemetry", db)
        df["response_sent"] = df["response_sent"].astype(bool)
        return df
    return pd.read_csv(path)
