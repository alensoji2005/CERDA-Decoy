"""Extra attribution signals, logged per session to signals.csv (long format).

These corroborate CERF clusters (they are not mixed into the embedding): the same HASSH
or HTTP header order across sessions suggests the same client tooling.
"""
import csv
import hashlib
import os
import struct
import threading
import time

HEADER = ["session_id", "timestamp_ns", "source_ip", "protocol", "kind", "value"]


class SignalLogger:
    def __init__(self, filepath: str = "signals.csv"):
        self.filepath = filepath
        self._lock = threading.Lock()
        if not os.path.exists(filepath):
            with open(filepath, "w", newline="") as f:
                csv.writer(f).writerow(HEADER)

    def log(self, session_id: str, source_ip: str, protocol: str, kind: str, value: str):
        row = [session_id, time.time_ns(), source_ip, protocol, kind, str(value)[:512]]
        with self._lock, open(self.filepath, "a", newline="") as f:
            csv.writer(f).writerow(row)


def hassh(kexinit_payload: bytes) -> str:
    """HASSH (Salesforce) of a client SSH_MSG_KEXINIT payload:
    md5(kex_algs;enc_algs_c2s;mac_algs_c2s;comp_algs_c2s). Returns "" if unparseable."""
    try:
        pos = 1 + 16  # message type + cookie
        lists = []
        for _ in range(10):
            (n,) = struct.unpack_from(">I", kexinit_payload, pos)
            lists.append(kexinit_payload[pos + 4:pos + 4 + n].decode("ascii"))
            pos += 4 + n
    except (struct.error, UnicodeDecodeError):
        return ""
    kex, _hostkey, enc_c2s, _enc_s2c, mac_c2s, _mac_s2c, comp_c2s = lists[:7]
    return hashlib.md5(";".join([kex, enc_c2s, mac_c2s, comp_c2s]).encode()).hexdigest()


def header_order(raw_headers) -> str:
    """Hash of the request header names in arrival order (HTTP clients differ in this)."""
    names = ",".join(k.decode("latin-1").lower() if isinstance(k, bytes) else str(k).lower() for k, _ in raw_headers)
    return hashlib.md5(names.encode()).hexdigest()[:16]
