"""Enrichment: who is behind an address?

IPDatabase    offline country / ASN / organisation per IP from the iptoasn.com TSV files (public domain, no account;
              fetch them with `python -m scripts.fetch_enrichment_data`). Nothing leaves the machine.
ThreatFeeds   optional reputation lookups (AbuseIPDB, GreyNoise community). This SENDS the attacker's IP to a third
              party, so it is only ever called on request (dashboard button / `python -m src.analytics.enrichment`),
              only for public addresses, cached in SQLite, and capped per day.
"""
import bisect
import ipaddress
import json
import os
import socket
import sqlite3
import struct
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import Dict, Iterable, List, Optional

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.join(REPO, "data")
PRIVATE_LABEL = "(private or reserved address)"


def default_geoip_paths() -> List[str]:
    """$CERDA_GEOIP (os.pathsep-separated) or the files `scripts/fetch_enrichment_data.py` downloads."""
    env = os.environ.get("CERDA_GEOIP")
    if env:
        return [p for p in env.split(os.pathsep) if p]
    return [os.path.join(DATA_DIR, "ip2asn-v4.tsv"), os.path.join(DATA_DIR, "ip2asn-v6.tsv")]


def is_public(ip: str) -> bool:
    """True for globally routable addresses: the only ones worth a lookup or an export."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    addr = getattr(addr, "ipv4_mapped", None) or addr
    return addr.is_global


def _to_int(ip: str, family: int) -> int:
    if family == 4:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    return int(ipaddress.IPv6Address(ip))


class IPDatabase:
    """Range table per address family, looked up by bisection. ~500k IPv4 ranges load in about a second."""

    def __init__(self, paths: Iterable[str]):
        self._starts = {4: [], 6: []}
        self._rows = {4: [], 6: []}  # (end, asn, country, org), parallel to _starts
        self.loaded = []
        for path in paths:
            if path and os.path.exists(path):
                self._load(path)
                self.loaded.append(path)
        for family in (4, 6):  # sort once, after all files are in
            order = sorted(range(len(self._starts[family])), key=self._starts[family].__getitem__)
            self._starts[family] = [self._starts[family][i] for i in order]
            self._rows[family] = [self._rows[family][i] for i in order]

    def _load(self, path: str):
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 5 or parts[2] in ("0", ""):  # AS0 = not routed
                    continue
                try:
                    family = 6 if ":" in parts[0] else 4
                    start, end = _to_int(parts[0], family), _to_int(parts[1], family)
                except (OSError, ValueError):
                    continue
                country = "" if parts[3] in ("None", "ZZ") else parts[3]
                self._starts[family].append(start)
                self._rows[family].append((end, f"AS{parts[2]}", country, parts[4]))

    def __bool__(self):
        return bool(self.loaded)

    def lookup(self, ip: str) -> Dict[str, str]:
        """{"country", "asn", "as_org"}; blanks when unknown. Private addresses say so instead of staying blank."""
        blank = {"country": "", "asn": "", "as_org": ""}
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return blank
        addr = getattr(addr, "ipv4_mapped", None) or addr
        if not addr.is_global:
            return {**blank, "as_org": PRIVATE_LABEL}
        family = addr.version
        value = int(addr)
        i = bisect.bisect_right(self._starts[family], value) - 1
        if i >= 0:
            end, asn, country, org = self._rows[family][i]
            if value <= end:
                return {"country": country, "asn": asn, "as_org": org}
        return blank


_cache: Dict[tuple, IPDatabase] = {}
_cache_lock = threading.Lock()


def load_ip_database(paths: Optional[Iterable[str]] = None) -> IPDatabase:
    """Shared instance per set of files (the analytics loop calls this every few seconds); reloaded if a file changes."""
    paths = list(paths) if paths is not None else default_geoip_paths()
    key = tuple((p, os.path.getmtime(p) if os.path.exists(p) else None) for p in paths)
    with _cache_lock:
        if key not in _cache:
            _cache.clear()
            _cache[key] = IPDatabase(paths)
        return _cache[key]


# --------------------------------------------------------------------------------------------------------------
class ThreatFeeds:
    """Reputation of public IPs from AbuseIPDB and GreyNoise (community API), cached in SQLite.

    Keys come from the arguments or $ABUSEIPDB_KEY / $GREYNOISE_KEY. GreyNoise's community endpoint also works
    without a key (low rate limit), AbuseIPDB does not. `daily_limit` caps requests per feed per day.
    """

    ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
    GREYNOISE_URL = "https://api.greynoise.io/v3/community/"

    def __init__(self, db_path: str = "enrichment.db", abuseipdb_key: str = None, greynoise_key: str = None,
                 ttl_s: float = 7 * 86400, daily_limit: int = 500, timeout_s: float = 8,
                 abuseipdb_url: str = None, greynoise_url: str = None):
        self.db_path = db_path
        self.abuseipdb_key = abuseipdb_key if abuseipdb_key is not None else os.environ.get("ABUSEIPDB_KEY", "")
        self.greynoise_key = greynoise_key if greynoise_key is not None else os.environ.get("GREYNOISE_KEY", "")
        self.ttl_s, self.daily_limit, self.timeout_s = ttl_s, daily_limit, timeout_s
        self.abuseipdb_url = abuseipdb_url or self.ABUSEIPDB_URL
        self.greynoise_url = greynoise_url or self.GREYNOISE_URL
        self.errors: List[str] = []
        with self._db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS reputation (ip TEXT, feed TEXT, fetched REAL, payload TEXT, "
                       "PRIMARY KEY (ip, feed))")
            db.execute("CREATE TABLE IF NOT EXISTS usage (day TEXT, feed TEXT, n INTEGER, PRIMARY KEY (day, feed))")

    def _db(self):
        db = sqlite3.connect(self.db_path, timeout=10)
        db.row_factory = sqlite3.Row
        return db

    @property
    def feeds(self) -> List[str]:
        """Feeds that will be queried: AbuseIPDB needs a key, GreyNoise community runs without one."""
        return (["abuseipdb"] if self.abuseipdb_key else []) + ["greynoise"]

    # -- budget ---------------------------------------------------------------------------------
    def _take_budget(self, feed: str) -> bool:
        day = time.strftime("%Y-%m-%d", time.gmtime())
        with self._db() as db:
            used = db.execute("SELECT n FROM usage WHERE day=? AND feed=?", (day, feed)).fetchone()
            if used and used["n"] >= self.daily_limit:
                return False
            db.execute("INSERT INTO usage VALUES (?,?,1) ON CONFLICT(day, feed) DO UPDATE SET n = n + 1", (day, feed))
        return True

    # -- feeds ----------------------------------------------------------------------------------
    def _get(self, url: str, headers: dict) -> Optional[dict]:
        """GET -> JSON; a 404 is a real answer ("not seen") and comes back as {"_not_found": True}."""
        request = urllib.request.Request(url, headers={**headers, "Accept": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_s) as response:
                return json.loads(response.read(1_000_000))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"_not_found": True}
            self.errors.append(f"{url.split('?')[0]}: HTTP {e.code}")
        except (OSError, ValueError) as e:
            self.errors.append(f"{url.split('?')[0]}: {type(e).__name__}: {e}")
        return None

    def _query(self, feed: str, ip: str) -> Optional[dict]:
        if feed == "abuseipdb":
            data = self._get(f"{self.abuseipdb_url}?ipAddress={ip}&maxAgeInDays=90", {"Key": self.abuseipdb_key})
            if not data or "data" not in data:
                return None
            d = data["data"]
            return {"abuse_score": d.get("abuseConfidenceScore"), "abuse_reports": d.get("totalReports"),
                    "abuse_isp": d.get("isp"), "abuse_usage": d.get("usageType"), "abuse_last": d.get("lastReportedAt")}
        headers = {"key": self.greynoise_key} if self.greynoise_key else {}
        data = self._get(self.greynoise_url + ip, headers)
        if data is None:
            return None
        if data.get("_not_found"):
            return {"gn_seen": False}
        return {"gn_seen": True, "gn_classification": data.get("classification"), "gn_noise": data.get("noise"),
                "gn_riot": data.get("riot"), "gn_name": data.get("name")}

    # -- public ---------------------------------------------------------------------------------
    def cached(self, ip: str) -> Dict[str, object]:
        """Everything known without a request (any age)."""
        out: Dict[str, object] = {}
        with self._db() as db:
            for row in db.execute("SELECT payload FROM reputation WHERE ip=?", (ip,)):
                out.update(json.loads(row["payload"]))
        return out

    def lookup(self, ip: str) -> Dict[str, object]:
        """Reputation of ip: cached answers younger than ttl, fresh requests for the rest. {} for non-public IPs."""
        if not is_public(ip):
            return {}
        result: Dict[str, object] = {}
        for feed in self.feeds:
            with self._db() as db:
                row = db.execute("SELECT fetched, payload FROM reputation WHERE ip=? AND feed=?", (ip, feed)).fetchone()
            if row and time.time() - row["fetched"] < self.ttl_s:
                result.update(json.loads(row["payload"]))
                continue
            if not self._take_budget(feed):
                self.errors.append(f"{feed}: daily limit of {self.daily_limit} requests reached")
                if row:
                    result.update(json.loads(row["payload"]))  # stale beats nothing
                continue
            payload = self._query(feed, ip)
            if payload is None:
                if row:
                    result.update(json.loads(row["payload"]))
                continue
            with self._db() as db:
                db.execute("INSERT OR REPLACE INTO reputation VALUES (?,?,?,?)", (ip, feed, time.time(), json.dumps(payload)))
            result.update(payload)
        return result

    def lookup_many(self, ips: Iterable[str], limit: int = 50) -> Dict[str, Dict[str, object]]:
        """Reputation for up to `limit` distinct public IPs (cached ones do not use a request)."""
        out = {}
        for ip in list(dict.fromkeys(i for i in ips if is_public(i)))[:limit]:
            out[ip] = self.lookup(ip)
        return out


def main(argv=None):
    """python -m src.analytics.enrichment [sessions.csv]: country/ASN per actor, then (asked first) reputation."""
    import pandas as pd
    argv = sys.argv[1:] if argv is None else argv
    path = argv[0] if argv else "sessions.csv"
    sessions = pd.read_csv(path)
    db = load_ip_database()
    if not db:
        print("No GeoIP/ASN data loaded. Run: python -m scripts.fetch_enrichment_data")
    for ip in sessions["source_ip"].drop_duplicates():
        info = db.lookup(ip)
        print(f"{ip:40s} {info['country'] or '--':3s} {info['asn']:10s} {info['as_org']}")
    public = [ip for ip in sessions["source_ip"].drop_duplicates() if is_public(ip)]
    if public:
        feeds = ThreatFeeds()
        print(f"\n{len(public)} public address(es). Reputation lookup would send them to: {', '.join(feeds.feeds)}.")
        if input("Send now? [y/N] ").strip().lower() == "y":
            for ip, rep in feeds.lookup_many(public).items():
                print(ip, rep)
            for err in feeds.errors:
                print("note:", err)


if __name__ == "__main__":
    main()
