"""Gap 5: enrichment (src/analytics/enrichment.py) and STIX / MISP export (src/analytics/export.py)."""
import http.server
import json
import os
import threading
import time

import pandas as pd
import pytest

from src.analytics import CERFEngine
from src.analytics.enrichment import IPDatabase, ThreatFeeds, is_public, load_ip_database, PRIVATE_LABEL
from src.analytics.export import build_misp, build_stix
from tests.test_decoy import temp_env  # noqa: F401  (fixture)

V4 = "\n".join([
    "1.0.0.0\t1.0.0.255\t13335\tAU\tCLOUDFLARENET",
    "8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE",
    "9.9.9.0\t9.9.9.255\t0\tNone\tNot routed",
    "93.184.216.0\t93.184.216.255\t15133\tUS\tEDGECAST",
    "185.0.0.0\t185.0.0.255\t64500\tNone\tNo country",
]) + "\n"
V6 = "2001:4860::\t2001:4860:ffff:ffff:ffff:ffff:ffff:ffff\t15169\tUS\tGOOGLE\n"


@pytest.fixture
def tables(temp_env):
    temp_dir, _ = temp_env
    v4, v6 = os.path.join(temp_dir, "v4.tsv"), os.path.join(temp_dir, "v6.tsv")
    open(v4, "w").write(V4)
    open(v6, "w").write(V6)
    return [v4, v6]


def test_e1_lookup(tables):
    db = IPDatabase(tables)
    assert db.lookup("8.8.8.8") == {"country": "US", "asn": "AS15169", "as_org": "GOOGLE"}
    assert db.lookup("8.8.8.0")["asn"] == "AS15169" and db.lookup("8.8.8.255")["asn"] == "AS15169"  # both ends of a range
    assert db.lookup("8.8.9.0")["asn"] == "" and db.lookup("8.8.7.255")["asn"] == ""  # just outside
    assert db.lookup("9.9.9.9")["asn"] == ""  # AS0 rows (not routed) are skipped
    assert db.lookup("185.0.0.7") == {"country": "", "asn": "AS64500", "as_org": "No country"}
    assert db.lookup("2001:4860:4860::8888")["asn"] == "AS15169"
    assert db.lookup("::ffff:8.8.8.8")["asn"] == "AS15169"  # IPv4-mapped
    for private in ("127.0.0.1", "10.1.2.3", "192.168.0.1", "203.0.113.5", "::1"):
        assert db.lookup(private) == {"country": "", "asn": "", "as_org": PRIVATE_LABEL}
    assert db.lookup("not an ip")["asn"] == "" and db.lookup("")["asn"] == ""
    assert db and db.loaded == tables


def test_e2_missing_files_give_blank_answers_and_big_tables_are_fast(temp_env):
    temp_dir, _ = temp_env
    empty = IPDatabase([os.path.join(temp_dir, "nope.tsv")])
    assert not empty and empty.lookup("8.8.8.8") == {"country": "", "asn": "", "as_org": ""}
    big = os.path.join(temp_dir, "big.tsv")
    with open(big, "w") as f:  # about the size of the real IPv4 table
        for i in range(500_000):
            start = 16_777_216 + i * 256
            f.write(f"{start >> 24}.{(start >> 16) & 255}.{(start >> 8) & 255}.0\t{start >> 24}.{(start >> 16) & 255}."
                    f"{(start >> 8) & 255}.255\t{64000 + i % 1000}\tUS\tORG{i}\n")
    t = time.time()
    db = IPDatabase([big])
    loaded = time.time() - t
    t = time.time()
    hits = [db.lookup(f"{(16_777_216 + k * 256 * 37) >> 24}.{((16_777_216 + k * 256 * 37) >> 16) & 255}."
                      f"{((16_777_216 + k * 256 * 37) >> 8) & 255}.9")["asn"] for k in range(2000)]
    assert all(hits) and loaded < 30 and time.time() - t < 5


def test_e3_engine_adds_geo_columns_and_cache_follows_file_changes(temp_env, tables):
    from src.decoy.telemetry import TelemetryEvent, TelemetryLogger
    temp_dir, telemetry_path = temp_env
    logger = TelemetryLogger(telemetry_path)
    for sid, ip in (("s1", "8.8.8.8"), ("s2", "127.0.0.1"), ("s3", "1.2.3.4")):
        for i, cmd in enumerate(["ls", "id", "uname -a", "cat /etc/passwd"]):
            logger.log_event(TelemetryEvent(session_id=sid, timestamp_ns=time.time_ns(), source_ip=ip, protocol="SSH",
                                            command_index=i, command_raw=cmd, command_root=cmd.split()[0],
                                            current_path="/", regime="baseline", delta_t_ns=1000 * i, response_sent=True))
    sessions = CERFEngine(telemetry_path=telemetry_path, output_dir=temp_dir, embedding="pca",
                          geoip_paths=tables).run_pipeline().set_index("session_id")
    assert sessions.loc["s1", ["country", "asn", "as_org"]].tolist() == ["US", "AS15169", "GOOGLE"]
    assert sessions.loc["s2", "as_org"] == PRIVATE_LABEL and sessions.loc["s3", "asn"] == ""
    first = load_ip_database(tables)
    assert load_ip_database(tables) is first  # the analytics loop reuses one instance
    time.sleep(0.05)
    open(tables[0], "a").write("1.2.3.0\t1.2.3.255\t4242\tFR\tNEW\n")
    os.utime(tables[0], (time.time() + 5, time.time() + 5))
    assert load_ip_database(tables).lookup("1.2.3.4")["asn"] == "AS4242"  # a refreshed table is picked up


class FakeFeeds:
    """Local stand-in for AbuseIPDB and GreyNoise; counts requests."""
    def __init__(self):
        self.requests = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                outer.requests.append((self.path, dict(self.headers)))
                if self.path.startswith("/abuse"):
                    body = {"data": {"abuseConfidenceScore": 97, "totalReports": 41, "isp": "Evil ISP",
                                     "usageType": "Data Center", "lastReportedAt": "2026-10-01T00:00:00+00:00"}}
                    code = 200
                elif self.path.endswith("1.2.3.4"):
                    body, code = {"noise": True, "riot": False, "classification": "malicious", "name": "unknown"}, 200
                elif self.path.endswith("9.9.9.9"):
                    body, code = {"message": "not observed"}, 404
                else:
                    body, code = {"error": "boom"}, 500
                self.send_response(code)
                self.end_headers()
                self.wfile.write(json.dumps(body).encode())

            def log_message(self, *args):
                pass
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"


@pytest.fixture
def feeds_server():
    fake = FakeFeeds()
    yield fake
    fake.server.shutdown()


def _feeds(temp_dir, fake, db="enrichment.db", **kw):
    return ThreatFeeds(os.path.join(temp_dir, db), abuseipdb_url=fake.base + "/abuse",
                       greynoise_url=fake.base + "/gn/", **kw)


def test_e4_reputation_lookup_cache_and_privacy(temp_env, feeds_server):
    temp_dir, _ = temp_env
    feeds = _feeds(temp_dir, feeds_server, abuseipdb_key="secret", greynoise_key="")
    rep = feeds.lookup("1.2.3.4")
    assert rep["abuse_score"] == 97 and rep["abuse_reports"] == 41 and rep["gn_classification"] == "malicious"
    assert any(h.get("Key") == "secret" for _, h in feeds_server.requests)
    assert feeds.lookup("9.9.9.9")["gn_seen"] is False  # GreyNoise 404 = "not observed", a real answer
    n = len(feeds_server.requests)
    assert feeds.lookup("1.2.3.4") == rep and len(feeds_server.requests) == n  # served from the cache
    assert feeds.cached("1.2.3.4") == rep
    for private in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "203.0.113.9", "garbage"):
        assert feeds.lookup(private) == {}
    assert len(feeds_server.requests) == n  # nothing private ever left the machine
    assert list(feeds.lookup_many(["1.2.3.4", "127.0.0.1", "1.2.3.4"])) == ["1.2.3.4"]


def test_e5_no_abuseipdb_without_key_errors_are_swallowed_and_budget_holds(temp_env, feeds_server):
    temp_dir, _ = temp_env
    feeds = _feeds(temp_dir, feeds_server, abuseipdb_key="", greynoise_key="")
    assert feeds.feeds == ["greynoise"]
    assert feeds.lookup("4.4.4.4") == {} and any("HTTP 500" in e for e in feeds.errors)  # failure: not cached, not raised
    assert feeds.cached("4.4.4.4") == {}
    limited = _feeds(temp_dir, feeds_server, "limited.db", abuseipdb_key="", greynoise_key="", daily_limit=1)
    limited.lookup("1.2.3.4")
    n = len(feeds_server.requests)
    assert limited.lookup("5.5.5.5") == {} and len(feeds_server.requests) == n  # second request refused
    assert any("daily limit" in e for e in limited.errors)
    stale = _feeds(temp_dir, feeds_server, "limited.db", abuseipdb_key="", greynoise_key="", ttl_s=0, daily_limit=1)
    assert stale.lookup("1.2.3.4")["gn_classification"] == "malicious"  # expired but over budget: stale beats nothing


def _sessions():
    return pd.DataFrame({
        "session_id": ["a1", "a2", "b1", "c1"], "threat_actor_id": ["TA-0001", "TA-0001", "TA-0002", "TA-0003"],
        "source_ip": ["8.8.8.8", "93.184.216.34", "2001:4860:4860::8888", "127.0.0.1"],
        "cerf": ["aaaa", "aaaa", "bbbb", "cccc"],
        "download_urls": ["http://evil.example/x.sh?a=1&b='2'", "", "", ""],
        "payload_hashes": ["a" * 64, "", "", ""], "hassh": ["h1", "h1", "", ""], "user_agent": ["", "", "curl/8", ""],
        "country": ["US", "US", "US", ""], "asn": ["AS15169", "AS15133", "AS15169", ""],
    })


def _telemetry():
    now = time.time_ns()
    return pd.DataFrame({"session_id": ["a1", "a2", "b1", "c1"], "timestamp_ns": [now - 5_000_000_000, now, now, now]})


def test_e6_stix_bundle_is_well_formed():
    bundle = build_stix(_sessions(), _telemetry())
    objects = bundle["objects"]
    ids = [o["id"] for o in objects]
    assert bundle["type"] == "bundle" and len(ids) == len(set(ids))
    by_type = {}
    for o in objects:
        by_type.setdefault(o["type"], []).append(o)
    assert sorted(a["name"] for a in by_type["threat-actor"]) == ["TA-0001", "TA-0002"]  # TA-0003 is loopback only
    patterns = sorted(i["pattern"] for i in by_type["indicator"])
    assert "[ipv4-addr:value = '8.8.8.8']" in patterns and "[ipv6-addr:value = '2001:4860:4860::8888']" in patterns
    assert f"[file:hashes.'SHA-256' = '{'a' * 64}']" in patterns
    assert "[url:value = 'http://evil.example/x.sh?a=1&b=\\'2\\'']" in patterns  # quote escaped
    assert not any("127.0.0.1" in p for p in patterns)
    for rel in by_type["relationship"]:  # every reference resolves, every indicator belongs to an actor
        assert rel["source_ref"] in ids and rel["target_ref"] in ids and rel["relationship_type"] == "indicates"
    assert len(by_type["relationship"]) == len(by_type["indicator"])
    actor = next(a for a in by_type["threat-actor"] if a["name"] == "TA-0001")
    assert actor["first_seen"] < actor["last_seen"] and "AS15169" in actor["description"]
    assert [o["id"] for o in build_stix(_sessions(), _telemetry())["objects"] if o["type"] != "bundle"
            and o["type"] != "x"] == ids  # re-exporting gives the same ids


def test_e7_stix_includes_private_only_on_request_and_empty_input_is_valid():
    with_private = build_stix(_sessions(), _telemetry(), include_private=True)
    assert "TA-0003" in [o.get("name") for o in with_private["objects"]]
    empty = build_stix(pd.DataFrame(), None)
    assert [o["type"] for o in empty["objects"]] == ["identity"]
    assert build_misp(pd.DataFrame(), None)["Event"]["Attribute"] == []


def test_e8_stix_parses_with_the_reference_library():
    stix2 = pytest.importorskip("stix2")
    parsed = stix2.parse(json.dumps(build_stix(_sessions(), _telemetry())), allow_custom=False)
    assert parsed.type == "bundle" and len(parsed.objects) > 5


def test_e9_misp_event():
    event = build_misp(_sessions(), _telemetry(), reputation={"8.8.8.8": {"abuse_score": 97}})["Event"]
    kinds = {(a["type"], a["value"]): a for a in event["Attribute"]}
    assert kinds[("ip-src", "8.8.8.8")]["to_ids"] is True and "abuse_score" in kinds[("ip-src", "8.8.8.8")]["comment"]
    assert ("sha256", "a" * 64) in kinds and ("url", "http://evil.example/x.sh?a=1&b='2'") in kinds
    assert kinds[("hassh-md5", "h1")]["to_ids"] is False and kinds[("user-agent", "curl/8")]["to_ids"] is False
    assert ("ip-src", "127.0.0.1") not in kinds
    assert {t["name"] for t in event["Tag"]} >= {"tlp:amber"}
    json.dumps(event)  # serialisable


def test_e10_helpers():
    assert is_public("8.8.8.8") and is_public("2001:4860:4860::8888") and is_public("::ffff:8.8.8.8")
    assert not any(is_public(x) for x in ("127.0.0.1", "10.0.0.1", "172.16.0.1", "169.254.1.1", "100.64.0.1",
                                          "203.0.113.1", "::1", "fe80::1", "", "x"))


def test_e11_urls_to_private_hosts_follow_the_same_rule_as_ips():
    s = _sessions()
    s.loc[0, "download_urls"] = "http://203.0.113.7/bot http://10.0.0.1/x http://evil.example/y http://8.8.4.4/z"
    shared = {i["pattern"] for i in build_stix(s, _telemetry())["objects"] if i["type"] == "indicator"}
    assert "[url:value = 'http://evil.example/y']" in shared and "[url:value = 'http://8.8.4.4/z']" in shared
    assert not any("203.0.113.7" in p or "10.0.0.1" in p for p in shared)
    everything = {i["pattern"] for i in build_stix(s, _telemetry(), include_private=True)["objects"] if i["type"] == "indicator"}
    assert "[url:value = 'http://203.0.113.7/bot']" in everything
    misp = {(a["type"], a["value"]) for a in build_misp(s, _telemetry())["Event"]["Attribute"]}
    assert ("url", "http://10.0.0.1/x") not in misp and ("url", "http://evil.example/y") in misp
