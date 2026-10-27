"""Threat-intelligence export: STIX 2.1 bundle and MISP event, built from sessions.csv (+ telemetry for dates).

What is exported per attributed actor (TA-xxxx): the source IPs it used, the dropper URLs it fetched, the SHA-256 of
payloads it dropped. Only globally routable IPs go out unless `include_private` is set (demo traffic is loopback, which
no feed wants). Identifiers are deterministic (UUIDv5), so exporting the same data twice gives the same objects and
a TIP de-duplicates instead of piling up copies.
"""
import ipaddress
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import urlsplit

import pandas as pd

from .enrichment import is_public

NAMESPACE = uuid.UUID("6f1c1a53-9a0e-4c6c-8d0b-3f6f4cda0001")  # fixed: ids stay stable across exports
SENSOR_NAME = "CERDA decoy"


def _id(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(NAMESPACE, f'{kind}:{key}')}"


def _ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _escape(value: str) -> str:
    """STIX patterning string literal: backslash and single quote are escaped."""
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


def _shareable_url(url: str) -> bool:
    """A URL whose host is a private / documentation IP literal says nothing to anyone else (names are kept)."""
    host = urlsplit(url).hostname or ""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return bool(host)
    return is_public(host)


def _actors(sessions: pd.DataFrame, telemetry: Optional[pd.DataFrame], include_private: bool,
            reputation: Dict[str, dict]) -> List[dict]:
    """One dict per actor with its indicators and first/last seen."""
    now = datetime.now(timezone.utc)
    sessions = sessions.fillna("")  # CSV round trips turn empty strings into NaN
    stamp = {}
    if telemetry is not None and not telemetry.empty:
        times = pd.to_datetime(telemetry["timestamp_ns"], unit="ns", utc=True)
        by_session = telemetry.assign(_t=times).groupby("session_id")["_t"].agg(["min", "max"])
        stamp = {sid: (row["min"].floor("us").to_pydatetime(), row["max"].floor("us").to_pydatetime()) for sid, row in by_session.iterrows()}
    actors = []
    for actor_id, group in sessions.groupby("threat_actor_id"):
        ips = [ip for ip in dict.fromkeys(group["source_ip"].astype(str)) if include_private or is_public(ip)]
        words = lambda col: list(dict.fromkeys(w for v in group.get(col, []) for w in str(v).split() if w != "nan"))
        urls = [u for u in words("download_urls") if include_private or _shareable_url(u)]
        seen = [stamp[s] for s in group["session_id"] if s in stamp]
        first = min((a for a, _ in seen), default=now)
        last = max((b for _, b in seen), default=now)
        places = sorted({f"{r.country} {r.asn}".strip() for r in group.itertuples() if getattr(r, "asn", "")}) \
            if "asn" in group else []
        actors.append({
            "id": str(actor_id), "cerf": str(group["cerf"].iloc[0]), "ips": ips, "urls": urls,
            "sha256": words("payload_hashes"),
            "sessions": len(group), "first": first, "last": last, "places": places,
            "reputation": {ip: reputation[ip] for ip in ips if reputation.get(ip)},
        })
    return actors


def _description(actor: dict) -> str:
    text = (f"Attributed by CERDA from execution rhythm (CERF {actor['cerf']}) over {actor['sessions']} decoy session(s). "
            "Attribution is statistical: treat as a lead, not a verdict.")
    if actor["places"]:
        text += " Network origin: " + ", ".join(actor["places"]) + "."
    return text


def build_stix(sessions: pd.DataFrame, telemetry: Optional[pd.DataFrame] = None, include_private: bool = False,
               reputation: Optional[Dict[str, dict]] = None) -> dict:
    """STIX 2.1 bundle: identity (sensor), threat-actor per actor, indicator per IP / URL / SHA-256, and
    `indicates` relationships from each indicator to its actor."""
    reputation = reputation or {}
    now = _ts(datetime.now(timezone.utc))
    sensor = _id("identity", SENSOR_NAME)
    objects = [{"type": "identity", "spec_version": "2.1", "id": sensor, "created": now, "modified": now,
                "name": SENSOR_NAME, "identity_class": "system", "description": "CERDA decoy sensor"}]
    if sessions is None or sessions.empty:
        return {"type": "bundle", "id": _id("bundle", now), "objects": objects}
    for actor in _actors(sessions, telemetry, include_private, reputation):
        if not (actor["ips"] or actor["urls"] or actor["sha256"]):
            continue  # nothing shareable (e.g. loopback-only demo traffic): an actor without indicators is noise
        first, last = _ts(actor["first"]), _ts(actor["last"])
        actor_ref = _id("threat-actor", actor["id"])
        objects.append({"type": "threat-actor", "spec_version": "2.1", "id": actor_ref, "created": first,
                        "modified": now, "created_by_ref": sensor, "name": actor["id"],
                        "description": _description(actor), "threat_actor_types": ["unknown"],
                        "first_seen": first, "last_seen": last, "labels": ["cerda-attributed"],
                        "external_references": [{"source_name": "cerda-cerf-hash", "external_id": actor["cerf"]}]})
        indicators = ([("ip", ip, f"[{'ipv6' if ':' in ip else 'ipv4'}-addr:value = '{ip}']") for ip in actor["ips"]]
                      + [("url", u, f"[url:value = '{_escape(u)}']") for u in actor["urls"]]
                      + [("sha256", h, f"[file:hashes.'SHA-256' = '{h}']") for h in actor["sha256"]])
        for kind, value, pattern in indicators:
            indicator_ref = _id("indicator", f"{kind}:{value}")
            note = actor["reputation"].get(value, {}) if kind == "ip" else {}
            description = f"{kind} seen in a CERDA decoy, attributed to {actor['id']}."
            if note:
                description += " Reputation at export time: " + json.dumps(note, sort_keys=True)
            objects.append({"type": "indicator", "spec_version": "2.1", "id": indicator_ref, "created": first,
                            "modified": now, "created_by_ref": sensor, "name": f"{kind}: {value}"[:200],
                            "description": description, "indicator_types": ["malicious-activity"],
                            "pattern": pattern, "pattern_type": "stix", "valid_from": first})
            objects.append({"type": "relationship", "spec_version": "2.1",
                            "id": _id("relationship", f"{indicator_ref}>{actor_ref}"), "created": first,
                            "modified": now, "created_by_ref": sensor, "relationship_type": "indicates",
                            "source_ref": indicator_ref, "target_ref": actor_ref})
    return {"type": "bundle", "id": _id("bundle", now), "objects": objects}


def build_misp(sessions: pd.DataFrame, telemetry: Optional[pd.DataFrame] = None, include_private: bool = False,
               reputation: Optional[Dict[str, dict]] = None, tlp: str = "tlp:amber") -> dict:
    """MISP event (import with "Add event" > "Import from MISP JSON"). to_ids is set for IPs, URLs and hashes only;
    client fingerprints (HASSH, user agent) are context, not detections. Default TLP is amber: widen it on purpose."""
    reputation = reputation or {}
    now = datetime.now(timezone.utc)
    attributes = []

    def add(type_, category, value, comment, to_ids):
        attributes.append({"type": type_, "category": category, "value": value, "comment": comment,
                           "to_ids": to_ids, "distribution": "0"})
    if sessions is not None and not sessions.empty:
        for actor in _actors(sessions, telemetry, include_private, reputation):
            comment = f"{actor['id']} (CERF {actor['cerf']})"
            for ip in actor["ips"]:
                extra = actor["reputation"].get(ip)
                add("ip-src", "Network activity", ip, comment + (f"; reputation {json.dumps(extra, sort_keys=True)}" if extra else ""), True)
            for url in actor["urls"]:
                add("url", "Network activity", url, comment, True)
            for sha in actor["sha256"]:
                add("sha256", "Payload delivery", sha, comment, True)
        group = sessions
        for col, type_, category in (("hassh", "hassh-md5", "Network activity"), ("user_agent", "user-agent", "Network activity")):
            if col in group:
                for value in dict.fromkeys(v for v in group[col].astype(str) if v and v != "nan"):
                    add(type_, category, value, "client fingerprint (shared by unrelated users of the same tool)", False)
    return {"Event": {"info": f"CERDA decoy export {now.strftime('%Y-%m-%d %H:%M')}Z", "date": now.strftime("%Y-%m-%d"),
                      "threat_level_id": "3", "analysis": "0", "distribution": "0",
                      "Tag": [{"name": tlp}, {"name": "cerda:attribution=\"statistical\""}],
                      "Attribute": attributes}}
