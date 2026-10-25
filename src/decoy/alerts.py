"""Canary alerts: tell the operator when an attacker touches bait.

Every alert is appended to alerts.jsonl; if a webhook URL is configured it is also POSTed
(JSON with "text" and "content" keys, which Slack/Mattermost and Discord accept).
"""
import json
import os
import threading
import time
import urllib.request


class AlertSink:
    def __init__(self, path: str = "alerts.jsonl", webhook: str = None):
        self.path = path
        self.webhook = webhook or os.getenv("CERDA_ALERT_WEBHOOK")
        self._lock = threading.Lock()
        self._seen = set()  # one alert per (session, kind, value)

    def send(self, session_id: str, source_ip: str, protocol: str, kind: str, value: str):
        key = (session_id, kind, value)
        with self._lock:
            if key in self._seen:
                return
            self._seen.add(key)
            alert = {"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "session_id": session_id,
                     "source_ip": source_ip, "protocol": protocol, "kind": kind, "value": str(value)[:512]}
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert) + "\n")
        if self.webhook:
            text = f"[CERDA] {kind} by {source_ip} ({protocol}): {alert['value']}"
            threading.Thread(target=self._post, args=(text,), daemon=True).start()

    def _post(self, text: str):
        try:
            request = urllib.request.Request(self.webhook, json.dumps({"text": text, "content": text}).encode(),
                                             {"Content-Type": "application/json"})
            urllib.request.urlopen(request, timeout=5).close()
        except Exception as e:  # an unreachable webhook must never affect the decoy
            print(f"alert webhook failed: {e}")
