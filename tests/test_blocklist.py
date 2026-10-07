import pandas as pd

from src.analytics.blocklist import collect_blocklist, render_nft


def test_blocklist_validates_and_groups_ips():
    sessions = pd.DataFrame({
        "threat_actor_id": ["TA-001", "TA-001", "TA-002", "TA-003"],
        "source_ip": ["203.0.113.5", "203.0.113.5", "2001:db8::1", "1.2.3.4; reboot"],
    })
    blocklist = collect_blocklist(sessions)
    assert blocklist == {"TA-001": ["203.0.113.5"], "TA-002": ["2001:db8::1"]}

    nft = render_nft(blocklist)
    assert "203.0.113.5" in nft and "2001:db8::1" in nft and "reboot" not in nft


def test_blocklist_min_sessions_and_loopback():
    sessions = pd.DataFrame({
        "threat_actor_id": ["TA-001", "TA-002", "TA-002"],
        "source_ip": ["198.51.100.1", "127.0.0.1", "198.51.100.2"],
    })
    assert collect_blocklist(sessions, min_sessions=2) == {"TA-002": ["198.51.100.2"]}
