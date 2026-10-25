# CERDA — Work Log

Running log of improvements, highest priority first. Each entry is added when the item is done and tested.

## Backlog (priority order)
1. Timing fix: measure attacker reaction time, not our own injected delay
2. Persistent actor registry (stable TA-IDs)
3. More attribution signals (HASSH, pubkeys, wordlist order, URLs, HTTP headers)
4. Engagement realism (drip cap, pipes/redirects, ps/netstat/etc, per-IP FS persistence)
5. Real-data detection (weak labels, A/B, novelty, drift)
6. Operations (per-IP limits, SQLite telemetry, canary alerts)

## Done
- [x] Stage 1.3 shell realism (pseudo_fs.py, ssh_server.py, tests/test_fs_realism.py) — 34 tests pass
