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
- [x] **1. Timing fix** (`DecoySession` in `src/decoy/server.py`): `delta_t` now = next command arrival minus end of our last response (`mark_response_end()`, called after the SSH byte drip), so injected delay/drip no longer pollutes it. Test A8. Note: synthetic training data already models reaction time directly, so no retrain was needed; real-data retrain happens in Stage 3.
- [x] **2. Persistent actor registry** (`ActorRegistry` in `src/analytics/clustering.py`, SQLite): actor leader hash fixed at creation, session->actor assignments kept across runs/restarts; a session is only re-matched while its command count is still growing, and an actor left empty is dropped. `CERFEngine(registry_path=...)` opts in (default None = old stateless behaviour so benchmarks stay unchanged); the live analytics loop uses `DecoyConfig.actor_registry_path` (`actors.db`, gitignored). Test B8. 36 tests pass.
- [x] **3. More attribution signals** (`src/decoy/signals.py`, `signals.csv`): SSH HASSH (md5 of client KEXINIT algorithm lists, one per connection), offered public-key fingerprints (always refused, never accepted), login-attempt order (wordlist order); HTTP header-name order hash and User-Agent (once per session). `CERFEngine(signals_path=...)` joins them into `sessions.csv` as `hassh`, `pubkeys`, `header_order`, `user_agent`, and `download_urls` (wget/curl URLs via `extract_urls`). Signals corroborate clusters; they are NOT mixed into the embedding (HASSH is shared by every user of the same client library). Side fix: asyncssh drops a connection whose client repeats the `ssh-userauth` service request (paramiko bots do this when trying a key then a password); OpenSSH tolerates it, so `ssh_server.py` patches asyncssh's private packet table to accept the repeat. Re-check this patch when upgrading asyncssh. Tests A5/A7 extended, A9 new. 37 tests pass.
- [x] **4. Engagement realism** (42 tests pass):
  - R3 drip capped at 0.3 s total (`R3_DRIP_BUDGET_S`), sent in <=15 chunks because Windows timers can't honour hundreds of sub-15 ms sleeps (uncapped per-char drip took 6 s for 400 chars). `regime_drop_rates()` in `src/analytics/benchmark.py` reports, per regime, how often a command was the session's last; compare with baseline on real data to tune the perturbations.
  - Shell: pipes (`grep -v/-i/-c`, `head`, `tail`, `wc`, `sort`, `uniq`, `tee`; `| sh` runs nothing; other filters pass through) and redirects (`>`, `>>`, `2>...`, `/dev/null`). Written files are readable with `cat`, so a dropped `authorized_keys` persists.
  - New `src/decoy/system_commands.py`: `ps` (aux/-ef/plain, including the attacker's own sshd and bash), `netstat`/`ss`, `ifconfig`/`ip a`, `df`, `uptime`, `w`, `who`, `date`, `env`, `last`, `crontab -l`, `lsb_release`; all describe one consistent Apache + MySQL server (10.0.0.55). Mock LLM no longer matches substrings (`pstree` used to return `ps` output). `/etc/nginx` replaced by `apache2` to match the HTTP decoy.
  - Filesystem and history persist per (IP, user) for 24 h across reconnects (`filesystem_for` in `ssh_server.py`, capped at 10k clients).
  - LLM guards (only matter when a real Gemini key is used; the decoy currently always runs the mock): attacker text enters prompts as JSON strings with an explicit untrusted-input warning, replies capped at 4000 chars, 20 calls per session then mock fallback.
  - NOT done: HTTPS decoy + JA4. Python's `ssl` never exposes the ClientHello, so it needs a raw-socket peek before the TLS handshake; deferred to its own task.
- [x] **5. Real-data detection tooling** (`src/analytics/validation.py`; 47 tests pass). Still needs real traffic to produce meaningful numbers; the demo run only proves the plumbing.
  - Weak labels: sessions sharing a dropper URL or an offered SSH key (transitively) get one label; `score_clusters` = ARI of CERF actors vs those labels plus coverage. HASSH/UA/header order are deliberately not used (shared by unrelated attackers).
  - Perturbation A/B: `DecoyConfig.control_fraction` sends that share of sessions (by session-id hash) through all-baseline; arm is logged to `signals.csv` and joined into `sessions.csv` (`arm`). `ab_report` scores each arm separately. Default 0.0 = no behaviour change.
  - Novelty / drift: `ActorRegistry.new_actors` (actors created in the last run, `new_actor` column in `sessions.csv`) and `new_actors_per_day()`; a rising rate means unseen attackers or drifting behaviour.
  - Scripted vs interactive: `operator_type` (column `operator`) from reaction times. UNCALIBRATED heuristic (median < 0.3 s or CV < 0.25 => script); calibrate before trusting.
  - Report: `python -m src.analytics.validation [sessions.csv] [--registry actors.db]`.
- [x] **6. Operations** (51 tests pass):
  - Limits (`src/decoy/limits.py`, `DecoyConfig`): `max_conns_per_ip` 20 and `max_conns_total` 1000 concurrent SSH connections (extras are aborted silently), `http_requests_per_minute_per_ip` 300 (extras get a 503 with the Apache Server header), `max_commands_per_session` 2000. Defaults are untuned guesses; adjust after seeing real traffic.
  - SQLite telemetry: `telemetry_path` ending in `.db` makes `TelemetryLogger` write an indexed WAL-mode table; `read_telemetry()` (`src/analytics/telemetry_io.py`) reads either format and is used by the CERF engine and the dashboard. CSV stays the default (scripts and tests use it). Analytics still re-reads the whole table every 3 s, so it is durable but not incremental yet.
  - Canary alerts (`src/decoy/alerts.py`): honeytoken reads (SSH `cat` of bait files via `is_honeytoken`, HTTP bait paths) and `wget`/`curl` download attempts append to `alerts.jsonl` (one alert per session/kind/value) and POST to `alert_webhook` / `$CERDA_ALERT_WEBHOOK` as `{"text","content"}` (Slack/Discord style). Webhook failures are swallowed.
  - NOT done: dashboard authentication and a Docker/compose update for the new files; `docker-compose.yml` still needs `signals.csv`, `alerts.jsonl`, `actors.db` on a volume before deploying.
- [x] Stage 1.3 shell realism (pseudo_fs.py, ssh_server.py, tests/test_fs_realism.py) — 34 tests pass
