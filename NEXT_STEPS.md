# CERDA — Next Steps Plan (2026-10-07)

> **Status:** Phase 1 done (plus a fix for fingerprinting sessions of unequal length). Phase 3 done: the root wrappers are kept as entry points, demo scripts moved to `scripts/`, old docs moved to `docs/archive/`, and dependencies pinned. A separate CLI was skipped because the wrappers already cover it. Phase 2 done: the Transformer is trained and is now the default. On unseen archetypes it scores ARI 1.0 vs ~0.49 for PCA. Next up: Phase 5 data collection and Phase 4 items.

## Where things stand

- **Module A (decoy):** works. Async SSH (2222) and HTTP (8080) listeners, a pseudo-FS (cd/ls/cat/pwd/wget/curl/touch/rm/chmod), R0–R3 perturbation, `DecoyConfig`, thread-safe `TelemetryLogger` and `RegimeScheduleLogger` (writes `regime_schedule.csv`), and an optional RL scheduler (`use_rl`).
- **Module B (CERF):** works. Sanitization, 13 timing features + 6 AST features, TF-IDF, PCA, 64-bit LSH, Hamming clustering. A Transformer embedding (`transformer_model.py`) is now wired into `cerf_engine.py`.
- **Module C (dashboard):** works. Streamlit app with the date-range filter, graph, timeline, JSON export and themes.
- **v2 already built:** RL scheduler (Claim 5), LLM decoy FS via Gemini (Claim 7), Transformer (Claim 8).
- **Tests:** 16 pass, 1 fail, 2 skip.

`CERDA_Build_Progress_Analysis.md` is **out of date**. Every "Priority 1" gap it lists (regime_schedule.csv, touch/rm/chmod, AST features, date filter, DecoyConfig, telemetry lock) is already in the code.

## Problems found

1. **`test_llm_context_awareness` fails.** `PseudoFilesystem` uses the real Gemini API whenever `GEMINI_API_KEY` is set, so the test hits the network and gets non-deterministic output. Tests should force the mock.
2. **The core patent proof is switched off.** B3 (attribution accuracy) and B4 (CERF ≥90% vs baseline) are skipped because the engine now uses an *untrained* Transformer. The README's "≥90% accuracy" claim is currently unverified.
3. **The Gemini model id `gemini-2.7-flash` is hardcoded** and may not exist. Failures are caught silently, so it may fall back without anyone noticing.
4. **Root clutter:**
   - `cerf_engine.py`, `decoy_server.py` and `dashboard.py` at the repo root duplicate or diverge from `src/` (root `cerf_engine.py` differs from the `src` one).
   - `attacker_client.py`, `bot_attacker.py` and `generate_demo_data.py` are loose demo scripts.
5. **Docs drift:**
   - `pmd-v2.md` §12 says "14 tests" and still lists Claims 7 and 8 as future work.
   - The spec file `Rewrite your PMD into a strict “spec document” for.md` has a bad filename and is a superseded draft.
   - The README has no decoy run command.
6. **No reproducible entry point** for running the full pipeline (decoy → attack → CERF → dashboard).

## Plan

### Phase 1: Restore a green, honest baseline (small, do first)

1. Make the LLM tests deterministic: pass `use_mock=True` through `PseudoFilesystem` (or set it in a fixture). Gate real Gemini tests behind `@pytest.mark.network`.
2. Make the embedding backend selectable (`CERFEngine(embedding="pca"|"transformer")`, default `pca`), then un-skip B3 and B4 on the PCA path. This brings back the ≥90% proof.
3. Make the Gemini model id an env var (`CERDA_LLM_MODEL`) and log fallbacks.
4. Run `pytest`: target 19/19 passing, 0 skipped. That's the verification for this phase.

### Phase 2: Make the Transformer earn its place

1. Add a training script (`scripts/train_transformer.py`): contrastive/triplet loss on synthetic A/B/C scripts, saving weights to `models/`.
2. Have the engine load the weights if present and otherwise fall back to PCA.
3. Add test B5: the Transformer is at least as accurate as PCA on held-out synthetic data. Record the numbers in README for patent evidence.

### Phase 3: Cleanup and docs

1. Delete or shrink the root duplicates into thin entry points that import `src/`. Move demo scripts to `scripts/`.
2. Add a single CLI (`python -m src run-decoy | analyze | dashboard`) plus an end-to-end demo script.
3. Update `pmd-v2.md` §12, delete or archive `CERDA_Build_Progress_Analysis.md`, and rename or archive the badly named spec draft. Update the README.
4. Pin `requirements.txt` versions (torch, google-genai, streamlit).

### Phase 4: Remaining v2 roadmap (pick by value)

| Item | Claim | Effort | Note |
|---|---|---|---|
| TCP socket tarpitting (ACK delay / small window) | 6 | M | Linux-only (setsockopt/tc); keep it behind a flag |
| Firewall integration (emit blocklist / nftables set per threat actor) | — | M | Output a file first; never auto-apply without a flag |
| Docker image + compose (decoy + dashboard) | — | M | Prerequisite for the fleet |
| TSDB backend (TimescaleDB/ClickHouse) | — | H | Only when CSV becomes the bottleneck; put a storage interface behind the loggers |
| Distributed decoy fleet | — | H | After Docker and TSDB |

### Phase 5: Real-world validation (biggest patent/credibility risk)

- Spec Risk 2 (overfitting to synthetic data) is still open. Deploy one decoy on a cheap VPS and collect real bot sessions for 2–4 weeks.
- Re-measure clustering on that data.
- Keep the decoy host isolated, with no real execution (test A3 already guards this).

## Recommended order

Phase 1 → Phase 3 (cheap, unblocks clarity) → Phase 2 → Phase 5 data collection running in the background → Phase 4 items as needed.
