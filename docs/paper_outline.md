# CERDA paper outline (draft 1, 2026-10-27)

Target: *Computers & Security*, Full Length Article, single-column Word file, numbered sections, ≤ 12,000 words including references (budget below: about 9,500).

**Sources rule.** Statements about CERDA come only from the final report (`Final_Report_BCSE497J_Revised.docx`) and the codebase (commit `1ebd3d4`; 51 tests pass, re-run today). Citations come only from `docs/literature.md`. The old IEEE draft is not used.

**Status tags used below:** `[WRITE NOW]` = fully supported by report and code. `[NEEDS DATA]` = needs the real-traffic deployment and experiments from `docs/paper_plan.md`. `[NEEDS READING]` = needs full texts of cited papers first.

---

## 0. Things the code check turned up (decide before drafting)

I read the code against the report. The report's numbers match the code (regime schedule 0/2/4/6 via `DecoyConfig`, thresholds 6 and 10, 64 bits, 32 dimensions, 2 layers, 51 tests). These points are not errors in the report but will draw reviewer questions:

| # | Finding (file) | Consequence for the paper |
|---|---|---|
| C1 | Every treatment session gets the **same fixed schedule by command index** (`server.py` `DecoyConfig.default_schedule`). No command is ever observed under two regimes in one session. | "Counterfactual" in the name is hard to defend as a causal term. Define it narrowly ("perturbation-conditioned reaction profile") or drop it from the title. Also, regime is a function of position, so reaction to the regime cannot be separated from reaction at that position. The control arm (all-baseline) is the only way to separate them. |
| C2 | Weak labels come from shared **download URLs** and SSH keys (`validation.py`), but `has_url` is one of the six per-command input features (`features.py`, `transformer_model.py`). | Scoring against URL-derived labels is **partly circular**: sessions sharing a URL already look alike in the features. Report URL-based and key-based scores separately; the key-based one is independent of the features. |
| C3 | The Transformer threshold (10) was calibrated on "benchmark seed 7" (`cerf_engine.py` comment); the reported benchmark uses seed 1000 (`benchmark.py`). Training, calibration and test data all come from the same simulator (`synthetic.py`). | Say exactly this. Different seeds, same generator: this is generalisation across random draws, not across attacker populations. |
| C4 | **Tested, confirmed.** The PCA backend refits scaler and PCA on each batch (`embedding.py`), so a session's hash depends on which other sessions are in the batch. The Transformer backend does not refit. **Re-run after C8/C9 were fixed (current numbers).** Test (benchmark seed 1000, 6 archetypes × 20 sessions; script in the scratchpad `pca_refit_test.py`): same session, hash from a half-size batch vs the full batch, PCA: mean 9.7 bits apart (median 7, max 28), 55% of sessions farther apart than the threshold of 6, 3% identical; when the first batch held only 2 of the 6 archetypes, mean 31.0 bits, i.e. as far apart as unrelated hashes (32 of 64 on average), 98% beyond the threshold. Transformer: 0 bits in both cases, 100% identical. Through a persistent registry (2 archetypes, then all 6): PCA gave 20 then 24 actors (truth 2 then 6; ARI 0.12 then 0.61; stateless on the full batch 9 actors, ARI 0.96); Transformer gave 2 then 6, ARI 1.00 both times. The "0 of 40 sessions changed actor" result is because the registry freezes assigned sessions, not because hashes are stable. One dataset, one seed. (Before the fix: 16.7 / 32.5 bits; same conclusion.) | Registry persistence and cross-run hash comparison hold for the **Transformer backend only**; the PCA backend is a batch method. The default engine and the live analytics loop use the Transformer, so the deployed path is unaffected. State this in Section 4.7. |
| C5 | The Transformer is trained with a **supervised** contrastive loss using synthetic archetype labels (`scripts/train_transformer.py`). | The report says no labelled data are needed. True at clustering time; the embedding itself is trained on synthetic labels. State this in Methods. |
| C6 | First-match clustering: a session joins the first actor (in ID order) within the threshold (`clustering.py`), so assignment depends on arrival order. | Already in the report's limitations; add an order-sensitivity experiment (shuffle sessions, measure ARI change). |
| C7 | `operator_type` thresholds (0.3 s, CV 0.25) are uncalibrated. | Use it only as a descriptive statistic, or calibrate it. Do not use it as a result. |
| C8 | **FIXED 2026-10-27 (analytics pairing).** Regime and Δt are offset by one command in the live log (`server.py` `DecoySession.step`). The row for command *k* stores the regime applied to the response to command *k* but Δt = the reaction to the response to command *k−1*. At each boundary (indices 2, 4, 6) the first row of a regime holds a reaction to the previous regime. The first row's Δt runs from the start of the shell session (after authentication), so it is the time to the first command, not a reaction. `features.py` groups Δt by the row's regime, so its per-regime medians mix two regimes. | Describe the pairing exactly as it is in Methods. For the PCA features this blurs the regime contrast (each regime has only 2 rows early in a session, one of them offset). A one-line fix (also log the regime of the preceding response) should be made **before the real-traffic collection starts**, since it changes the recorded data. Needs your decision. |
| C9 | **FIXED 2026-10-27 (shared `src/schedule.py`, retrained).** The synthetic benchmark did not use the live schedule (`synthetic.py`): regimes switch at command indices 12, 25, 37, not 2, 4, 6, and Δt is paired with the same row's regime (no offset). Archetypes differ by construction in per-regime reaction time and in command habits, so the benchmark assumes the premise of RQ1. | The Transformer is trained and evaluated on a layout the live decoy never produces, so its benchmark scores say little about live sessions. The benchmark can show the pipeline separates synthetic archetypes; it cannot answer RQ1. Say so, and regenerate the simulator with the live schedule and offset before retraining. |

**Decisions made:** title = the report's title (user, 2026-10-27). C4 tested (above). **C8 and C9 fixed and the Transformer retrained (2026-10-27)**: see CLAUDE.md for what changed. C8 was fixed in the analytics (each Δt is paired with the previous row's regime; command 0's Δt is ignored), not in the logger, so the log schema is unchanged and old logs are covered. C9: the simulator and the decoy now share `src/schedule.py`.
**Consequences for the paper:** (a) the headline benchmark result changed: PCA 0.96 (9 actors) vs Transformer 1.00 on seed 1000, and over seeds 1001-1010 PCA mean 0.95 (0.88-1.00) vs Transformer mean 0.98 (0.81-1.00); the old 0.49 vs 1.00 is gone, so the paper must not claim the Transformer beats PCA by a wide margin on the simulator; (b) the Transformer threshold of 10 now has no margin on the calibration seed (within 10, between 11); (c) each session has only two reactions to baseline responses (commands 1 and 2), two to slowdown and two to jitter before the filesystem-latency phase, a design weakness for the per-regime statistics. **Decisions needed:** whether to lengthen the baseline phase before the deployment; whether "counterfactual" stays in the system name (C1).

---

## 1. Working titles

Journal asks for concise titles without avoidable abbreviations.
- A. *Attributing honeypot sessions to persistent threat actors from reactions to timing perturbation* (preferred; no contested term)
- B. *Perturbation-conditioned reaction fingerprints for linking SSH and HTTP honeypot sessions*
- C. *CERDA: counterfactual execution-rhythm fingerprints for honeypot attribution* (only if C1 is resolved; contains an abbreviation)

## 2. Contribution statement (draft; wording is deliberately cautious)

1. A honeypot that deliberately varies its response timing across four regimes and records the attacker's reaction time **net of the delay it injected itself**.
2. A session fingerprint (64-bit sign-LSH hash of a 32-d embedding) and a first-match Hamming clustering with a persistent actor registry, with corroborating signals (HASSH, offered SSH keys, header order, download URLs) kept out of the embedding.
3. An evaluation protocol for data without ground truth: weak labels, an all-baseline control arm, novelty and drift tracking.
4. `[NEEDS DATA]` An evaluation on real internet traffic with text-only and no-perturbation baselines.

Wording rule from the literature pass: adaptive perturbation and reaction-based assessment are **not** new (Wagener 2011; Schneider et al. 2021). Say "to our knowledge, the combination of timing perturbation, delay-corrected reaction time and hash-based actor linking has not been reported", cite Wagener as precedent, and do not claim more until his thesis full text is read. Items 1-3 are claims about the design; only item 4 can support a claim that it *works*.

## 3. Research questions (drive Sections 5-6)

- **RQ1** Does the reaction to timing perturbation add attribution signal beyond command structure alone?
- **RQ2** Does the perturbation change engagement (session length, early disconnects) relative to a baseline-only control arm?
- **RQ3** How sensitive are actor assignments to the Hamming threshold, session length and session order?

---

## 4. Section outline

Word budget in brackets. Source = where the material comes from.

### Abstract (≤ 250 words) [WRITE NOW for design, NEEDS DATA for results]
Purpose, method, main findings, conclusion; no references; abbreviations defined (SSH, HTTP, ARI, HASSH). The report's abstract (about 430 words) is the starting point and must be cut by roughly 40%. Findings sentence stays empty until real data exist.

**Keywords (5-10, avoid "and"/"of" phrases):** honeypot, deception, attribution, SSH, fingerprinting, clustering, threat intelligence, locality-sensitive hashing.

**Highlights (separate file; ≤ 85 characters each; counts checked):**
- Decoy varies its response timing to elicit reactions from attacker tools (72)
- Reaction time is measured net of the delay the decoy itself injected (68)
- Sessions are hashed to 64 bits and linked to persistent threat-actor IDs (72)
- Open-source prototype with weak-label scoring and an A/B control arm (68)
- *(only if the experiments are run)* Compared with text-only and no-perturbation baselines on real SSH traffic (73)

### 1. Introduction [900] [WRITE NOW]
- 1.1 Problem: automated attackers; honeypot logs are voluminous and unstructured; linking sessions to the same operator matters for intelligence. Source: report 1.1, 2.4.
- 1.2 Idea: perturb timing, read the reaction. One paragraph on why reaction time (not just command text) might carry operator information, with Song et al. 2001 for timing as a signal.
- 1.3 Research questions RQ1-RQ3 and contributions (Section 2 above).
- 1.4 What this paper does *not* claim (real-world accuracy beyond the data reported; superiority over unnamed systems). Keep the report's honest tone.
- 1.5 Paper structure with section numbers (journal requires numbered cross-references).

### 2. Related work [1,300] [NEEDS READING]
Organised by what each group does, ending with a comparison table (Table 1).
- 2.1 Honeypots and deception: Zhang and Thing 2021; Fan et al. 2018; Provos-style frameworks are not yet verified, so omit. LLM honeypots in one paragraph (Sladić; Wang; Bridges SoK) because the decoy has an optional LLM mode.
- 2.2 Clustering and profiling attackers from honeypot data: Crespi 2021, Shamsi 2022, Zhu 2022, Passino 2025, Boffa 2022a/b, Deshmukh 2019, Valeros 2023, Udhani 2019, Dumont 2019. **Full texts must be read first.** Compare on: data used, whether the goal is linking operators, whether timing is used, whether real data were used.
- 2.3 Active and adaptive honeypots: Wagener 2011 and 2010, Schneider 2021, Huang and Zhu 2019, Guan 2023, Dykstra 2025. This is where the contribution is positioned (Section 2 above).
- 2.4 Timing as a signal: Song et al. 2001; Almotairi et al. 2007 (inter-arrival times); Kuzminykh et al. (network conditions distort timing); Yurcik and Liu 2005 (command behaviour).
- 2.5 Detectability and measurement caveats: Holz and Raynal 2005; Vetterl and Clayton 2018; Srinivasa et al. 2023; Valeros 2026 (99.23% of authenticated sessions non-interactive).
- 2.6 Gap statement, scoped narrowly. The report already says a universal novelty claim needs a systematic review; keep that sentence in spirit.
- **Table 1:** related work compared on: active perturbation, uses timing, links sessions to actors, persistent IDs, real deployment, open code.

### 3. Threat model, ethics and data handling [500] [WRITE NOW, NEEDS DECISIONS]
- Attacker model: automated and manual SSH/HTTP clients; attacker may probe for honeypots; may change tools or pace.
- What the decoy never does: no real command execution (test A3), no outbound traffic from the decoy, isolated host.
- Data collected: credentials, commands, IP addresses, timing, HASSH, offered keys, HTTP headers. Retention, pseudonymisation (salted hash of IPs, as in Haikal et al.), credential handling, GDPR position, provider terms (Stage 5 in NEXT_STEPS). Ethics of deception: Zhu 2023.
- Source: report 5.1.2 (credential handling paragraph), CLAUDE.md items 4 and 6.

### 4. System design [1,800] [WRITE NOW]
- 4.1 Overview and architecture. Source: report 4.1. **Figure 1.**
- 4.2 SSH and HTTP decoys: asyncssh, aiohttp, banners, bait pages, login policy (accept on common password or third attempt), pseudo-filesystem, per-(IP, user) persistence for 24 h, pipes and redirects, system-command emulation, connection and rate limits. Files: `ssh_server.py`, `http_server.py`, `pseudo_fs.py`, `system_commands.py`, `limits.py`. Keep short; the ops detail goes to an appendix.
- 4.3 Timing perturbation: four regimes. **Table 2:** R0 0 ms from command 0; R1 100 ms from command index 2; R2 uniform 50-200 ms from index 4; R3 200 ms for filesystem-touching commands, else 50 ms, from index 6 (`perturbation.py`, `server.py`). SSH output drip capped at 0.3 s total (`R3_DRIP_BUDGET_S`); optional RL scheduler not used by default; control arm via `control_fraction` (arm chosen by session-ID hash). State C1 plainly here.
- 4.4 Measuring reaction time: Δt = arrival of next command minus end of our last response, via `mark_response_end()`, so injected delay and drip are excluded. This is the central measurement; include a timeline figure (**Figure 2**). Discuss the network-latency caveat (Kuzminykh).
- 4.5 Telemetry and corroborating signals. **Table 3:** HASSH (once per connection), offered public-key fingerprints (always refused), login-attempt order, HTTP header-name order hash, User-Agent, download URLs. Stated role: corroborate, never embedded (HASSH is shared by every user of a client library).
- 4.6 Features and embedding. **Table 4:** per-command step vector, 11 dimensions (log Δt scaled by 20; flags; URL; pipe; redirect; subshell; argument count; regime one-hot), from `transformer_model.py`. Transformer: 2 layers, 4 heads, d=32, learned positions, masked mean pooling, L2 normalisation. PCA baseline: per-regime median/std of log Δt, ratios to baseline, adaptation speed, six command-structure means, 10 TF-IDF features, 95% variance retained, padded to 32 (`features.py`, `embedding.py`, `cerf_engine.py`). Training: supervised contrastive loss (Khosla 2020) on random synthetic archetypes (C5).
- 4.7 CERF hash and actor assignment: 64 random hyperplanes (fixed seed) sign-LSH (Charikar 2002); Hamming threshold 6 (PCA) or 10 (Transformer); first-match rule; SQLite registry with fixed leader hash and re-matching only while a session grows (`clustering.py`). Order sensitivity (C6) and the PCA-refit issue (C4) stated here.
- 4.8 Analyst tooling: dashboard, blocklist and threat-intelligence export, canary alerts. One paragraph; screenshots not needed.

### 5. Experimental setup [900] [NEEDS DATA for 5.1-5.3; 5.4-5.5 WRITE NOW]
- 5.1 Real deployment: VPS, ports, period, code version, control fraction, raw counts, share of sessions that are interactive (answers the Valeros challenge). **Table 5.**
- 5.2 Synthetic benchmark: generator, archetypes, seeds (training, calibration seed 7, test seed 1000), and an explicit statement that it tests a simulator.
- 5.3 Ground truth: there is none for real traffic. Weak labels from shared dropper URL or SSH key, transitively; reported separately for URL-derived and key-derived labels because of C2; coverage always reported.
- 5.4 Methods compared: text-only baseline (TF-IDF + clustering, from the report's original idea; **to be implemented**), PCA backend, Transformer backend, and ablations (no timing features; no command features; control-arm-only).
- 5.5 Metrics: ARI against weak labels, coverage, number of actors, session length and early-disconnect rate by arm, threshold sensitivity, order sensitivity. Statistical tests and confidence intervals (bootstrap over sessions).
- 5.6 Validity threats listed in advance (feeds Section 7).

### 6. Results [1,500] [NEEDS DATA]
Skeleton only; no numbers until real data exist.
- 6.1 Deployment summary (**Table 5**: sessions, unique IPs, interactive share, commands per session).
- 6.2 Attribution against weak labels (**Table 6**: method × {URL labels, key labels} → ARI, coverage, actors).
- 6.3 Value of the perturbation signal (**Table 6 ablation rows**; **Figure 3** reaction time by regime, treatment vs control).
- 6.4 Engagement (**Table 7**: treatment vs control session length and early-disconnect rate; **Figure 4**).
- 6.5 Sensitivity (**Figure 5**: ARI and actor count vs threshold; order shuffle).
- 6.6 Synthetic benchmark (**Table 8**: 1.00 / 1.00 equal, 1.00 / 1.00 unequal, 0.49 (20 actors) vs 1.00 (6 actors) on six unseen archetypes; report Table 7.1, labelled as simulator results). `[WRITE NOW]`
- 6.7 Detectability check against honeypot-detection tools (Stage 1.3 part 2).
- 6.8 Resource use: measure on the real pipeline or omit the edge-device claim.

### 7. Discussion and limitations [800] [WRITE NOW, extend with data]
Does not repeat results (journal rule).
- What the results do and do not show; what real traffic would change.
- Limitations from the report 7.2, kept: network conditions distort Δt; different attackers with the same tool may share a fingerprint; short sessions carry little signal; thresholds and hash size tuned on synthetic data; first-match order dependence; perturbation may change attacker behaviour; plain HTTP only (no TLS fingerprints); dashboard without authentication.
- Added from this check: C1 (confounded regime and position), C2 (circular weak labels), C3 (same-generator evaluation), C5 (synthetic labels in training), ARCANE-style feature-indistinguishability ceiling, non-interactive majority (Valeros 2026), honeypot detectability (Vetterl 2018).
- Ethics and misuse: deception, attacker data, dual use of attribution.

### 8. Conclusion [300] [WRITE NOW, finalise with data]
Main conclusions only; future work: calibration on real traffic, TLS/JA4 fingerprints, dashboard authentication, container deployment, resource measurement.

### Back matter (journal order)
- Declaration of competing interests; funding statement (standard sentence if none)
- **Declaration of generative AI use**, in its own section before the references
- Data availability statement (**Option C: deposit required**, or state why not): dataset deposit with DOI; software archive with DOI (needs `LICENSE`, which the repo lacks, and a tagged release); both cited in the reference list
- CRediT author contributions; Acknowledgements (separate section before references; not on the title page)
- References (consistent style; DOIs; every reference verified); web references with access dates
- Appendix A: operational detail (limits, alerts, dashboard); Appendix B: reproduction commands
- Vitae (≤ 100 words and a photo each, separate editable file)

---

## 5. Figures and tables

| ID | Content | Source | Status |
|---|---|---|---|
| Fig 1 | System architecture | report Fig 4.1, redraw single-column | WRITE NOW |
| Fig 2 | One session: command timeline, regime, Δt with injected delay excluded | `docs/figures/fig4_regime_timeline_live_bot.png` as a base; retake on real session | NEEDS DATA |
| Fig 3 | Reaction time by regime, treatment vs control | new | NEEDS DATA |
| Fig 4 | Session length distributions by arm | new | NEEDS DATA |
| Fig 5 | Threshold sensitivity | new | NEEDS DATA |
| Fig 6 | Cluster view (optional) | `fig11_dashboard_cluster_view.png`, retake | optional |
| Graphical abstract | ≥ 1328 px wide, readable at 13 cm | new | after results |
| Table 1 | Related-work comparison | `docs/literature.md` | NEEDS READING |
| Table 2 | Regimes and delays | `perturbation.py`, `server.py` | WRITE NOW |
| Table 3 | Signals and their role | `signals.py`, report 5.1.2 | WRITE NOW |
| Table 4 | Per-step features and model configuration | `transformer_model.py`, `features.py` | WRITE NOW |
| Table 5 | Datasets | deployment | NEEDS DATA |
| Tables 6-8 | Attribution; engagement; synthetic benchmark | experiments; report Table 7.1 | see Section 6 |

Figure and table rules: titles ≤ 15 words and legends ≤ 300 words in the manuscript, not in the image; 85 or 170 mm wide at about 300 dpi; real Word table objects, no colour or shading in tables. Not yet read: the Guide's own figure and table pages for Elsevier specifics, so confirm before building the package.

## 6. Word budget

| Part | Words |
|---|---|
| Abstract | 250 |
| 1 Introduction | 900 |
| 2 Related work | 1,300 |
| 3 Threat model and ethics | 500 |
| 4 System design | 1,800 |
| 5 Experimental setup | 900 |
| 6 Results | 1,500 |
| 7 Discussion and limitations | 800 |
| 8 Conclusion | 300 |
| Declarations and statements | 400 |
| References (about 55) | 1,100 |
| **Total** | **about 9,750** (cap 12,000) |

## 7. What can be written now versus later

**Now** (no new data needed): Sections 1, 3 (apart from the retention numbers), 4, 5.2, 5.4-5.5, 6.6, and the limitations in 7; Tables 2-4; Figure 1.
**After reading:** Section 2 and Table 1 (full texts of Crespi, Shamsi, Zhu, Wagener).
**After the deployment and experiments:** Abstract findings, 5.1, 5.3, Sections 6.1-6.5 and 6.7-6.8, Section 8, highlights 4, the graphical abstract.

## 8. Things I did not do
- No prose has been drafted, only structure and facts.
- The text-only baseline and ablations do not exist in the code yet; the plan assumes they will be implemented.
- C4 (PCA refit) is inferred from reading the code, not tested.
