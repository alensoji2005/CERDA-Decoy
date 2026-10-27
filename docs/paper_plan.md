# CERDA journal paper: plan (2026-10-27)

Target: **Computers & Security (Elsevier), subscription route, article type "Full Length Article"**.
Sources: Final_Report_BCSE497J_Revised.docx, the repo (CLAUDE.md, NEXT_STEPS.md), and the journal's Guide for Authors (read 2026-10-27).
This is a plan only. Nothing has been written or changed in the paper yet.

## 1. Decisions needed before any writing

| # | Decision | Why it matters |
|---|---|---|
| D1 | **Patent vs. publication.** NEXT_STEPS.md and pmd-v2.md talk about patent claims and "patent proof". | Publishing, or even posting a preprint, is a public disclosure and can end patentability in many jurisdictions. Ask the guide / VIT's IPR cell **before** posting anything. |
| D2 | **Who the authors are.** The report has 3 students plus supervisor Dr. Sudha S. | Elsevier needs all authors' approval and the university's approval. Fixes author order, corresponding author, and the CRediT roles. |
| D3 | **Real data or not.** | See section 2. This is the biggest risk to acceptance. |
| D4 | **What data can be deposited.** | The journal requires a deposit or a stated reason (section 3). Raw sessions contain attacker IPs and possibly real leaked credentials. |
| D5 | **Disclosing AI tools.** | A statement is mandatory at submission if any generative AI was used in preparing the manuscript. Be accurate about writing help and about AI-assisted coding. |
| D6 | **Fee route.** | Subscription = no fee, paywalled for readers. Open access = APC (not looked up yet). Chosen at acceptance, so it does not block the work. |

## 2. Is the project paper-ready? An honest gap list

The report itself says (Sections 7.1, 7.2) that every result is synthetic or from the authors' own bot. That is fine for a thesis. For a security journal it is the main weakness:

1. **ARI 1.00 is circular.** The Transformer was trained on archetypes from the same simulator that generated the test set. Report Table 7.1 shows the simulator, not attacker behaviour.
2. **The central research question is unanswered.** The report asks whether the reaction to perturbation adds information beyond command text. There is no text-only baseline (TF-IDF + K-Means) and no ablation (with vs. without the perturbation signals).
3. **No real traffic.** The decoy has only run on localhost. Stage 2 (VPS) and Stage 3 (weak labels, A/B, retrain) in NEXT_STEPS.md are not done.
4. **Thresholds are uncalibrated** (6 bits PCA, 10 bits Transformer), tuned on synthetic data.
5. **No engagement result.** The A/B control arm is implemented but never run on real traffic, so there is no evidence that the perturbation does not drive attackers away.
6. **No resource figures.** Edge/CPU claims are unmeasured, so the paper must not make them.
7. **No detectability check.** Stage 1.3 part 2 (external honeypot-detection tools) is open.

**Fallback if real data is thin:** frame it as a framework paper with a small preliminary deployment, state the limits plainly, and expect reviewers to push back. Alternative: a workshop paper first.

## 3. What the journal requires (read from the Guide for Authors)

Read in full: file format, title page, abstract, keywords, highlights, graphical abstract, article structure, length, references, research data, preprints, generative AI, checklist.
**Not yet read:** the Guide's sections on figures, tables and supplementary material, and the open-access fee. Read these before the submission package is built.

| Item | Requirement |
|---|---|
| File | .docx or .tex. **Word must be single-column**; PDF is not accepted. Remove strikethrough and underline. |
| Length | **12,000 words maximum including abstract, text, references and appendices.** |
| Title page | Concise title (no avoidable abbreviations); full names; affiliations with **lowercase superscript letters** and full postal address with country; corresponding author with email. |
| Abstract | **≤ 250 words**, stand-alone, no references, abbreviations defined. (The report's abstract is about 430 words and must be cut.) |
| Keywords | 5-10, English, avoid multi-word phrases built with "and"/"of". |
| Highlights | Encouraged: separate editable file with "highlights" in the name; 3-5 bullets, **≤ 85 characters each**. |
| Graphical abstract | Encouraged: ≥ 1328 px wide, readable at 13 cm, TIFF/EPS/PDF/Office. |
| Sections | Numbered 1, 1.1, 1.1.1; cross-reference by number; abstract is not numbered. |
| Structure | Introduction (objectives, not a lit dump); Methods (reproducible); Results; Discussion (do not repeat results); Conclusion. |
| Back matter | Acknowledgements (own section before references); **CRediT** author contributions; **Vitae** (≤ 100 words + photo per author, editable file); appendices labelled A, B with Eq. (A.1), Table A.1. |
| Mandatory declarations | Competing interests; funding (standard sentence if none); **generative AI statement** in its own section before the reference list; data statement. |
| Research data | **Option C: required** to deposit data in a repository and cite/link it in the article, or state why it cannot be shared. |
| References | Any consistent style at submission; Elsevier applies its style at proof. In-text author-year ("Smith et al., 2023"). Every reference must be real; include DOIs. |
| Preprints | Allowed and not counted as prior publication. Free SSRN posting offered at submission. (See D1 first.) |
| Prior publication | The thesis counts as an allowed prior form ("academic thesis"). |

## 4. Work plan

### Phase A: Decisions and legal (this week)
- Resolve D1, D2, D5 with the guide and co-authors.
- Stage 5 of NEXT_STEPS.md, before deploying: check the VPS provider's terms for running a honeypot, set a retention policy, and decide whether a GDPR/ethics note is needed for storing IPs.
- Add a LICENSE, tag a release, and archive it on Zenodo for a DOI. The data and software statement needs it.

### Phase B: Collect real data (2-4 weeks, runs in the background)
- Deploy on a VPS (Stage 2). Run the A/B control arm from day one (`control_fraction`).
- Freeze the code version used for collection and record it.

### Phase C: Experiments the paper needs
Research questions:
- RQ1: does attacker reaction to timing perturbation add attribution signal beyond command text?
- RQ2: does the perturbation reduce engagement (session length, early disconnects) compared with the control arm?
- RQ3: how stable are actor assignments over time, and how sensitive are they to the Hamming threshold?

| Experiment | Details |
|---|---|
| Baselines | Text-only TF-IDF + K-Means (the original IEEE draft's method); PCA backend; Transformer backend. |
| Ablation | Remove reaction-time features; remove command features; remove each corroborating signal. |
| Split | Calibrate thresholds on the first period, report on a later held-out period. Never tune and report on the same data. |
| Scoring | Weak labels (shared dropper URL / offered SSH key) used **only for scoring, never for training**. Say clearly this is partial ground truth, not attacker identity. |
| Synthetic benchmark | Keep it, but evaluate on archetype families held out from training, and label it as a simulator test. |
| Engagement | Session duration and commands per session, perturbed vs. control arm, with a significance test. |
| Cost | Measure CPU/RAM on the real pipeline, or drop the edge-device claim. |
| Detectability | Run public honeypot-detection tools (closes Stage 1.3 part 2). |

### Phase D: Literature (before drafting)
The report has about 17 references, several incomplete (e.g. [6] "N. T. N.", [9], [11], [14] lack authors, venue or DOI). Needed: honeypot attribution and fingerprinting (Cowrie-style logs, HASSH, JA3/JA4), timing-based bot/human discrimination, honeypot detectability, tarpitting, and shell-session clustering. Every reference gets checked against its real source and given a DOI. The old IEEE draft's TF-IDF + K-Means framing is obsolete and must not be reused.

### Phase E: Draft (target about 9,500 words including references)

| § | Section | Words | Source in report |
|---|---|---|---|
| | Abstract | ≤ 250 | rewrite (current one is about 430) |
| 1 | Introduction, RQs, contributions | 900 | Ch. 1, 2.2, 2.4 |
| 2 | Related work | 1,300 | Ch. 2.1, plus new literature |
| 3 | Threat model and ethics | 500 | new; safety, isolation, data handling |
| 4 | System design (decoy, regimes, telemetry, CERF, registry) | 1,800 | Ch. 4, 5.1 |
| 5 | Experimental setup (datasets, baselines, metrics, validity) | 900 | Ch. 5.2, new |
| 6 | Results | 1,500 | Ch. 7.1, replaced with real-data results |
| 7 | Discussion, limitations, detectability | 800 | Ch. 7.2 |
| 8 | Conclusion | 300 | Ch. 8 |
| | Declarations, acknowledgements, AI statement, references | about 1,500 | |

**Dropped from the report:** declaration/certificate/front matter, Gantt chart, feasibility study, hardware/software spec tables, cost analysis, use-case diagram, sample-code appendix (replace with a repository link).
**Reused:** architecture and data-flow diagrams, the regime-timeline and cluster-view figures (re-taken on real data), and the existing wording of the limitations section.

### Phase F: Submission package
- Manuscript .docx, single-column, with line numbers, title page and numbered sections
- Highlights file (3-5 bullets, ≤ 85 characters each)
- Graphical abstract (optional)
- Vitae file with photos
- Figures and tables per the Guide's sections not yet read
- Dataset deposit (DOI) and software archive (DOI), both cited in the Data statement
- Declarations: competing interests, funding, CRediT, generative AI
- Cover letter and suggested reviewers (the portal asks for these)

## 5. Order of work

A (decisions) → B (start collecting immediately) → D (literature, in parallel with B) → C (once data exists) → E → F.
The real-data run is the long pole; start it first.

## 6. Notes on the existing files
- `IEEE_Paper_Threat_Clustering_Honeypot.docx` was an early proposal (TF-IDF + K-Means, "planned evaluation"). It did not describe the built system and was removed from the repository on 2026-10-27.
- `Final_Report_BCSE497J_Revised.docx` is the right base for the design sections. It uses numeric IEEE-style citations and the report's own layout, both of which must be converted.
