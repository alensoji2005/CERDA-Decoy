# Manuscript package (2026-10-27)

Target: Computers & Security, Full Length Article.

| File | What it is |
|---|---|
| `CERDA_manuscript.docx` | Manuscript: single column, A4, double spacing, continuous line numbers, numbered sections, tables as Word tables, figures embedded, declarations and references. Items in `[CONFIRM: ...]` need the authors. |
| `CERDA_manuscript_highlights.docx` | Highlights file (3-5 bullets, at most 85 characters each), uploaded separately. |
| `cover_letter_DRAFT.docx` | Draft cover letter with candidate reviewers (names only; the authors must verify affiliations, emails and conflicts). |
| `figures/` | The four figures and the graphical abstract (`graphical_abstract.png`, 1620 x 750 px) as PNG at 300 dpi. |
| `build/` | Sources that produce the manuscript: `content.js` (text; result numbers are read from `sensitivity.json`), `build.js`, `fig1.py`, `fig2.py`, `fig34.py`, `ga.py`, `cover.js`. |

Rebuild (from `build/`, needs Node with the `docx` package and Python with matplotlib):

    SENS=sensitivity.json FIGS=../figures OUT=../CERDA_manuscript.docx node build.js

Results are regenerated with `python -m scripts.sensitivity`, `python -m scripts.hash_stability` and `python -m src.analytics.benchmark` from the repository root.

Not produced (needs the authors): Vitae with photos, CRediT statement, funding and competing-interest confirmations, corresponding-author details, and the archived release DOI (the repository is public and MIT-licensed; push and tag first).
