# CERDA: Counterfactual Execution-Rhythm Decoy Architecture

CERDA is an active honeypot/decoy system that actively perturbs response timing across multiple regimes to extract automated attacker script timing responses. It generates a 64-bit Locality-Sensitive Hash (LSH) fingerprint (CERF) to attribute and cluster threat actors based on their timing reactions.

## Features
- **Module A (Decoy Server):** Non-blocking SSH and HTTP listeners with a stateful pseudo-filesystem and counterfactual timing perturbation engine.
- **Module B (CERF Analytics):** Extracts timing features and AST command structures, utilizing PCA and LSH for highly deterministic threat actor fingerprinting.
- **Module C (Dashboard):** Streamlit-based Threat Intelligence Dashboard with Retro CLI and Academic theme toggles, interactive Network Topology graphs, and Regime Timeline plots.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

Run everything from the repo root.

```bash
python decoy_server.py [--tarpit] [--rl] # SSH-like :2222, HTTP-like :8080 -> telemetry.csv, regime_schedule.csv
python cerf_engine.py [telemetry.csv]   # fingerprint + cluster -> sessions.csv, cerf_clusters.json
streamlit run dashboard.py              # threat intel dashboard
python -m src.analytics.blocklist       # sessions.csv -> cerda_blocklist.txt / .nft (never auto-applied)
pytest tests/ -v                        # acceptance tests (A1-A4, B1-B7, C1-C3, RL, blocklist, v2)
```

Docker (decoy with tarpit + dashboard on `127.0.0.1:8501`, shared `/data` volume):

```bash
docker compose up --build
```

Notes:
- `--tarpit` shrinks the TCP receive window on the decoy's listening sockets so attacker sends are throttled at the network layer. The effect is strongest on Linux.
- The blocklist exporter validates every IP. Review `cerda_blocklist.nft`, then apply it yourself with `sudo nft -f cerda_blocklist.nft`.

Demo helpers (in `scripts/`):

```bash
python -m scripts.generate_demo_data    # synthetic telemetry + CERF run, no server needed
python -m scripts.attacker_client 2222  # interactive attacker shell against the decoy
python -m scripts.bot_attacker          # automated bot session against the decoy
python -m scripts.train_transformer     # retrain the Transformer embedding (~9 min CPU)
```

Configuration (`.env`):
- `GEMINI_API_KEY`: enables the live LLM for decoy file and command output (otherwise deterministic mock output is used).
- `CERDA_LLM_MODEL`: Gemini model id (default `gemini-2.5-flash`).

The CERF engine has two embedding backends:
- `embedding="transformer"` (default): a trained Spatio-Temporal Transformer whose weights ship in `src/analytics/weights/`. Retrain with `python -m scripts.train_transformer`.
- `embedding="pca"`: the baseline. It is also the automatic fallback when the weights file is missing.

Benchmark both with `python -m src.analytics.benchmark` (held-out scenarios, adjusted Rand index):

| Scenario | PCA | Transformer |
|---|---|---|
| Script A/B, equal length | 1.00 | 1.00 |
| Script A/B, unequal length | 1.00 | 1.00 |
| 6 unseen random archetypes | ~0.49 | 1.00 |

## Current Version & Status

The project is currently finalizing **v1.0** with all core modules (Decoy Server, CERF Analytics, and Threat Dashboard) fully functional and passing acceptance tests. 

Additionally, several **v2.0 experimental features** have already been integrated:
- **RL Regime Selection:** Reinforcement Learning-based dynamic perturbation scheduling.
- **LLM-Driven Decoy FS:** Generative AI-powered stateful pseudo-filesystem responses.
- **Spatio-Temporal Transformer:** Advanced deep learning model for threat actor fingerprinting.

## Architecture Details
This repository contains a patent-verifiable prototype demonstrating that Active CERF Perturbation + LSH achieves ≥90% attribution accuracy on automated attack scripts, outperforming static TF-IDF text baselines.
