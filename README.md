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

**1. Run the Streamlit Dashboard:**
```bash
streamlit run dashboard.py
```

**2. Run the Decoy Server (Background):**
You can run the decoy server listeners asynchronously in a Python shell or an entry script.

**3. Run the Benchmark & Test Suite:**
```bash
pytest tests/ -v
```

## Current Version & Status

The project is currently finalizing **v1.0** with all core modules (Decoy Server, CERF Analytics, and Threat Dashboard) fully functional and passing acceptance tests. 

Additionally, several **v2.0 experimental features** have already been integrated:
- **RL Regime Selection:** Reinforcement Learning-based dynamic perturbation scheduling.
- **LLM-Driven Decoy FS:** Generative AI-powered stateful pseudo-filesystem responses.
- **Spatio-Temporal Transformer:** Advanced deep learning model for threat actor fingerprinting.

## Architecture Details
This repository contains a patent-verifiable prototype demonstrating that Active CERF Perturbation + LSH achieves ≥90% attribution accuracy on automated attack scripts, outperforming static TF-IDF text baselines.
