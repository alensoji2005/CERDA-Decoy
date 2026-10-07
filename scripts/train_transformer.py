"""Train the Spatio-Temporal Transformer CERF embedding (Patent Claim 8).

Supervised contrastive training on randomly generated attacker archetypes
(src.analytics.synthetic.random_family). The canonical Script A/B benchmarks are
never seen in training, so tests B3-B6 measure generalisation.

Run from the repo root: python -m scripts.train_transformer [--steps N]
Writes src/analytics/weights/cerf_transformer.pt (reproducible via --seed).
"""
import argparse
import os

import numpy as np
import torch

from src.analytics.synthetic import random_family, generate_family_sessions
from src.analytics.transformer_model import SpatioTemporalTransformer, TransformerEmbeddingModel, DEFAULT_WEIGHTS


def make_batch(rng, extractor, families_per_batch, sessions_per_family):
    seqs, labels = [], []
    for label in range(families_per_batch):
        df = generate_family_sessions(random_family(rng), sessions_per_family, rng, family_id=str(label))
        for _, sdf in df.groupby("session_id"):
            seqs.append(extractor.extract_sequence_features(sdf))
            labels.append(label)
    max_len = max(len(s) for s in seqs)
    x = torch.zeros(len(seqs), max_len, seqs[0].shape[1])
    pad = torch.ones(len(seqs), max_len, dtype=torch.bool)
    for i, s in enumerate(seqs):
        x[i, :len(s)] = torch.from_numpy(s)
        pad[i, :len(s)] = False
    return x, pad, torch.tensor(labels)


def supcon_loss(z, labels, temperature=0.1):
    """Supervised contrastive loss (Khosla et al., 2020) on L2-normalised embeddings."""
    sim = z @ z.T / temperature
    self_mask = torch.eye(len(z), dtype=torch.bool)
    sim = sim.masked_fill(self_mask, -1e9)
    pos = (labels[:, None] == labels[None, :]) & ~self_mask
    log_prob = sim - torch.logsumexp(sim, dim=1, keepdim=True)
    return -(log_prob * pos).sum(1).div(pos.sum(1).clamp(min=1)).mean()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--steps", type=int, default=1500)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", default=DEFAULT_WEIGHTS)
    args = parser.parse_args()

    torch.manual_seed(args.seed)
    rng = np.random.default_rng(args.seed)
    extractor = TransformerEmbeddingModel(models_dir="models", weights_path="")
    model = SpatioTemporalTransformer()
    opt = torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)

    model.train()
    for step in range(1, args.steps + 1):
        x, pad, labels = make_batch(rng, extractor, families_per_batch=8, sessions_per_family=4)
        loss = supcon_loss(model(x, pad), labels)
        opt.zero_grad()
        loss.backward()
        opt.step()
        if step % 100 == 0:
            print(f"step {step:5d}  loss {loss.item():.4f}")

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    torch.save(model.state_dict(), args.out)
    print(f"Saved weights to {args.out}")


if __name__ == "__main__":
    main()
