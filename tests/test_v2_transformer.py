import pytest
import numpy as np
import pandas as pd
from src.analytics.transformer_model import TransformerEmbeddingModel

def test_transformer_shape_and_determinism():
    model = TransformerEmbeddingModel(seed=42)
    
    # Create mock session df
    data = {
        "command_raw": ["ls -la", "wget http://test.com", "chmod +x file.sh"],
        "command_index": [0, 1, 2],
        "delta_t_ns": [3000, 105000, 120000]
    }
    df = pd.DataFrame(data)
    
    # Extract sequence features
    seq = model.extract_sequence_features(df)
    assert seq.shape == (3, 7) # 3 commands, 7 features (1 dt + 6 AST)
    
    # Run through transformer
    emb1 = model.fit_transform([seq])
    assert emb1.shape == (1, 32)
    
    # Test determinism
    emb2 = model.fit_transform([seq])
    np.testing.assert_array_almost_equal(emb1, emb2)

def test_cerf_hash_generation():
    model = TransformerEmbeddingModel(seed=42)
    vec = np.random.RandomState(42).randn(32)
    
    cerf = model.compute_cerf_hash(vec)
    assert len(cerf) == 16 # 64 bits = 16 hex chars
    
    # Same vec should produce same hash
    cerf2 = model.compute_cerf_hash(vec)
    assert cerf == cerf2
