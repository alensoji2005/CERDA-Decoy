import os
import joblib
import numpy as np
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
from typing import Tuple

# Keep only the principal components carrying this share of variance. Trailing
# components hold within-actor timing noise (e.g. few jitter samples in short
# sessions) that would otherwise flip LSH bits and fragment threat actors.
PCA_VARIANCE_RETAINED = 0.95

class CERFEmbeddingModel:
    def __init__(self, models_dir: str = "models", seed: int = 42):
        self.models_dir = models_dir
        self.seed = seed
        self.scaler = StandardScaler()
        self.pca = None
        self.lsh_matrix = None
        
        os.makedirs(self.models_dir, exist_ok=True)
        self._init_lsh()
        
    def _init_lsh(self, dim: int = 32, num_bits: int = 64):
        np.random.seed(self.seed)
        self.lsh_matrix = np.random.randn(dim, num_bits)

    def fit_transform(self, X: np.ndarray) -> np.ndarray:
        X_scaled = self.scaler.fit_transform(X)
        n_samples, n_features = X_scaled.shape
        max_comp = min(32, n_samples, n_features)
        
        self.pca = PCA(n_components=max_comp, random_state=self.seed)
        X_pca = self.pca.fit_transform(X_scaled)
        if n_samples > 1:
            cum = np.cumsum(self.pca.explained_variance_ratio_)
            keep = int(np.searchsorted(cum, PCA_VARIANCE_RETAINED) + 1)
            X_pca = X_pca[:, :min(keep, max_comp)]
        
        if X_pca.shape[1] < 32:
            pad_width = 32 - X_pca.shape[1]
            X_pca = np.pad(X_pca, ((0, 0), (0, pad_width)), mode='constant')
            
        joblib.dump(self.scaler, os.path.join(self.models_dir, "scaler.pkl"))
        joblib.dump(self.pca, os.path.join(self.models_dir, "pca.pkl"))
        
        return X_pca

    def compute_cerf_hash(self, vec_32d: np.ndarray) -> str:
        projections = np.dot(vec_32d, self.lsh_matrix)
        bits = (projections > 0).astype(int)
        bit_str = "".join(map(str, bits))
        hex_str = f"{int(bit_str, 2):016x}"
        return hex_str
