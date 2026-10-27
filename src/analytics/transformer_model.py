import os
import torch
import torch.nn as nn
import numpy as np

REGIMES = ["baseline", "slowdown", "jitter", "fs_latency"]
# Per-step features: log reaction time + 6 AST + one-hot of the regime that reaction was to
STEP_DIM = 1 + 6 + len(REGIMES)
DEFAULT_WEIGHTS = os.path.join(os.path.dirname(__file__), "weights", "cerf_transformer.pt")

class SpatioTemporalTransformer(nn.Module):
    def __init__(self, input_dim=STEP_DIM, d_model=32, nhead=4, num_layers=2):
        super().__init__()
        self.d_model = d_model
        # Project raw features into d_model dimensions
        self.input_projection = nn.Linear(input_dim, d_model)
        
        # Standard Transformer Encoder
        encoder_layers = nn.TransformerEncoderLayer(d_model=d_model, nhead=nhead, dim_feedforward=64, batch_first=True)
        self.transformer_encoder = nn.TransformerEncoder(encoder_layers, num_layers=num_layers)
        
        # Positional encoding (learned) - assumes max seq len of 1000
        self.pos_encoder = nn.Embedding(1000, d_model)
        
    def forward(self, x, padding_mask=None):
        # x shape: (batch_size, seq_len, input_dim); padding_mask: (batch_size, seq_len), True = pad
        batch_size, seq_len, _ = x.shape
        
        x = self.input_projection(x)
        
        # Add positional encoding
        positions = torch.arange(0, seq_len, dtype=torch.long, device=x.device).unsqueeze(0).expand(batch_size, seq_len)
        x = x + self.pos_encoder(positions)
        
        # Pass through transformer
        encoded = self.transformer_encoder(x, src_key_padding_mask=padding_mask)
        
        # Masked mean pooling, then L2-normalise so sign-LSH bits track angular distance
        if padding_mask is None:
            pooled = encoded.mean(dim=1)
        else:
            keep = (~padding_mask).unsqueeze(-1).float()
            pooled = (encoded * keep).sum(dim=1) / keep.sum(dim=1).clamp(min=1.0)
        return nn.functional.normalize(pooled, dim=-1)

class TransformerEmbeddingModel:
    def __init__(self, models_dir: str = "models", seed: int = 42, weights_path: str = None):
        """weights_path: None = bundled trained weights, "" = untrained (for training)."""
        self.models_dir = models_dir
        self.seed = seed
        self.device = torch.device("cpu") # Keep it CPU for simplicity in decoy server
        
        torch.manual_seed(self.seed)
        np.random.seed(self.seed)
        
        self.model = SpatioTemporalTransformer()
        self.weights_loaded = False
        if weights_path is None:
            weights_path = DEFAULT_WEIGHTS
        if weights_path and os.path.exists(weights_path):
            self.model.load_state_dict(torch.load(weights_path, map_location=self.device))
            self.weights_loaded = True
        self.model.eval()
        
        self.lsh_matrix = None
        os.makedirs(self.models_dir, exist_ok=True)
        self._init_lsh()
        
    def _init_lsh(self, dim: int = 32, num_bits: int = 64):
        np.random.seed(self.seed)
        self.lsh_matrix = np.random.randn(dim, num_bits)

    def extract_sequence_features(self, session_df) -> np.ndarray:
        """
        Converts a session DataFrame into a sequence of feature vectors.
        Output shape: (seq_len, STEP_DIM)

        Each step pairs a command's structure with the reaction time that preceded it and the regime
        of the response that reaction was to (the previous row's regime). Command 0 has no preceding
        response, so its timing is 0 and its regime one-hot is all zeros.
        """
        seq = []
        for i, (_, row) in enumerate(session_df.sort_values("command_index").iterrows()):
            if i == 0:
                reaction_regime, reaction_dt = None, 0.0
            else:
                reaction_regime, reaction_dt = previous_regime, float(row["delta_t_ns"])
            previous_regime = row["regime"] if "regime" in row else "baseline"
            cmd = str(row["command_raw"])
            tokens = cmd.split()
            args = tokens[1:] if len(tokens) > 1 else []
            
            # 1 timing (log ns, scaled to ~[0, 1]) + 6 AST features + regime one-hot
            dt = float(np.log1p(reaction_dt)) / 20.0
            n_flags = sum(1 for a in args if a.startswith("-"))
            has_url = 1.0 if any("http://" in a or "https://" in a for a in tokens) else 0.0
            has_pipe = 1.0 if "|" in cmd else 0.0
            has_redir = 1.0 if ">" in cmd else 0.0
            has_subshell = 1.0 if "$(" in cmd or "`" in cmd else 0.0
            n_args = len(args)
            
            regime_onehot = [1.0 if reaction_regime == r else 0.0 for r in REGIMES]
            step_features = [dt, n_flags, has_url, has_pipe, has_redir, has_subshell, n_args] + regime_onehot
            seq.append(step_features)
            
        return np.array(seq, dtype=np.float32).reshape(-1, STEP_DIM)

    def fit_transform(self, X_seq_list) -> np.ndarray:
        """
        X_seq_list is a list of numpy arrays, each (seq_len, 7)
        We pad them and run through the model.
        """
        if not X_seq_list:
            return np.array([])
            
        embeddings = []
        with torch.no_grad():
            for seq in X_seq_list:
                if len(seq) == 0:
                    embeddings.append(np.zeros(32))
                    continue
                # (1, seq_len, 7)
                x = torch.tensor(seq, dtype=torch.float32).unsqueeze(0).to(self.device)
                emb = self.model(x).squeeze(0).numpy()
                embeddings.append(emb)
                
        return np.array(embeddings)
        
    def compute_cerf_hash(self, vec_32d: np.ndarray) -> str:
        projections = np.dot(vec_32d, self.lsh_matrix)
        bits = (projections > 0).astype(int)
        bit_str = "".join(map(str, bits))
        hex_str = f"{int(bit_str, 2):016x}"
        return hex_str
