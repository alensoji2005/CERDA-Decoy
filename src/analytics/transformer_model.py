import os
import torch
import torch.nn as nn
import numpy as np

class SpatioTemporalTransformer(nn.Module):
    def __init__(self, input_dim=7, d_model=32, nhead=4, num_layers=2):
        super().__init__()
        self.d_model = d_model
        # Project raw features into d_model dimensions
        self.input_projection = nn.Linear(input_dim, d_model)
        
        # Standard Transformer Encoder
        encoder_layers = nn.TransformerEncoderLayer(d_model=d_model, nhead=nhead, batch_first=True)
        self.transformer_encoder = nn.TransformerEncoder(encoder_layers, num_layers=num_layers)
        
        # Positional encoding (learned) - assumes max seq len of 1000
        self.pos_encoder = nn.Embedding(1000, d_model)
        
    def forward(self, x):
        # x shape: (batch_size, seq_len, input_dim)
        batch_size, seq_len, _ = x.shape
        
        # Project input and scale
        x = self.input_projection(x) * 10.0
        
        # Add positional encoding
        positions = torch.arange(0, seq_len, dtype=torch.long, device=x.device).unsqueeze(0).expand(batch_size, seq_len)
        x = x + self.pos_encoder(positions)
        
        # Pass through transformer
        encoded = self.transformer_encoder(x)
        
        # Mean pooling to get sequence-level embedding
        # shape: (batch_size, d_model)
        seq_embedding = encoded.mean(dim=1)
        
        return seq_embedding

class TransformerEmbeddingModel:
    def __init__(self, models_dir: str = "models", seed: int = 42):
        self.models_dir = models_dir
        self.seed = seed
        self.device = torch.device("cpu") # Keep it CPU for simplicity in decoy server
        
        torch.manual_seed(self.seed)
        np.random.seed(self.seed)
        
        self.model = SpatioTemporalTransformer()
        self.model.eval() # We use it untrained as a robust random projection, or it can be trained later
        
        self.lsh_matrix = None
        os.makedirs(self.models_dir, exist_ok=True)
        self._init_lsh()
        
    def _init_lsh(self, dim: int = 32, num_bits: int = 64):
        np.random.seed(self.seed)
        self.lsh_matrix = np.random.randn(dim, num_bits)

    def extract_sequence_features(self, session_df) -> np.ndarray:
        """
        Converts a session DataFrame into a sequence of feature vectors.
        Output shape: (seq_len, 7)
        """
        seq = []
        for _, row in session_df.sort_values("command_index").iterrows():
            cmd = str(row["command_raw"])
            tokens = cmd.split()
            args = tokens[1:] if len(tokens) > 1 else []
            
            # 1 timing + 6 AST features
            dt = float(np.log1p(row["delta_t_ns"]))
            n_flags = sum(1 for a in args if a.startswith("-"))
            has_url = 1.0 if any("http://" in a or "https://" in a for a in tokens) else 0.0
            has_pipe = 1.0 if "|" in cmd else 0.0
            has_redir = 1.0 if ">" in cmd else 0.0
            has_subshell = 1.0 if "$(" in cmd or "`" in cmd else 0.0
            n_args = len(args)
            
            step_features = [dt, n_flags, has_url, has_pipe, has_redir, has_subshell, n_args]
            seq.append(step_features)
            
        return np.array(seq, dtype=np.float32)

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
