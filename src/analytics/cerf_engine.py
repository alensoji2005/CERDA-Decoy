import os
import json
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple
from sklearn.feature_extraction.text import TfidfVectorizer

from .sanitization import sanitize_command
from .features import FeatureExtractor
from .embedding import CERFEmbeddingModel
from .transformer_model import TransformerEmbeddingModel
from .clustering import CERFClusterer

class CERFEngine:
    # Hamming-distance clustering threshold, validated per embedding backend
    CLUSTER_THRESHOLDS = {"pca": 6, "transformer": 2}

    def __init__(self, telemetry_path: str = "telemetry.csv", output_dir: str = ".", embedding: str = "pca"):
        """embedding: "pca" (timing + AST + TF-IDF -> PCA, the validated default) or
        "transformer" (Spatio-Temporal Transformer over per-command sequences)."""
        if embedding not in ("pca", "transformer"):
            raise ValueError(f"Unknown embedding backend: {embedding}")
        self.telemetry_path = telemetry_path
        self.output_dir = output_dir
        self.embedding = embedding
        models_dir = os.path.join(output_dir, "models")
        if embedding == "pca":
            self.feature_extractor = FeatureExtractor()
            self.embedding_model = CERFEmbeddingModel(models_dir=models_dir)
        else:
            self.embedding_model = TransformerEmbeddingModel(models_dir=models_dir)
        self.clusterer = CERFClusterer()
        self.features = {}
        self.session_meta = {}
        self.pca_vectors = {}
        
    def load_telemetry(self) -> pd.DataFrame:
        return self.load_and_sanitize()

    def load_and_sanitize(self) -> pd.DataFrame:
        if not os.path.exists(self.telemetry_path):
            raise FileNotFoundError(f"Telemetry file not found at {self.telemetry_path}")
        df = pd.read_csv(self.telemetry_path)
        df["command_raw"] = df["command_raw"].astype(str).apply(sanitize_command)
        return df

    def extract_features(self, df: pd.DataFrame) -> Dict[str, np.ndarray]:
        sessions = df["session_id"].unique()
        if self.embedding == "pca":
            session_cmds = [" ".join(df[df["session_id"] == s]["command_raw"].tolist()) for s in sessions]
            tfidf_matrix = TfidfVectorizer(max_features=10).fit_transform(session_cmds).toarray()
            if tfidf_matrix.shape[1] < 10:
                tfidf_matrix = np.pad(tfidf_matrix, ((0, 0), (0, 10 - tfidf_matrix.shape[1])), mode='constant')

        self.features = {}
        self.session_meta = {}
        
        for idx, session_id in enumerate(sessions):
            sdf = df[df["session_id"] == session_id].sort_values("command_index")
            if self.embedding == "pca":
                t_feats = self.feature_extractor.extract_session_features(sdf)
                self.features[session_id] = np.concatenate([list(t_feats.values()), tfidf_matrix[idx]])
            else:
                self.features[session_id] = self.embedding_model.extract_sequence_features(sdf)
            
            dominant_regime = sdf["regime"].mode()[0] if not sdf["regime"].empty else "baseline"
            source_ip = sdf["source_ip"].iloc[0] if not sdf.empty else "0.0.0.0"
            num_commands = len(sdf)
            
            self.session_meta[session_id] = {
                "session_id": session_id,
                "source_ip": source_ip,
                "num_commands": num_commands,
                "dominant_regime": dominant_regime
            }
            
        return self.features

    def _embed(self, feats: List[np.ndarray]) -> np.ndarray:
        if self.embedding == "pca":
            return self.embedding_model.fit_transform(np.array(feats))
        return self.embedding_model.fit_transform(feats)

    def train_embedding_model(self, features: Dict[str, np.ndarray]):
        session_ids = list(features.keys())
        X_pca = self._embed([features[s] for s in session_ids])
        for i, s in enumerate(session_ids):
            self.pca_vectors[s] = X_pca[i]

    def compute_cerf_for_session(self, session_id: str) -> str:
        if session_id not in self.pca_vectors:
            X_pca = self._embed([self.features[session_id]])
            self.pca_vectors[session_id] = X_pca[0]
        return self.embedding_model.compute_cerf_hash(self.pca_vectors[session_id])

    def run_pipeline(self) -> pd.DataFrame:
        df = self.load_and_sanitize()
        self.extract_features(df)
        self.train_embedding_model(self.features)
        
        session_cerfs = []
        meta_list = []
        
        for session_id, meta in self.session_meta.items():
            cerf_hash = self.compute_cerf_for_session(session_id)
            meta["cerf"] = cerf_hash
            meta["embedding_norm"] = float(np.linalg.norm(self.pca_vectors[session_id]))
            session_cerfs.append((session_id, cerf_hash))
            meta_list.append(meta)
            
        session_to_ta = self.clusterer.cluster_sessions(session_cerfs, threshold=self.CLUSTER_THRESHOLDS[self.embedding])
        for meta in meta_list:
            meta["threat_actor_id"] = session_to_ta[meta["session_id"]]
            
        sessions_df = pd.DataFrame(meta_list)
        output_sessions_path = os.path.join(self.output_dir, "sessions.csv")
        sessions_df.to_csv(output_sessions_path, index=False)
        
        cerf_clusters = {}
        if not sessions_df.empty:
            for ta_id, group in sessions_df.groupby("threat_actor_id"):
                cerf_clusters[ta_id] = {
                    "cerf": group["cerf"].iloc[0],
                    "sessions": group["session_id"].tolist()
                }
        with open(os.path.join(self.output_dir, "cerf_clusters.json"), "w") as f:
            json.dump(cerf_clusters, f, indent=2)
            
        return sessions_df

if __name__ == "__main__":
    print("[*] Running CERF Engine Analytics...")
    engine = CERFEngine()
    df = engine.run_pipeline()
    print(f"[*] Processed {len(df)} sessions and updated sessions.csv")
