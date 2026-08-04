"""
CERDA Module B: CERF Analytics Engine
=====================================
Per technical specification section 3:
- Loads and sanitizes decoy telemetry.
- Extracts timing features (based on R0-R3 perturbations) and AST command features.
- Reduces dimensionality to 32 dims via PCA.
- Computes deterministic 64-bit Locality-Sensitive Hash (CERF) for each session.
- Clusters sessions to attribute Threat Actors based on CERF Hamming distance.
"""

import json
import os
import re
from typing import Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler


class CERFEngine:
    def __init__(self, telemetry_path: str = "telemetry.csv", output_dir: str = "."):
        self.telemetry_path = telemetry_path
        self.output_dir = output_dir
        self.models_dir = os.path.join(output_dir, "models")
        os.makedirs(self.models_dir, exist_ok=True)
        
        self.scaler = None
        self.pca = None
        self.tfidf = TfidfVectorizer(max_features=100, ngram_range=(1, 2))
        
        # State
        self.feature_vectors: Dict[str, np.ndarray] = {}
        self.cerfs: Dict[str, str] = {}
        self.clusters: Dict[str, str] = {}

    def _sanitize_command(self, raw_cmd: str) -> Tuple[str, List[str], Dict[str, int]]:
        """Cleans command and extracts AST features."""
        # Strip ANSI codes (simple regex)
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        clean_cmd = ansi_escape.sub('', raw_cmd).strip()
        
        # Normalize whitespace
        clean_cmd = re.sub(r'\s+', ' ', clean_cmd)
        tokens = clean_cmd.split()
        
        cmd_root = tokens[0].lower() if tokens else ""
        args = tokens[1:]
        
        ast_features = {
            "num_flags": sum(1 for t in args if t.startswith("-")),
            "has_url": 1 if ("http://" in clean_cmd or "https://" in clean_cmd) else 0,
            "has_pipe": 1 if "|" in clean_cmd else 0,
            "has_redirection": 1 if (">" in clean_cmd or ">>" in clean_cmd) else 0,
            "has_subshell": 1 if ("$(" in clean_cmd or "`" in clean_cmd) else 0,
            "num_args": len(args),
        }
        
        return clean_cmd, tokens, ast_features

    def load_telemetry(self) -> pd.DataFrame:
        """Loads and sanitizes telemetry data."""
        df = pd.read_csv(self.telemetry_path)
        
        sanitized_cmds = []
        ast_features_list = []
        
        for raw in df["command_raw"].fillna(""):
            clean, _, ast = self._sanitize_command(str(raw))
            sanitized_cmds.append(clean)
            ast_features_list.append(ast)
            
        df["command_sanitized"] = sanitized_cmds
        ast_df = pd.DataFrame(ast_features_list)
        
        return pd.concat([df, ast_df], axis=1)

    def extract_features(self, telemetry_df: pd.DataFrame) -> Dict[str, np.ndarray]:
        """Computes feature vectors for all sessions."""
        if telemetry_df.empty:
            return {}

        # 1. Fit TF-IDF on all sanitized commands globally (for simplicity in this baseline)
        all_cmds = telemetry_df["command_sanitized"].tolist()
        self.tfidf.fit(all_cmds)
        
        feature_dict = {}
        
        for session_id, group in telemetry_df.groupby("session_id"):
            group = group.sort_values("command_index")
            
            # --- Timing Features ---
            timings_by_regime = {
                "baseline": [], "slowdown": [], "jitter": [], "fs_latency": []
            }
            
            # The first command in a session has delta_t_ns = 0, we can exclude it for pure response timing
            valid_timings = group[group["command_index"] > 0]
            
            for _, row in valid_timings.iterrows():
                r = row["regime"]
                dt_ms = row["delta_t_ns"] / 1e6
                if r in timings_by_regime:
                    timings_by_regime[r].append(dt_ms)
            
            def get_stats(arr):
                return np.median(arr) if arr else 0.0, np.std(arr) if arr else 0.0
                
            med_r0, std_r0 = get_stats(timings_by_regime["baseline"])
            med_r1, std_r1 = get_stats(timings_by_regime["slowdown"])
            med_r2, std_r2 = get_stats(timings_by_regime["jitter"])
            med_r3, std_r3 = get_stats(timings_by_regime["fs_latency"])
            
            # Compute Ratios (avoid division by zero)
            denom = med_r0 if med_r0 > 0 else 1.0
            ratio_r1 = med_r1 / denom
            ratio_r2 = med_r2 / denom
            ratio_r3 = med_r3 / denom
            
            timing_features = [
                med_r0, med_r1, med_r2, med_r3,
                std_r0, std_r1, std_r2, std_r3,
                ratio_r1, ratio_r2, ratio_r3,
                0.0,  # adaptation_speed_R1 placeholder (simplification)
                0.0   # adaptation_speed_R2 placeholder (simplification)
            ]
            
            # --- Command Features ---
            ast_cols = ["num_flags", "has_url", "has_pipe", "has_redirection", "has_subshell", "num_args"]
            ast_means = group[ast_cols].mean().fillna(0.0).values.tolist()
            
            session_cmds = " ".join(group["command_sanitized"].tolist())
            tfidf_vec = self.tfidf.transform([session_cmds]).toarray()[0].tolist()
            
            # Combine
            feat_vec = np.concatenate([timing_features, ast_means, tfidf_vec])
            feature_dict[session_id] = feat_vec
            
        self.feature_vectors = feature_dict
        return feature_dict

    def train_embedding_model(self, feature_vectors: Dict[str, np.ndarray]) -> None:
        """Fits StandardScaler and PCA to map high-dim features to 32 dimensions."""
        if not feature_vectors:
            return
            
        X = np.vstack(list(feature_vectors.values()))
        
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        
        # PCA needs min(n_samples, n_features). If we have very few sessions in test, limit components.
        n_components = min(32, X_scaled.shape[0], X_scaled.shape[1])
        self.pca = PCA(n_components=n_components, random_state=42)
        self.pca.fit(X_scaled)
        
        joblib.dump(self.scaler, os.path.join(self.models_dir, "scaler.joblib"))
        joblib.dump(self.pca, os.path.join(self.models_dir, "pca.joblib"))

    def compute_cerf_for_session(self, session_id: str, num_hashes: int = 64) -> str:
        """
        Computes the Counterfactual Execution-Rhythm Fingerprint (CERF) via LSH.
        Ensures determinism by seeding the projection matrix.
        """
        if session_id not in self.feature_vectors or self.scaler is None or self.pca is None:
            return "0" * (num_hashes // 4)
            
        feat_vec = self.feature_vectors[session_id]
        
        # 1. Inference through trained model
        scaled = self.scaler.transform(feat_vec.reshape(1, -1))
        embedding = self.pca.transform(scaled)[0]
        
        # Pad embedding to 32 dims if PCA generated fewer (due to small dataset)
        padded_embedding = np.zeros(32)
        padded_embedding[:len(embedding)] = embedding
        
        # 2. LSH Projection (Strictly seed=42 for patent determinism)
        projection_matrix = np.random.RandomState(seed=42).randn(32, num_hashes)
        projections = np.dot(padded_embedding, projection_matrix)
        
        # 3. Quantize and convert to hex
        binary_hash = (projections > 0).astype(int)
        
        cerf = "".join([
            format(int("".join(map(str, binary_hash[i:i+4])), 2), 'x')
            for i in range(0, num_hashes, 4)
        ])
        
        self.cerfs[session_id] = cerf
        return cerf

    def cluster_sessions(self, df: pd.DataFrame) -> pd.DataFrame:
        """Groups sessions by identical CERF or Hamming distance <= 2."""
        clusters = {}
        cluster_counter = 1
        
        def hamming_distance(h1: str, h2: str) -> int:
            b1 = bin(int(h1, 16))[2:].zfill(64)
            b2 = bin(int(h2, 16))[2:].zfill(64)
            return sum(c1 != c2 for c1, c2 in zip(b1, b2))
            
        session_cerfs = list(self.cerfs.items())
        
        for session_id, cerf in session_cerfs:
            assigned = False
            for c_id, c_cerf in clusters.items():
                if hamming_distance(cerf, c_cerf) <= 4:
                    self.clusters[session_id] = c_id
                    assigned = True
                    break
            
            if not assigned:
                new_ta_id = f"TA-{cluster_counter:03d}"
                clusters[new_ta_id] = cerf
                self.clusters[session_id] = new_ta_id
                cluster_counter += 1
                
        # Aggregate Output
        results = []
        for session_id, group in df.groupby("session_id"):
            cerf = self.cerfs.get(session_id, "Unknown")
            ta_id = self.clusters.get(session_id, "Unknown")
            source_ip = group["source_ip"].iloc[0] if not group.empty else "Unknown"
            num_commands = len(group)
            dom_regime = group["regime"].mode()[0] if not group.empty else "baseline"
            
            emb_norm = 0.0
            if session_id in self.feature_vectors and self.pca:
                scaled = self.scaler.transform(self.feature_vectors[session_id].reshape(1, -1))
                emb = self.pca.transform(scaled)[0]
                emb_norm = np.linalg.norm(emb)
                
            results.append({
                "session_id": session_id,
                "source_ip": source_ip,
                "cerf": cerf,
                "threat_actor_id": ta_id,
                "embedding_norm": emb_norm,
                "num_commands": num_commands,
                "dominant_regime": dom_regime
            })
            
        sessions_df = pd.DataFrame(results)
        sessions_df.to_csv(os.path.join(self.output_dir, "sessions.csv"), index=False)
        
        with open(os.path.join(self.output_dir, "cerf_clusters.json"), "w") as f:
            json.dump(self.clusters, f, indent=2)
            
        return sessions_df

    def run_pipeline(self) -> pd.DataFrame:
        """Executes full analytics pipeline."""
        df = self.load_telemetry()
        self.extract_features(df)
        self.train_embedding_model(self.feature_vectors)
        
        for session_id in self.feature_vectors.keys():
            self.compute_cerf_for_session(session_id)
            
        return self.cluster_sessions(df)
