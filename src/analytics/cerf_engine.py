import os
import warnings
import json
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple
from sklearn.feature_extraction.text import TfidfVectorizer

from .enrichment import load_ip_database
from .telemetry_io import read_telemetry
from .validation import operator_type
from .sanitization import extract_urls, sanitize_command
from .features import FeatureExtractor
from .embedding import CERFEmbeddingModel
from .transformer_model import TransformerEmbeddingModel
from .clustering import ActorRegistry, CERFClusterer

MIN_LINKABLE_WRITE = 64  # bytes


class CERFEngine:
    # Hamming-distance clustering threshold per backend. Transformer value calibrated on benchmark
    # seed 7 with the live-layout simulator and the retrained weights: max within-actor distance 10,
    # min between-actor distance 11, so 10 is the only separating value (no margin). The PCA value
    # is not calibrated: on seed 7 its within-actor (13) and between-actor (12) distances overlap.
    CLUSTER_THRESHOLDS = {"pca": 6, "transformer": 10}

    def __init__(self, telemetry_path: str = "telemetry.csv", output_dir: str = ".", embedding: str = "transformer",
                 registry_path: str = None, signals_path: str = None, samples_path: str = None,
                 geoip_paths: List[str] = None):
        """embedding: "transformer" (trained Spatio-Temporal Transformer over per-command
        sequences, default) or "pca" (timing + AST + TF-IDF -> PCA). Falls back to PCA
        if the trained Transformer weights are missing (see scripts/train_transformer.py)."""
        """registry_path: SQLite file for persistent actor IDs; None = stateless clustering.
        signals_path: signals.csv from the decoy; its per-session values (HASSH, SSH public keys,
        HTTP header order, user agent) are added to sessions.csv as corroborating columns.
        samples_path: samples.jsonl from the malware store; the SHA-256 of every file a session downloaded
        or uploaded goes into the `payload_hashes` column (the same payload in two sessions links them).
        geoip_paths: iptoasn TSV files (default: see enrichment.default_geoip_paths); adds `country`, `asn`, `as_org`."""
        if embedding not in ("pca", "transformer"):
            raise ValueError(f"Unknown embedding backend: {embedding}")
        self.telemetry_path = telemetry_path
        self.output_dir = output_dir
        models_dir = os.path.join(output_dir, "models")
        if embedding == "transformer":
            self.embedding_model = TransformerEmbeddingModel(models_dir=models_dir)
            if not self.embedding_model.weights_loaded:
                warnings.warn("Transformer weights not found; falling back to PCA embedding. "
                              "Run `python -m scripts.train_transformer` to create them.")
                embedding = "pca"
        if embedding == "pca":
            self.feature_extractor = FeatureExtractor()
            self.embedding_model = CERFEmbeddingModel(models_dir=models_dir)
        self.embedding = embedding
        self.clusterer = CERFClusterer()
        self.registry_path = registry_path
        self.signals_path = signals_path
        self.samples_path = samples_path
        self.geoip_paths = geoip_paths
        self.features = {}
        self.session_meta = {}
        self.pca_vectors = {}
        
    def load_telemetry(self) -> pd.DataFrame:
        return self.load_and_sanitize()

    def load_and_sanitize(self) -> pd.DataFrame:
        if not os.path.exists(self.telemetry_path):
            raise FileNotFoundError(f"Telemetry file not found at {self.telemetry_path}")
        df = read_telemetry(self.telemetry_path)
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
            urls = extract_urls(sdf["command_raw"])
            num_commands = len(sdf)
            
            self.session_meta[session_id] = {
                "session_id": session_id,
                "source_ip": source_ip,
                "num_commands": num_commands,
                "dominant_regime": dominant_regime,
                "download_urls": " ".join(urls),
                "operator": operator_type(sdf)
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

    SIGNAL_COLUMNS = {"hassh": "hassh", "pubkey": "pubkeys", "header_order": "header_order",
                      "user_agent": "user_agent", "arm": "arm", "telnet_opts": "telnet_opts",
                      "port_forward": "forward_targets", "sftp_upload": "sftp_uploads"}

    def _add_signals(self, sessions_df: pd.DataFrame) -> pd.DataFrame:
        """Join signals.csv onto sessions as one column per signal kind (unique values, space-joined)."""
        for col in self.SIGNAL_COLUMNS.values():
            sessions_df[col] = ""
        if not (self.signals_path and os.path.exists(self.signals_path)) or sessions_df.empty:
            return sessions_df
        signals = pd.read_csv(self.signals_path, dtype=str, keep_default_na=False)
        for (session_id, kind), values in signals.groupby(["session_id", "kind"])["value"]:
            if kind in self.SIGNAL_COLUMNS:
                sessions_df.loc[sessions_df["session_id"] == session_id, self.SIGNAL_COLUMNS[kind]] =                     " ".join(dict.fromkeys(values))
        return sessions_df

    def _add_payloads(self, sessions_df: pd.DataFrame) -> pd.DataFrame:
        """Column `payload_hashes`: SHA-256s of files the session downloaded or uploaded, plus files it wrote that are
        big enough to be a payload (a Mirai dropper builds its binary with `echo >>`; `echo hi > x` links nothing)."""
        sessions_df["payload_hashes"] = ""
        if not (self.samples_path and os.path.exists(self.samples_path)) or sessions_df.empty:
            return sessions_df
        found = {}
        for line in open(self.samples_path, encoding="utf-8"):
            try:
                row = json.loads(line)
            except ValueError:
                continue
            linkable = row.get("origin") in ("download", "upload") or (row.get("origin") == "write" and row.get("size", 0) >= MIN_LINKABLE_WRITE)
            if linkable and row.get("sha256"):
                found.setdefault(row["session_id"], {})[row["sha256"]] = None
        sessions_df["payload_hashes"] = sessions_df["session_id"].map(lambda sid: " ".join(found.get(sid, {})))
        return sessions_df

    def _add_geo(self, sessions_df: pd.DataFrame) -> pd.DataFrame:
        """Columns `country`, `asn`, `as_org` from the offline IP database (blank if it is not installed)."""
        db = load_ip_database(self.geoip_paths)
        info = [db.lookup(ip) for ip in sessions_df["source_ip"]]
        for col in ("country", "asn", "as_org"):
            sessions_df[col] = [i[col] for i in info]
        return sessions_df

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
            
        threshold = self.CLUSTER_THRESHOLDS[self.embedding]
        if self.registry_path:
            registry = ActorRegistry(self.registry_path)
            try:
                session_to_ta = registry.assign(
                    [(sid, cerf, self.session_meta[sid]["num_commands"]) for sid, cerf in session_cerfs], threshold)
                new_actors = registry.new_actors
            finally:
                registry.close()
        else:
            session_to_ta = self.clusterer.cluster_sessions(session_cerfs, threshold=threshold)
            new_actors = set()
        for meta in meta_list:
            meta["threat_actor_id"] = session_to_ta[meta["session_id"]]
            meta["new_actor"] = meta["threat_actor_id"] in new_actors  # only meaningful with a registry
            
        sessions_df = self._add_geo(self._add_payloads(self._add_signals(pd.DataFrame(meta_list))))
        output_sessions_path = os.path.join(self.output_dir, "sessions.csv")
        tmp_path = output_sessions_path + ".tmp"  # write then swap, so a reader never sees half a file
        sessions_df.to_csv(tmp_path, index=False)
        os.replace(tmp_path, output_sessions_path)
        
        cerf_clusters = {}
        if not sessions_df.empty:
            for ta_id, group in sessions_df.groupby("threat_actor_id"):
                cerf_clusters[ta_id] = {
                    "cerf": group["cerf"].iloc[0],
                    "sessions": group["session_id"].tolist()
                }
        clusters_path = os.path.join(self.output_dir, "cerf_clusters.json")
        with open(clusters_path + ".tmp", "w") as f:
            json.dump(cerf_clusters, f, indent=2)
        os.replace(clusters_path + ".tmp", clusters_path)
            
        return sessions_df

if __name__ == "__main__":
    print("[*] Running CERF Engine Analytics...")
    engine = CERFEngine()
    df = engine.run_pipeline()
    print(f"[*] Processed {len(df)} sessions and updated sessions.csv")
