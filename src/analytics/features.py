import numpy as np
import pandas as pd
from typing import Dict, Any

class FeatureExtractor:
    def extract_session_features(self, session_df: pd.DataFrame) -> Dict[str, float]:
        features = {}
        
        # Timing features per regime with log scaling for variance reduction
        for regime in ["baseline", "slowdown", "jitter", "fs_latency"]:
            sub = session_df[session_df["regime"] == regime]["delta_t_ns"]
            if not sub.empty:
                features[f"median_dt_{regime}"] = float(np.log1p(sub.median()))
                features[f"std_dt_{regime}"] = float(np.log1p(sub.std(ddof=0))) if len(sub) > 1 else 0.0
            else:
                features[f"median_dt_{regime}"] = 0.0
                features[f"std_dt_{regime}"] = 0.0
                
        # Ratios (R1/R0, R2/R0, R3/R0)
        med_r0 = max(features["median_dt_baseline"], 1.0)
        features["ratio_r1_r0"] = features["median_dt_slowdown"] / med_r0
        features["ratio_r2_r0"] = features["median_dt_jitter"] / med_r0
        features["ratio_r3_r0"] = features["median_dt_fs_latency"] / med_r0
        
        # Adaptation speed
        dts = session_df["delta_t_ns"].values
        if len(dts) > 1:
            diffs = np.abs(np.diff(dts))
            features["adaptation_speed"] = float(np.log1p(np.mean(diffs)))
            features["overall_std"] = float(np.log1p(np.std(dts)))
        else:
            features["adaptation_speed"] = 0.0
            features["overall_std"] = 0.0
            
        return features
