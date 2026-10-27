import numpy as np
import pandas as pd
from typing import Dict, Any

def sorted_with_reaction_regime(session_df: pd.DataFrame) -> pd.DataFrame:
    """Session rows in command order, plus `reaction_regime`: the regime of the response that the
    row's delta_t reacts to. A row's `regime` is the one applied to the response to its own command,
    but its delta_t is the reaction to the previous response (see src/schedule.py), so the pairing
    is the previous row's regime. Command 0 has no preceding response: NaN, and delta_t is ignored."""
    sdf = session_df.sort_values("command_index").copy()
    sdf["reaction_regime"] = sdf["regime"].shift(1)
    return sdf


class FeatureExtractor:
    def extract_session_features(self, session_df: pd.DataFrame) -> Dict[str, float]:
        features = {}
        session_df = sorted_with_reaction_regime(session_df)

        # Timing features per regime with log scaling for variance reduction. Grouped by the regime
        # each delta_t reacts to; command 0 (no preceding response) is left out.
        for regime in ["baseline", "slowdown", "jitter", "fs_latency"]:
            sub = session_df[session_df["reaction_regime"] == regime]["delta_t_ns"]
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
        dts = session_df["delta_t_ns"].values[1:]  # reactions only: command 0 has none
        if len(dts) > 1:
            diffs = np.abs(np.diff(dts))
            features["adaptation_speed"] = float(np.log1p(np.mean(diffs)))
            features["overall_std"] = float(np.log1p(np.std(dts)))
        else:
            features["adaptation_speed"] = 0.0
            features["overall_std"] = 0.0
            
        # Compute AST feature means
        num_flags, has_url, has_pipe, has_redirection, has_subshell, num_args = [], [], [], [], [], []
        for raw_cmd in session_df["command_raw"]:
            tokens = str(raw_cmd).split()
            args = tokens[1:] if len(tokens) > 1 else []
            num_args.append(len(args))
            num_flags.append(sum(1 for a in args if a.startswith("-")))
            has_url.append(1.0 if any("http://" in a or "https://" in a for a in tokens) else 0.0)
            has_pipe.append(1.0 if "|" in str(raw_cmd) else 0.0)
            has_redirection.append(1.0 if ">" in str(raw_cmd) else 0.0)
            has_subshell.append(1.0 if "$(" in str(raw_cmd) or "`" in str(raw_cmd) else 0.0)
            
        features["ast_num_flags"] = float(np.mean(num_flags)) if num_flags else 0.0
        features["ast_has_url"] = float(np.mean(has_url)) if has_url else 0.0
        features["ast_has_pipe"] = float(np.mean(has_pipe)) if has_pipe else 0.0
        features["ast_has_redirection"] = float(np.mean(has_redirection)) if has_redirection else 0.0
        features["ast_has_subshell"] = float(np.mean(has_subshell)) if has_subshell else 0.0
        features["ast_num_args"] = float(np.mean(num_args)) if num_args else 0.0
            
        return features
