"""Generate synthetic telemetry and run the CERF pipeline so the dashboard has data.
Run from the folder the decoy uses: python -m scripts.generate_demo_data

It never overwrites existing data. If telemetry.csv already exists it stops; with --force it first copies the
old file to telemetry.csv.bak-<time> and then writes the synthetic sessions.
"""
import os
import shutil
import sys
import time
import pandas as pd
from src.analytics import CERFEngine
from src.analytics.synthetic import generate_synthetic_data

if os.path.exists("telemetry.csv"):
    if "--force" not in sys.argv:
        sys.exit("telemetry.csv already exists and was left untouched. Use a fresh folder, or add --force to back it up first.")
    backup = f"telemetry.csv.bak-{time.strftime('%Y%m%d-%H%M%S')}"
    shutil.copy2("telemetry.csv", backup)
    print(f"existing telemetry.csv backed up to {backup}")

print("Generating demo telemetry data...")
df_a = generate_synthetic_data(num_sessions=20, script_type="A")
df_b = generate_synthetic_data(num_sessions=15, script_type="B")
df = pd.concat([df_a, df_b]).reset_index(drop=True)
df["timestamp_ns"] += time.time_ns() - 3600 * 10**9   # synthetic clocks start near 0; anchor them to the last hour
df.to_csv("telemetry.csv", index=False)

print("Running CERF Analytics Engine...")
CERFEngine(telemetry_path="telemetry.csv", output_dir=".").run_pipeline()

print("Demo data generated! Check your dashboard.")
