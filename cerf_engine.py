"""
CERF Engine Entry Point Wrapper
Points to src.analytics
"""
from src.analytics import CERFEngine, sanitize_command, FeatureExtractor, CERFEmbeddingModel, CERFClusterer

if __name__ == "__main__":
    import sys
    telemetry_file = sys.argv[1] if len(sys.argv) > 1 else "telemetry.csv"
    engine = CERFEngine(telemetry_path=telemetry_file)
    print(f"Running CERF Engine on {telemetry_file}...")
    df = engine.run_pipeline()
    print("CERF Processing Complete. Sessions output:")
    print(df[["session_id", "threat_actor_id", "cerf"]].head())
