"""
Decoy Server Entry Point Wrapper
Points to src.decoy
"""
from src.decoy import DecoyServer, DecoyConfig, PseudoFilesystem, PerturbationEngine, Regime, TelemetryLogger, TelemetryEvent

if __name__ == "__main__":
    import asyncio
    config = DecoyConfig()
    server = DecoyServer(config=config)
    print("Starting CERDA Decoy Server on Ports 2222 (SSH) & 8080 (HTTP)...")
    asyncio.run(server.start())
