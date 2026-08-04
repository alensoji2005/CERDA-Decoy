"""
Decoy Server Entry Point Wrapper
Points to src.decoy
"""
from src.decoy import DecoyServer, PseudoFilesystem, PerturbationEngine, Regime, TelemetryLogger, TelemetryEvent

if __name__ == "__main__":
    import asyncio
    server = DecoyServer()
    print("Starting CERDA Decoy Server on Ports 2222 (SSH) & 8080 (HTTP)...")
    asyncio.run(server.start())
