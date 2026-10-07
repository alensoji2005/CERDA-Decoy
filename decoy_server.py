"""
Decoy Server Entry Point Wrapper
Points to src.decoy
"""
from src.decoy import DecoyServer, DecoyConfig, PseudoFilesystem, PerturbationEngine, Regime, TelemetryLogger, TelemetryEvent

if __name__ == "__main__":
    import argparse
    import asyncio
    parser = argparse.ArgumentParser(description="CERDA decoy server")
    parser.add_argument("--tarpit", action="store_true", help="enable TCP socket tarpit (Patent Claim 6)")
    parser.add_argument("--rl", action="store_true", help="use the RL perturbation scheduler")
    args = parser.parse_args()
    config = DecoyConfig(tarpit=args.tarpit, use_rl=args.rl)
    server = DecoyServer(config=config)
    print(f"Starting CERDA Decoy Server on Ports {config.ssh_port} (SSH) & {config.http_port} (HTTP)"
          f"{' with TCP tarpit' if config.tarpit else ''}...")
    asyncio.run(server.start())
