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
    parser.add_argument("--fetch-payloads", action="store_true",
                        help="let the decoy download the URLs attackers pass to wget/curl (public addresses only; "
                             "makes the decoy an outbound client, see src/decoy/malware.py)")
    args = parser.parse_args()
    config = DecoyConfig(tarpit=args.tarpit, use_rl=args.rl, fetch_payloads=args.fetch_payloads)
    server = DecoyServer(config=config)
    print(f"Starting CERDA Decoy Server on Ports {config.ssh_port} (SSH), {config.http_port} (HTTP) & "
          f"{config.telnet_port} (Telnet)"
          f"{' with TCP tarpit' if config.tarpit else ''}...")
    asyncio.run(server.start())
