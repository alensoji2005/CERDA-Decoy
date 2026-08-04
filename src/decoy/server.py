import asyncio
import time
import uuid
from .telemetry import TelemetryEvent, TelemetryLogger
from .pseudo_fs import PseudoFilesystem
from .perturbation import PerturbationEngine

class DecoyServer:
    def __init__(self, host: str = "0.0.0.0", ssh_port: int = 2222, http_port: int = 8080, telemetry_file: str = "telemetry.csv", use_rl: bool = False):
        self.host = host
        self.ssh_port = ssh_port
        self.http_port = http_port
        self.logger = TelemetryLogger(telemetry_file)
        self.perturbation_engine = PerturbationEngine(use_rl=use_rl)
        
    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, protocol: str):
        session_id = f"session_{uuid.uuid4().hex[:8]}"
        peername = writer.get_extra_info('peername')
        source_ip = peername[0] if peername else "127.0.0.1"
        
        fs = PseudoFilesystem()
        cmd_index = 0
        last_cmd_time = time.monotonic_ns()
        last_regime = "baseline"
        last_dt = 0
        
        writer.write(f"CERDA Decoy Shell ({protocol})\n$ ".encode())
        await writer.drain()
        
        try:
            while True:
                data = await reader.readline()
                if not data:
                    break
                    
                raw_cmd = data.decode(errors='ignore').strip()
                if not raw_cmd:
                    continue
                    
                now_ns = time.monotonic_ns()
                delta_t_ns = now_ns - last_cmd_time
                last_cmd_time = now_ns
                
                regime = self.perturbation_engine.get_regime_for_command(cmd_index, last_regime, delta_t_ns)
                
                if self.perturbation_engine.use_rl and self.perturbation_engine.rl_scheduler and cmd_index > 0:
                    reward = self.perturbation_engine.rl_scheduler.compute_reward(delta_t_ns, regime)
                    self.perturbation_engine.rl_scheduler.update(
                        cmd_index - 1, last_regime, last_dt, regime, reward, cmd_index, delta_t_ns
                    )
                    
                out, new_path, fs_weight = fs.execute_command(raw_cmd)
                delay_ns = await self.perturbation_engine.apply_delay(regime, fs_weight)
                
                cmd_root = raw_cmd.split()[0] if raw_cmd.split() else ""
                
                event = TelemetryEvent(
                    session_id=session_id,
                    timestamp_ns=now_ns,
                    source_ip=source_ip,
                    protocol=protocol,
                    command_index=cmd_index,
                    command_raw=raw_cmd,
                    command_root=cmd_root,
                    current_path=new_path,
                    regime=regime.value,
                    delta_t_ns=delta_t_ns,
                    response_sent=True
                )
                self.logger.log_event(event)
                
                writer.write((out + f"$ ").encode())
                await writer.drain()
                
                last_regime = regime.value
                last_dt = delta_t_ns
                cmd_index += 1
                
        except Exception as e:
            pass
        finally:
            writer.close()
            await writer.wait_closed()
            
    async def start(self):
        ssh_server = await asyncio.start_server(
            lambda r, w: self.handle_connection(r, w, "SSH"), self.host, self.ssh_port
        )
        http_server = await asyncio.start_server(
            lambda r, w: self.handle_connection(r, w, "HTTP"), self.host, self.http_port
        )
        await asyncio.gather(ssh_server.serve_forever(), http_server.serve_forever())
