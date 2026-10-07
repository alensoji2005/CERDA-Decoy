import asyncio
import time
import uuid
import random
import socket
from dataclasses import dataclass, field
from typing import List, Tuple
from .telemetry import TelemetryEvent, TelemetryLogger, RegimeScheduleEvent, RegimeScheduleLogger
from .pseudo_fs import PseudoFilesystem
from .perturbation import PerturbationEngine, Regime
from src.analytics.cerf_engine import CERFEngine

@dataclass
class DecoyConfig:
    ssh_port: int = 2222
    http_port: int = 8080
    telemetry_path: str = "telemetry.csv"
    regime_schedule_path: str = "regime_schedule.csv"
    use_rl: bool = False
    # TCP tarpit (Patent Claim 6): shrink the kernel receive buffer on the listening
    # sockets so accepted connections advertise a tiny TCP window, throttling the
    # attacker's sends at the network layer. Effect is OS-dependent (strongest on Linux).
    tarpit: bool = False
    tarpit_rcvbuf_bytes: int = 256
    default_schedule: List[Tuple[int, Regime]] = field(default_factory=lambda: [
        (0, Regime.R0_BASELINE),
        (2, Regime.R1_SLOWDOWN),
        (4, Regime.R2_JITTER),
        (6, Regime.R3_FS_LATENCY)
    ])

class DecoyServer:
    def __init__(self, host: str = "0.0.0.0", config: DecoyConfig = None):
        self.host = host
        self.config = config or DecoyConfig()
        self.logger = TelemetryLogger(self.config.telemetry_path)
        self.schedule_logger = RegimeScheduleLogger(self.config.regime_schedule_path)
        
    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, protocol: str):
        session_id = f"session_{uuid.uuid4().hex[:8]}"
        peername = writer.get_extra_info('peername')
        source_ip = peername[0] if peername else "127.0.0.1"
        
        session_seed = random.randint(0, 10000)
        perturbation_engine = PerturbationEngine(
            seed=session_seed, 
            use_rl=self.config.use_rl, 
            default_schedule=self.config.default_schedule
        )
        
        fs = PseudoFilesystem(session_id)
        cmd_index = 0
        last_cmd_time = time.monotonic_ns()
        last_regime = "baseline"
        regime_start_idx = 0
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
                
                regime = perturbation_engine.get_regime_for_command(cmd_index, last_regime, delta_t_ns)
                
                if regime.value != last_regime and cmd_index > 0:
                    self.schedule_logger.log_event(RegimeScheduleEvent(
                        session_id=session_id,
                        seed=session_seed,
                        command_index_start=regime_start_idx,
                        command_index_end=cmd_index - 1,
                        regime=last_regime
                    ))
                    regime_start_idx = cmd_index
                
                if perturbation_engine.use_rl and perturbation_engine.rl_scheduler and cmd_index > 0:
                    reward = perturbation_engine.rl_scheduler.compute_reward(delta_t_ns, regime)
                    perturbation_engine.rl_scheduler.update(
                        cmd_index - 1, last_regime, last_dt, regime, reward, cmd_index, delta_t_ns
                    )
                    
                out, new_path, fs_weight = fs.execute_command(raw_cmd)
                delay_ns = await perturbation_engine.apply_delay(regime, fs_weight)
                
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
                
                # Application-layer byte drip during the R3 regime
                full_output = out + f"$ "
                if regime == Regime.R3_FS_LATENCY:
                    for char in full_output:
                        writer.write(char.encode())
                        await writer.drain()
                        await asyncio.sleep(random.uniform(0.02, 0.08))  # Tarpit: Realistic network lag jitter
                else:
                    writer.write(full_output.encode())
                    await writer.drain()
                
                last_regime = regime.value
                last_dt = delta_t_ns
                cmd_index += 1
                
        except Exception as e:
            pass
        finally:
            self.schedule_logger.log_event(RegimeScheduleEvent(
                session_id=session_id,
                seed=session_seed,
                command_index_start=regime_start_idx,
                command_index_end=cmd_index - 1,
                regime=last_regime
            ))
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass
            
    async def run_analytics_loop(self):
        while True:
            try:
                engine = CERFEngine(telemetry_path=self.config.telemetry_path)
                await asyncio.to_thread(engine.run_pipeline)
            except Exception as e:
                pass
            await asyncio.sleep(3)
            
    def _listening_socket(self, port: int) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if self.config.tarpit:
            # Must be set before listen(): the window scale is negotiated in the SYN/ACK
            # and accepted sockets inherit the buffer size.
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.config.tarpit_rcvbuf_bytes)
        sock.bind((self.host, port))
        sock.listen(100)
        sock.setblocking(False)
        return sock

    async def start_listeners(self) -> Tuple[asyncio.AbstractServer, asyncio.AbstractServer]:
        ssh_server = await asyncio.start_server(
            lambda r, w: self.handle_connection(r, w, "SSH"), sock=self._listening_socket(self.config.ssh_port)
        )
        http_server = await asyncio.start_server(
            lambda r, w: self.handle_connection(r, w, "HTTP"), sock=self._listening_socket(self.config.http_port)
        )
        return ssh_server, http_server

    async def start(self):
        analytics_task = asyncio.create_task(self.run_analytics_loop())
        ssh_server, http_server = await self.start_listeners()
        await asyncio.gather(ssh_server.serve_forever(), http_server.serve_forever(), analytics_task)
