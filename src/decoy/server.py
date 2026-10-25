import asyncio
import time
import uuid
import random
import socket
from dataclasses import dataclass, field
from typing import AsyncIterator, Awaitable, Callable, List, Optional, Tuple
from .telemetry import TelemetryEvent, TelemetryLogger, RegimeScheduleEvent, RegimeScheduleLogger, AuthLogger
from .pseudo_fs import PseudoFilesystem
from .signals import SignalLogger
from .perturbation import PerturbationEngine, Regime
from src.analytics.cerf_engine import CERFEngine

R3_DRIP_BUDGET_S = 0.3  # max total time one R3 response may be dripped
R3_DRIP_MIN_GAP_S = 0.02


@dataclass
class DecoyConfig:
    ssh_port: int = 2222
    http_port: int = 8080
    telemetry_path: str = "telemetry.csv"
    regime_schedule_path: str = "regime_schedule.csv"
    auth_path: str = "auth.csv"
    actor_registry_path: str = "actors.db"
    signals_path: str = "signals.csv"
    ssh_host_key_path: str = "ssh_host_ed25519_key"
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
        self.auth_logger = AuthLogger(self.config.auth_path)
        self.signal_logger = SignalLogger(self.config.signals_path)
        
    async def run_session(self, lines: AsyncIterator[str], write: Callable[[str], None],
                          drain: Callable[[], Awaitable[None]], protocol: str, source_ip: str,
                          prompt: Optional[Callable[[PseudoFilesystem], str]], session_id: Optional[str] = None,
                          fs: Optional[PseudoFilesystem] = None):
        """Line-based shell session (SSH, raw TCP) over DecoySession.

        prompt=None runs non-interactively (e.g. `ssh host cmd`): no prompts are written.
        """
        session = DecoySession(self, protocol, source_ip, session_id)
        fs = fs or PseudoFilesystem(session.session_id)
        if prompt:
            write(prompt(fs))
            await drain()
        try:
            async for line in lines:
                raw_cmd = line.strip()
                if not raw_cmd:
                    if prompt:
                        write(prompt(fs))
                        await drain()
                    continue
                if raw_cmd in ("exit", "logout"):
                    break
                out, regime = await session.step(raw_cmd, fs.execute_command)
                full_output = out + (prompt(fs) if prompt else "")
                if regime == Regime.R3_FS_LATENCY:
                    # Application-layer drip during the R3 regime. Total time is capped so slow bots
                    # don't hit their read timeout, and the number of sleeps is bounded because
                    # OS timers (Windows ~15 ms) can't honour thousands of sub-millisecond sleeps.
                    n_chunks = min(len(full_output), int(R3_DRIP_BUDGET_S / R3_DRIP_MIN_GAP_S)) or 1
                    size = -(-len(full_output) // n_chunks)  # ceil
                    max_gap = R3_DRIP_BUDGET_S / n_chunks
                    for i in range(0, len(full_output), size):
                        write(full_output[i:i + size])
                        await drain()
                        await asyncio.sleep(min(random.uniform(0.02, 0.08), max_gap))
                else:
                    write(full_output)
                    await drain()
                session.mark_response_end()
        except (ConnectionError, asyncio.IncompleteReadError, BrokenPipeError):
            pass  # attacker hung up mid-session
        finally:
            session.close()

    async def run_analytics_loop(self):
        while True:
            try:
                engine = CERFEngine(telemetry_path=self.config.telemetry_path, registry_path=self.config.actor_registry_path,
                                    signals_path=self.config.signals_path)
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

    async def start_listeners(self):
        """ssh_port: SSH-2 decoy. http_port: HTTP decoy."""
        from .ssh_server import start_ssh_decoy
        from .http_server import HTTPDecoy
        ssh_server = await start_ssh_decoy(self, self._listening_socket(self.config.ssh_port))
        http_server = await HTTPDecoy(self).start(self._listening_socket(self.config.http_port))
        return ssh_server, http_server

    async def start(self):
        analytics_task = asyncio.create_task(self.run_analytics_loop())
        ssh_server, http_server = await self.start_listeners()
        await asyncio.gather(ssh_server.wait_closed(), analytics_task)


class DecoySession:
    """Per-attacker perturbation state: picks the regime for each command/request,
    applies the delay and writes telemetry and the regime schedule."""

    def __init__(self, decoy: "DecoyServer", protocol: str, source_ip: str, session_id: Optional[str] = None):
        self.decoy = decoy
        self.protocol = protocol
        self.source_ip = source_ip
        self.session_id = session_id or f"session_{uuid.uuid4().hex[:8]}"
        self.seed = random.randint(0, 10000)
        self.engine = PerturbationEngine(seed=self.seed, use_rl=decoy.config.use_rl,
                                         default_schedule=decoy.config.default_schedule)
        self.cmd_index = 0
        # End of our last response (or session start). delta_t is measured from here to the
        # next command's arrival, so it is the attacker's reaction time and excludes any
        # delay or byte drip we injected ourselves.
        self.last_response_end_ns = time.monotonic_ns()
        self.last_activity = time.monotonic()
        self.last_regime = "baseline"
        self.regime_start_idx = 0
        self.last_dt = 0

    async def step(self, raw_cmd: str, execute: Callable[[str], Tuple[str, str, int]]) -> Tuple[str, Regime]:
        """execute(raw_cmd) -> (output, current_path, fs_weight). Returns (output, regime)."""
        now_ns = time.monotonic_ns()
        self.last_activity = time.monotonic()
        delta_t_ns = now_ns - self.last_response_end_ns

        regime = self.engine.get_regime_for_command(self.cmd_index, self.last_regime, delta_t_ns)
        if regime.value != self.last_regime and self.cmd_index > 0:
            self._log_schedule(self.cmd_index - 1)
            self.regime_start_idx = self.cmd_index

        if self.engine.use_rl and self.engine.rl_scheduler and self.cmd_index > 0:
            reward = self.engine.rl_scheduler.compute_reward(delta_t_ns, regime)
            self.engine.rl_scheduler.update(
                self.cmd_index - 1, self.last_regime, self.last_dt, regime, reward, self.cmd_index, delta_t_ns
            )

        out, path, fs_weight = execute(raw_cmd)
        await self.engine.apply_delay(regime, fs_weight)

        self.decoy.logger.log_event(TelemetryEvent(
            session_id=self.session_id,
            timestamp_ns=now_ns,
            source_ip=self.source_ip,
            protocol=self.protocol,
            command_index=self.cmd_index,
            command_raw=raw_cmd,
            command_root=raw_cmd.split()[0],
            current_path=path,
            regime=regime.value,
            delta_t_ns=delta_t_ns,
            response_sent=True
        ))
        self.last_regime = regime.value
        self.last_dt = delta_t_ns
        self.cmd_index += 1
        self.mark_response_end()  # callers that stream a slower response call this again afterwards
        return out, regime

    def mark_response_end(self):
        self.last_response_end_ns = time.monotonic_ns()

    def close(self):
        if self.cmd_index > 0:
            self._log_schedule(self.cmd_index - 1)

    def _log_schedule(self, end_idx: int):
        self.decoy.schedule_logger.log_event(RegimeScheduleEvent(
            session_id=self.session_id, seed=self.seed, command_index_start=self.regime_start_idx,
            command_index_end=end_idx, regime=self.last_regime
        ))
