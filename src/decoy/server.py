import asyncio
import time
import uuid
import random
import hashlib
import socket
from dataclasses import dataclass, field
from typing import AsyncIterator, Awaitable, Callable, List, Optional, Tuple
from .telemetry import TelemetryEvent, TelemetryLogger, RegimeScheduleEvent, RegimeScheduleLogger, AuthLogger
from .pseudo_fs import PseudoFilesystem
from .alerts import AlertSink
from .malware import FetchError, MalwareStore
from .recorder import SessionRecorder
from .limits import ConnectionLimiter, RateLimiter
from .signals import SignalLogger
from .defense import DefenseStore
from .perturbation import PerturbationEngine, Regime, DEFAULT_SCHEDULE
from src.analytics.cerf_engine import CERFEngine

R3_DRIP_BUDGET_S = 0.3  # max total time one R3 response may be dripped
R3_DRIP_MIN_GAP_S = 0.02
MAX_FETCHES_PER_SESSION = 5
MAX_CONCURRENT_FETCHES = 4


@dataclass
class DecoyConfig:
    ssh_port: int = 2222
    http_port: int = 8080
    telnet_port: Optional[int] = 2323  # None disables the Telnet decoy
    telemetry_path: str = "telemetry.csv"
    regime_schedule_path: str = "regime_schedule.csv"
    auth_path: str = "auth.csv"
    actor_registry_path: str = "actors.db"
    signals_path: str = "signals.csv"
    # A/B test: this share of sessions (chosen by session-id hash) gets no perturbation at all.
    # Compare CERF accuracy of control vs treatment with analytics.validation.ab_report.
    control_fraction: float = 0.0
    # Resource limits (per source IP unless noted) and operator alerts.
    max_conns_per_ip: int = 20
    max_conns_total: int = 1000
    max_commands_per_session: int = 2000
    http_requests_per_minute_per_ip: int = 300
    alerts_path: str = "alerts.jsonl"
    defense_path: str = "defense.db"  # actor blocks, IP bans and the enforcement log (see defense.py)
    alert_webhook: Optional[str] = None  # default: $CERDA_ALERT_WEBHOOK
    # Malware capture (see malware.py). Files an attacker writes or uploads are always quarantined. Fetching the
    # URLs of wget/curl makes the decoy an outbound client (public addresses only, size and time capped), so it is off.
    quarantine_dir: str = "quarantine"
    samples_path: str = "samples.jsonl"
    fetch_payloads: bool = False
    recordings_dir: str = "recordings"  # one asciinema .cast per session (see recorder.py); "" turns recording off
    max_sample_bytes: int = 5 * 1024 * 1024
    max_quarantine_bytes: int = 500 * 1024 * 1024
    ssh_host_key_path: str = "ssh_host_ed25519_key"
    use_rl: bool = False
    # TCP tarpit (Patent Claim 6): shrink the kernel receive buffer on the listening
    # sockets so accepted connections advertise a tiny TCP window, throttling the
    # attacker's sends at the network layer. Effect is OS-dependent (strongest on Linux).
    tarpit: bool = False
    tarpit_rcvbuf_bytes: int = 256
    default_schedule: List[Tuple[int, Regime]] = field(default_factory=lambda: list(DEFAULT_SCHEDULE))

class DecoyServer:
    def __init__(self, host: str = "0.0.0.0", config: DecoyConfig = None):
        self.host = host
        self.config = config or DecoyConfig()
        self.logger = TelemetryLogger(self.config.telemetry_path)
        self.schedule_logger = RegimeScheduleLogger(self.config.regime_schedule_path)
        self.auth_logger = AuthLogger(self.config.auth_path)
        self.signal_logger = SignalLogger(self.config.signals_path)
        self.alerts = AlertSink(self.config.alerts_path, self.config.alert_webhook)
        self.defense = DefenseStore(self.config.defense_path)
        self.malware = MalwareStore(self.config.quarantine_dir, self.config.samples_path,
                                    self.config.max_sample_bytes, self.config.max_quarantine_bytes)
        self.recorder = SessionRecorder(self.config.recordings_dir) if self.config.recordings_dir else None
        self._fetch_slots = asyncio.Semaphore(MAX_CONCURRENT_FETCHES)
        self._fetch_tasks = set()  # strong references so background fetches are not garbage-collected
        self.active = {}  # session_id -> live DecoySession, for the defence to cut
        self.conn_limiter = ConnectionLimiter(self.config.max_conns_per_ip, self.config.max_conns_total)
        self.http_limiter = RateLimiter(self.config.http_requests_per_minute_per_ip)
        
    async def run_session(self, lines: AsyncIterator[str], write: Callable[[str], None],
                          drain: Callable[[], Awaitable[None]], protocol: str, source_ip: str,
                          prompt: Optional[Callable[[PseudoFilesystem], str]], session_id: Optional[str] = None,
                          fs: Optional[PseudoFilesystem] = None, terminate: Optional[Callable[[], None]] = None):
        """Line-based shell session (SSH, raw TCP) over DecoySession.

        prompt=None runs non-interactively (e.g. `ssh host cmd`): no prompts are written.
        """
        session = DecoySession(self, protocol, source_ip, session_id)
        session.terminate = terminate  # lets the defence drop this connection
        fs = fs or PseudoFilesystem(session.session_id)
        if self.recorder:
            self.recorder.start(session.session_id, protocol, source_ip)
            raw_write = write

            def write(text: str):  # everything the attacker is shown is recorded
                self.recorder.output(session.session_id, text)
                raw_write(text)
        fs.alert = lambda kind, value: self.alerts.send(session.session_id, source_ip, protocol, kind, value)
        fs.on_write = lambda path, data: self.capture(data, "write", path, session.session_id, source_ip, protocol)
        fetches = []
        fs.on_download = lambda url: self.start_fetch(url, fetches, session.session_id, source_ip, protocol)
        if prompt:
            write(prompt(fs))
            await drain()
        try:
            async for line in lines:
                raw_cmd = line.strip()
                if raw_cmd and self.recorder:
                    self.recorder.command(session.session_id, raw_cmd)
                if not raw_cmd:
                    if prompt:
                        write(prompt(fs))
                        await drain()
                    continue
                if raw_cmd in ("exit", "logout") or session.cmd_index >= self.config.max_commands_per_session:
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
        except Exception:
            if not session.cut:  # a session cut by the defence ends with a dropped connection
                raise
        finally:
            fs.flush_writes()
            session.close()

    def capture(self, data: bytes, origin: str, source: str, session_id: str, source_ip: str, protocol: str):
        """Quarantine a file the attacker wrote or uploaded and tell the operator about new samples."""
        record = self.malware.store(data, origin, source, session_id, source_ip, protocol)
        if record and record["new"]:
            self.alerts.send(session_id, source_ip, protocol, "malware_captured",
                             f"{record['sha256'][:16]} {record['type']} {record['size']}B {origin}:{source}")
        return record

    def start_fetch(self, url: str, fetches: list, session_id: str, source_ip: str, protocol: str):
        """Fetch an attacker-named URL in the background (never delays the reply). No-op unless enabled."""
        if not self.config.fetch_payloads or len(fetches) >= MAX_FETCHES_PER_SESSION or not self.malware.should_fetch(url):
            return
        fetches.append(url)
        task = asyncio.get_running_loop().create_task(self._fetch_payload(url, session_id, source_ip, protocol))
        self._fetch_tasks.add(task)
        task.add_done_callback(self._fetch_tasks.discard)

    async def _fetch_payload(self, url: str, session_id: str, source_ip: str, protocol: str):
        async with self._fetch_slots:
            try:
                data = await asyncio.to_thread(self.malware.fetch, url)
            except FetchError as e:
                self.malware.note_failure(url, str(e), session_id, source_ip, protocol)
                return
            except Exception as e:  # a fetch problem must never reach the session
                self.malware.note_failure(url, repr(e), session_id, source_ip, protocol)
                return
        if not self.capture(data, "download", url, session_id, source_ip, protocol):
            self.malware.note_failure(url, "empty or over the storage limit", session_id, source_ip, protocol)

    async def run_analytics_loop(self):
        while True:
            try:
                engine = CERFEngine(telemetry_path=self.config.telemetry_path, registry_path=self.config.actor_registry_path,
                                    signals_path=self.config.signals_path, samples_path=self.config.samples_path)
                sessions = await asyncio.to_thread(engine.run_pipeline)
                self.defense.enforce(sessions, self.active, self.alerts.tripped)
            except Exception as e:
                print(f"analytics loop error: {e!r}")  # keep running; the next pass retries
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
        """ssh_port: SSH-2 decoy. http_port: HTTP decoy. telnet_port: Telnet decoy (None = off).
        Returns (ssh, http, telnet); telnet is None when disabled."""
        from .ssh_server import start_ssh_decoy
        from .http_server import HTTPDecoy
        from .telnet_server import TelnetDecoy
        ssh_server = await start_ssh_decoy(self, self._listening_socket(self.config.ssh_port))
        http_server = await HTTPDecoy(self).start(self._listening_socket(self.config.http_port))
        telnet_server = None
        if self.config.telnet_port is not None:
            telnet_server = await TelnetDecoy(self).start(self._listening_socket(self.config.telnet_port))
        return ssh_server, http_server, telnet_server

    async def start(self):
        analytics_task = asyncio.create_task(self.run_analytics_loop())
        ssh_server, http_server, telnet_server = await self.start_listeners()
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
        bucket = int(hashlib.md5(self.session_id.encode()).hexdigest(), 16) % 1000 / 1000
        self.arm = "control" if bucket < decoy.config.control_fraction else "treatment"
        schedule = [(0, Regime.R0_BASELINE)] if self.arm == "control" else decoy.config.default_schedule
        self.engine = PerturbationEngine(seed=self.seed, use_rl=decoy.config.use_rl and self.arm == "treatment",
                                         default_schedule=schedule)
        if decoy.config.control_fraction > 0:
            decoy.signal_logger.log(self.session_id, source_ip, protocol, "arm", self.arm)
        self.cmd_index = 0
        self.terminate = None  # set by the transport so the defence can drop the connection
        self.cut = False
        decoy.active[self.session_id] = self
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
            timestamp_ns=time.time_ns(),  # wall clock for dates; delta_t uses the monotonic clock
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
        self.decoy.active.pop(self.session_id, None)
        if self.decoy.recorder:
            self.decoy.recorder.close(self.session_id)
        if self.cmd_index > 0:
            self._log_schedule(self.cmd_index - 1)

    def _log_schedule(self, end_idx: int):
        self.decoy.schedule_logger.log_event(RegimeScheduleEvent(
            session_id=self.session_id, seed=self.seed, command_index_start=self.regime_start_idx,
            command_index_end=end_idx, regime=self.last_regime
        ))
