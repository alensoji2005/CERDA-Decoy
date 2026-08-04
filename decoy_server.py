"""
CERDA Module A: Active Decoy & Telemetry System
=================================================
Per technical specification section 2:
- Dual TCP listeners: SSH-like (2222) and HTTP-like (8080).
- Stateful pseudo-filesystem handling mock commands with zero host OS execution.
- Deterministic timing perturbation engine (Regimes R0-R3).
- Nanosecond-precision CSV telemetry logging.
"""

import asyncio
import csv
from dataclasses import dataclass, field
from enum import Enum
import os
from pathlib import Path
import random
import time
from typing import Dict, List, Optional, Tuple
import uuid


class Regime(Enum):
    R0_BASELINE = "baseline"        # No artificial delay
    R1_SLOWDOWN = "slowdown"        # +100ms fixed delay before response
    R2_JITTER = "jitter"            # Random delay 50-200ms
    R3_FS_LATENCY = "fs_latency"    # +200ms for filesystem operations only


@dataclass
class DecoyConfig:
    ssh_port: int = 2222
    http_port: int = 8080
    telemetry_path: str = "telemetry.csv"
    regime_schedule_path: str = "regime_schedule.csv"
    default_schedule: List[Tuple[int, Regime]] = field(default_factory=lambda: [
        (0, Regime.R0_BASELINE),
        (5, Regime.R1_SLOWDOWN),
        (10, Regime.R2_JITTER),
        (15, Regime.R3_FS_LATENCY),
    ])


class PseudoFilesystem:
    """
    Stateful memory-only filesystem simulating directory navigation and file actions.
    Guarantees absolute host isolation (zero OS execution / zero subprocess calls).
    """

    def __init__(self) -> None:
        self.current_path: str = "/home/root"
        self.files: Dict[str, Dict[str, Optional[str]]] = {
            "/home/root": {"type": "dir", "content": None},
            "/home/root/readme.txt": {"type": "file", "content": "Welcome to Decoy Node alpha-01\n"},
            "/home/root/config.cfg": {"type": "file", "content": "DB_HOST=127.0.0.1\nDB_PASS=admin123\n"},
            "/etc": {"type": "dir", "content": None},
            "/etc/passwd": {"type": "file", "content": "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:user:/home/user:/bin/bash\n"},
            "/tmp": {"type": "dir", "content": None},
        }

    def execute_command(self, raw_cmd: str) -> Tuple[str, str]:
        """
        Evaluates string commands against the pseudo-filesystem.
        Returns (response_string, operation_type) where operation_type is 'filesystem' or 'general'.
        """
        tokens = raw_cmd.strip().split()
        if not tokens:
            return "", "general"

        cmd_root = tokens[0].lower()
        args = tokens[1:]
        op_type = "general"

        if cmd_root == "cd":
            op_type = "filesystem"
            if not args or args[0] == "~":
                self.current_path = "/home/root"
            else:
                target = args[0]
                if target.startswith("/"):
                    new_path = target
                else:
                    new_path = f"{self.current_path.rstrip('/')}/{target}"
                
                # Normalize path
                parts = []
                for p in new_path.split("/"):
                    if p == ".." and parts:
                        parts.pop()
                    elif p and p != ".":
                        parts.append(p)
                norm_path = "/" + "/".join(parts)
                
                if norm_path in self.files and self.files[norm_path]["type"] == "dir":
                    self.current_path = norm_path
                    return "", op_type
                else:
                    return f"bash: cd: {target}: No such file or directory\n", op_type

        elif cmd_root == "ls":
            op_type = "filesystem"
            contents = []
            prefix = self.current_path.rstrip("/") + "/"
            for path in self.files:
                if path.startswith(prefix) and path != prefix:
                    rel = path[len(prefix):]
                    if "/" not in rel:
                        contents.append(rel)
            if not contents and self.current_path == "/home/root":
                contents = ["readme.txt", "config.cfg"]
            return "  ".join(contents) + ("\n" if contents else ""), op_type

        elif cmd_root == "cat":
            op_type = "filesystem"
            if not args:
                return "", op_type
            filename = args[0]
            path = filename if filename.startswith("/") else f"{self.current_path.rstrip('/')}/{filename}"
            if path in self.files and self.files[path]["type"] == "file":
                return self.files[path]["content"] or "", op_type
            else:
                return f"cat: {filename}: No such file or directory\n", op_type

        elif cmd_root == "wget":
            op_type = "general"
            url = args[0] if args else "http://example.com"
            filename = url.split("/")[-1] or "index.html"
            filepath = f"{self.current_path.rstrip('/')}/{filename}"
            self.files[filepath] = {"type": "file", "content": "# Simulated downloaded payload\n"}
            return f"--2026-08-04 23:00:00--  {url}\nConnecting to {url}... connected.\nHTTP request sent, awaiting response... 200 OK\nSaving to: '{filename}'\n", op_type

        elif cmd_root in ("chmod", "touch", "rm"):
            op_type = "filesystem"
            if args:
                target = args[0]
                filepath = target if target.startswith("/") else f"{self.current_path.rstrip('/')}/{target}"
                if cmd_root == "touch":
                    self.files[filepath] = {"type": "file", "content": ""}
                elif cmd_root == "rm":
                    self.files.pop(filepath, None)
            return "", op_type

        elif cmd_root in ("pwd", "whoami", "id", "uname"):
            if cmd_root == "pwd":
                return f"{self.current_path}\n", "filesystem"
            elif cmd_root == "whoami":
                return "root\n", "general"
            elif cmd_root == "id":
                return "uid=0(root) gid=0(root) groups=0(root)\n", "general"
            elif cmd_root == "uname":
                return "Linux decoy-node 5.15.0-generic x86_64\n", "general"

        # Default fallback shell response
        return f"bash: {cmd_root}: command not found\n", "general"


def get_regime_for_command(command_index: int, schedule: List[Tuple[int, Regime]]) -> Regime:
    """Determines active Regime given a 0-based command index and schedule."""
    current_regime = Regime.R0_BASELINE
    for start_idx, regime in sorted(schedule, key=lambda x: x[0]):
        if command_index >= start_idx:
            current_regime = regime
        else:
            break
    return current_regime


def apply_perturbation(regime: Regime, operation_type: str, rng: Optional[random.Random] = None) -> None:
    """Applies artificial latency perturbation based on active regime."""
    delay_ms = 0.0
    if regime == Regime.R1_SLOWDOWN:
        delay_ms = 100.0
    elif regime == Regime.R2_JITTER:
        if rng:
            delay_ms = rng.uniform(50.0, 200.0)
        else:
            delay_ms = random.uniform(50.0, 200.0)
    elif regime == Regime.R3_FS_LATENCY and operation_type == "filesystem":
        delay_ms = 200.0

    if delay_ms > 0:
        time.sleep(delay_ms / 1000.0)


class DecoyServer:
    """
    Decoy Server managing async listeners for SSH-like (port 2222) and HTTP-like (port 8080) traffic.
    Logs telemetry and regime schedules to CSV files.
    """

    def __init__(self, config: Optional[DecoyConfig] = None) -> None:
        self.config = config or DecoyConfig()
        self.lock = asyncio.Lock()
        self.ssh_server: Optional[asyncio.AbstractServer] = None
        self.http_server: Optional[asyncio.AbstractServer] = None
        self._init_csv_headers()

    def _init_csv_headers(self) -> None:
        """Initializes CSV log files with proper headers if they do not exist."""
        if not os.path.exists(self.config.telemetry_path):
            with open(self.config.telemetry_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "session_id", "timestamp_ns", "source_ip", "protocol",
                    "command_index", "command_raw", "command_root",
                    "current_path", "regime", "delta_t_ns", "response_sent"
                ])

        if not os.path.exists(self.config.regime_schedule_path):
            with open(self.config.regime_schedule_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "session_id", "seed", "command_index_start", "command_index_end", "regime"
                ])

    def log_regime_schedule(self, session_id: str, seed: int) -> None:
        """Logs session regime schedule bounds to CSV."""
        schedule = self.config.default_schedule
        sorted_sched = sorted(schedule, key=lambda x: x[0])
        
        with open(self.config.regime_schedule_path, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            for i, (start_idx, regime) in enumerate(sorted_sched):
                end_idx = sorted_sched[i + 1][0] - 1 if i + 1 < len(sorted_sched) else 999999
                writer.writerow([session_id, seed, start_idx, end_idx, regime.value])

    def log_telemetry(
        self,
        session_id: str,
        timestamp_ns: int,
        source_ip: str,
        protocol: str,
        command_index: int,
        command_raw: str,
        command_root: str,
        current_path: str,
        regime: Regime,
        delta_t_ns: int,
        response_sent: bool,
    ) -> None:
        """Appends telemetry log entry to telemetry.csv."""
        with open(self.config.telemetry_path, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                session_id,
                timestamp_ns,
                source_ip,
                protocol,
                command_index,
                command_raw,
                command_root,
                current_path,
                regime.value,
                delta_t_ns,
                response_sent,
            ])

    async def handle_ssh_session(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        session_id: Optional[str] = None,
        seed: Optional[int] = None,
    ) -> None:
        """Handles an SSH-like interactive TCP session."""
        session_id = session_id or str(uuid.uuid4())
        seed = seed if seed is not None else hash(session_id) % 100000
        rng = random.Random(seed)

        peername = writer.get_extra_info("peername")
        source_ip = peername[0] if peername else "127.0.0.1"

        self.log_regime_schedule(session_id, seed)
        pfs = PseudoFilesystem()

        writer.write(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\n")
        writer.write(b"root@decoy-node:~$ ")
        await writer.drain()

        command_index = 0
        last_timestamp_ns = time.monotonic_ns()

        try:
            while not reader.at_eof():
                line = await reader.readline()
                if not line:
                    break

                raw_cmd = line.decode("utf-8", errors="ignore").strip()
                if not raw_cmd:
                    writer.write(f"root@decoy-node:{pfs.current_path}$ ".encode("utf-8"))
                    await writer.drain()
                    continue

                now_ns = time.monotonic_ns()
                delta_t_ns = now_ns - last_timestamp_ns if command_index > 0 else 0
                last_timestamp_ns = now_ns

                regime = get_regime_for_command(command_index, self.config.default_schedule)
                cmd_root = raw_cmd.split()[0] if raw_cmd.split() else ""

                # Evaluate command against pseudo-filesystem
                response, op_type = pfs.execute_command(raw_cmd)

                # Log to telemetry BEFORE applying perturbation and sending response
                self.log_telemetry(
                    session_id=session_id,
                    timestamp_ns=now_ns,
                    source_ip=source_ip,
                    protocol="SSH",
                    command_index=command_index,
                    command_raw=raw_cmd,
                    command_root=cmd_root,
                    current_path=pfs.current_path,
                    regime=regime,
                    delta_t_ns=delta_t_ns,
                    response_sent=True,
                )

                # Apply active perturbation delay
                apply_perturbation(regime, op_type, rng)

                # Send response back to attacker client
                if response:
                    writer.write(response.encode("utf-8"))
                prompt = f"root@decoy-node:{pfs.current_path}$ "
                writer.write(prompt.encode("utf-8"))
                await writer.drain()

                command_index += 1
                if raw_cmd.lower() in ("exit", "quit"):
                    break

        except (asyncio.CancelledError, ConnectionResetError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    async def handle_http_session(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        session_id: Optional[str] = None,
        seed: Optional[int] = None,
    ) -> None:
        """Handles an HTTP-like TCP session (port 8080)."""
        session_id = session_id or str(uuid.uuid4())
        seed = seed if seed is not None else hash(session_id) % 100000
        rng = random.Random(seed)

        peername = writer.get_extra_info("peername")
        source_ip = peername[0] if peername else "127.0.0.1"

        self.log_regime_schedule(session_id, seed)
        pfs = PseudoFilesystem()

        last_timestamp_ns = time.monotonic_ns()
        command_index = 0

        try:
            line = await reader.readline()
            if line:
                raw_req = line.decode("utf-8", errors="ignore").strip()
                now_ns = time.monotonic_ns()
                delta_t_ns = 0

                regime = get_regime_for_command(command_index, self.config.default_schedule)
                cmd_root = raw_req.split()[0] if raw_req.split() else "GET"

                response_body, op_type = pfs.execute_command(raw_req)

                self.log_telemetry(
                    session_id=session_id,
                    timestamp_ns=now_ns,
                    source_ip=source_ip,
                    protocol="HTTP",
                    command_index=command_index,
                    command_raw=raw_req,
                    command_root=cmd_root,
                    current_path=pfs.current_path,
                    regime=regime,
                    delta_t_ns=delta_t_ns,
                    response_sent=True,
                )

                apply_perturbation(regime, op_type, rng)

                http_response = (
                    "HTTP/1.1 200 OK\r\n"
                    "Server: Apache/2.4.41 (Ubuntu)\r\n"
                    "Content-Type: text/plain\r\n"
                    f"Content-Length: {len(response_body)}\r\n"
                    "Connection: close\r\n\r\n"
                    f"{response_body}"
                )
                writer.write(http_response.encode("utf-8"))
                await writer.drain()

        except (asyncio.CancelledError, ConnectionResetError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    async def start(self) -> None:
        """Starts dual TCP listeners on configured ports."""
        self.ssh_server = await asyncio.start_server(
            self.handle_ssh_session, "0.0.0.0", self.config.ssh_port
        )
        self.http_server = await asyncio.start_server(
            self.handle_http_session, "0.0.0.0", self.config.http_port
        )

    async def stop(self) -> None:
        """Stops decoy server listeners."""
        if self.ssh_server:
            self.ssh_server.close()
            await self.ssh_server.wait_closed()
        if self.http_server:
            self.http_server.close()
            await self.http_server.wait_closed()
