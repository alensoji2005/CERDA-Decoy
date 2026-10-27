"""Telnet decoy (asyncio): the protocol Mirai-style IoT bots still use.

Same fake Ubuntu host as the SSH decoy: a `login:` / `Password:` exchange (same accept policy as SSH), then the
shell runs through DecoyServer.run_session, so perturbation, pseudo-FS, telemetry, canary alerts, malware capture
and the defence behave exactly as for SSH. Nothing is ever executed on the host.

Signals logged per session: every login attempt in order, and `telnet_opts`, a hash of the option negotiation the
client sent (Telnet's analogue of HASSH: real telnet clients and each bot family negotiate differently).
"""
import asyncio
import hashlib
import socket
import time
import uuid
from typing import Optional

from .pseudo_fs import HOSTNAME
from .ssh_server import accept_login, filesystem_for, shell_prompt
from .telemetry import AuthEvent

IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240
ECHO, SGA = 1, 3
OFFERED = {ECHO, SGA}  # we do the echoing (so passwords are not shown) and suppress go-ahead, like a real telnetd
LOGIN_TRIES = 5
LOGIN_TIMEOUT_S = 60
IDLE_TIMEOUT_S = 300
MAX_LINE = 1024
MAX_SUBNEGOTIATION = 256
BANNER = "Ubuntu 22.04.4 LTS\r\n"


class TelnetConnection:
    """Byte stream with the Telnet command layer stripped, plus line editing."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader, self.writer = reader, writer
        self.options = []  # (command, option) the client sent, in order
        self._buf = b""

    def send_raw(self, data: bytes):
        self.writer.write(data)

    def send_text(self, text: str):
        text = text.replace("\r\n", "\n").replace("\n", "\r\n")
        self.writer.write(text.encode("utf-8", "replace"))  # utf-8 never contains 0xFF, so no IAC doubling

    async def _raw(self) -> Optional[int]:
        if not self._buf:
            self._buf = await self.reader.read(4096)
            if not self._buf:
                return None
        byte, self._buf = self._buf[0], self._buf[1:]
        return byte

    async def _byte(self) -> Optional[int]:
        """Next data byte; negotiation is answered (everything we did not offer is refused) and skipped."""
        while True:
            b = await self._raw()
            if b != IAC:
                return b
            c = await self._raw()
            if c is None or c == IAC:
                return c  # EOF, or an escaped 0xFF data byte
            if c in (DO, DONT, WILL, WONT):
                option = await self._raw()
                if option is None:
                    return None
                self.options.append((c, option))
                if c == DO and option not in OFFERED:
                    self.send_raw(bytes([IAC, WONT, option]))
                elif c == WILL:
                    self.send_raw(bytes([IAC, DONT, option]))
            elif c == SB:  # subnegotiation: skip to IAC SE (bounded, so garbage cannot make us buffer forever)
                previous = None
                for _ in range(MAX_SUBNEGOTIATION):
                    b = await self._raw()
                    if b is None:
                        return None
                    if previous == IAC and b == SE:
                        break
                    previous = b

    async def readline(self, echo: bool) -> Optional[str]:
        """One edited line, or None on EOF / Ctrl-D on an empty line. Backspace edits, Ctrl-C clears."""
        line = bytearray()
        while True:
            b = await self._byte()
            if b is None:
                return None
            if b == 0x0D:  # CR is followed by LF or NUL; a bare LF also ends the line
                if self._buf[:1] in (b"\n", b"\x00"):
                    self._buf = self._buf[1:]
                if echo:
                    self.send_text("\r\n")
                return line.decode("utf-8", "replace")
            if b == 0x0A:
                if echo:
                    self.send_text("\r\n")
                return line.decode("utf-8", "replace")
            if b in (0x7F, 0x08):
                if line:
                    line.pop()
                    if echo:
                        self.send_raw(b"\b \b")
            elif b == 0x03:
                if echo:
                    self.send_text("^C\r\n")
                return ""
            elif b == 0x04 and not line:
                return None
            elif b >= 0x20 and len(line) < MAX_LINE:
                line.append(b)
                if echo:
                    self.send_raw(bytes([b]))

    def opts_fingerprint(self) -> str:
        if not self.options:
            return "none"  # most bots ignore negotiation entirely
        return hashlib.md5(",".join(f"{c}-{o}" for c, o in self.options).encode()).hexdigest()[:16]


class TelnetDecoy:
    def __init__(self, decoy):
        self.decoy = decoy
        self.server = None

    async def start(self, sock: socket.socket):
        self.server = await asyncio.start_server(self.handle, sock=sock)
        self.sockets = [sock]
        return self

    def close(self):
        if self.server:
            self.server.close()

    async def wait_closed(self):
        await self.server.wait_closed()

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        ip = (writer.get_extra_info("peername") or ("0.0.0.0",))[0]
        decoy = self.decoy
        if ip in decoy.defense.banned_ips():  # banned because a blocked actor used this address
            decoy.defense.log_refused(ip, "TELNET")
            writer.transport.abort()
            return
        if not decoy.conn_limiter.acquire(ip):  # too many connections from this IP (or in total): drop silently
            writer.transport.abort()
            return
        try:
            await self._session(TelnetConnection(reader, writer), ip, writer)
        except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError):
            pass  # attacker hung up or went silent
        finally:
            decoy.conn_limiter.release(ip)
            writer.transport.abort()

    async def _session(self, conn: TelnetConnection, ip: str, writer: asyncio.StreamWriter):
        decoy = self.decoy
        session_id = f"session_{uuid.uuid4().hex[:8]}"
        conn.send_raw(bytes([IAC, WILL, ECHO, IAC, WILL, SGA]))
        conn.send_text(BANNER)
        username = await asyncio.wait_for(self._login(conn, ip, session_id), LOGIN_TIMEOUT_S)
        if username is None:
            return
        fs = filesystem_for(ip, username, session_id)

        async def lines():
            while True:
                line = await asyncio.wait_for(conn.readline(echo=True), IDLE_TIMEOUT_S)
                if line is None:
                    return
                yield line

        async def drain():
            await writer.drain()

        await decoy.run_session(lines(), conn.send_text, drain, "TELNET", ip, prompt=shell_prompt(username),
                                session_id=session_id, fs=fs, terminate=writer.transport.abort)

    async def _login(self, conn: TelnetConnection, ip: str, session_id: str) -> Optional[str]:
        decoy = self.decoy
        attempts = 0
        while attempts < LOGIN_TRIES:
            conn.send_text(f"{HOSTNAME} login: ")
            username = await conn.readline(echo=True)
            if username is None:
                return None
            if not username.strip():
                continue  # an empty username is just a prompt again
            conn.send_text("Password: ")
            password = await conn.readline(echo=False)
            if password is None:
                return None
            conn.send_text("\r\n")
            if attempts == 0:
                decoy.signal_logger.log(session_id, ip, "TELNET", "telnet_opts", conn.opts_fingerprint())
            attempts += 1
            decoy.signal_logger.log(session_id, ip, "TELNET", "login_attempt", f"{username}:{password}")
            accepted = accept_login("telnet:" + ip, password)
            decoy.auth_logger.log_event(AuthEvent(
                session_id=session_id, timestamp_ns=time.time_ns(), source_ip=ip, protocol="TELNET",
                username=username[:256], password=password[:256], client_version="", accepted=accepted))
            if accepted:
                conn.send_text("\r\nWelcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-105-generic x86_64)\r\n\r\n")
                return username.strip()
            conn.send_text("Login incorrect\r\n\r\n")
        return None
