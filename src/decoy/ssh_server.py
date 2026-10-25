"""Real SSH-2 decoy (asyncssh): password auth, interactive shell and `ssh host cmd` exec.

Every session runs through DecoyServer.run_session, so perturbation, the pseudo-FS
and telemetry are identical to the raw TCP decoy. Nothing is ever executed on the host.
"""
import os
import time
import uuid
from collections import OrderedDict

import asyncssh
from asyncssh import connection as _asyncssh_connection
from asyncssh.packet import String

from .pseudo_fs import HOSTNAME, PseudoFilesystem
from .signals import hassh
from .telemetry import AuthEvent

# Looks like a stock Ubuntu 22.04 server (asyncssh prefixes "SSH-2.0-").
SERVER_VERSION = "OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
# Credentials bots try first; anything else is accepted on the Nth attempt from the
# same source IP (bots often reconnect per attempt) so brute-forcers "succeed" and
# reveal their post-login behaviour.
COMMON_PASSWORDS = {"123456", "password", "admin", "root", "toor", "12345678", "ubuntu", "1234", "qwerty"}
ACCEPT_AFTER_ATTEMPTS = 3
MAX_TRACKED_IPS = 100_000
_attempts_by_ip: dict = {}
# Attackers who reconnect find their earlier files and history still there, like a real host.
FS_KEEP_SECONDS = 24 * 3600
MAX_TRACKED_FS = 10_000
_fs_by_client: "OrderedDict[tuple, tuple]" = OrderedDict()  # (ip, user) -> (last_seen, PseudoFilesystem)


def filesystem_for(source_ip: str, username: str, session_id: str) -> PseudoFilesystem:
    now = time.monotonic()
    saved = _fs_by_client.pop((source_ip, username), None)
    if saved and now - saved[0] < FS_KEEP_SECONDS:
        fs = saved[1]
        fs.cwd, fs.session_id = fs.home, session_id
    else:
        fs = PseudoFilesystem(session_id, username)
    _fs_by_client[(source_ip, username)] = (now, fs)
    while len(_fs_by_client) > MAX_TRACKED_FS:
        _fs_by_client.popitem(last=False)
    return fs


def _allow_repeated_userauth_request():
    """OpenSSH re-accepts a repeated `ssh-userauth` service request; asyncssh disconnects.
    paramiko-based bots send one per auth method (e.g. a key, then a password), so without
    this they would be dropped mid-login. Patches asyncssh's private packet table."""
    msg = _asyncssh_connection.MSG_SERVICE_REQUEST
    original = _asyncssh_connection.SSHConnection._packet_handlers[msg]

    def handler(self, pkttype, pktid, packet):
        if self._next_service is None and self._auth_in_progress and not self.is_client():
            service = packet.get_string()
            packet.check_end()
            if service == b"ssh-userauth":
                self.send_packet(_asyncssh_connection.MSG_SERVICE_ACCEPT, String(service))
                return
            raise asyncssh.ServiceNotAvailable("Unexpected service in service request")
        return original(self, pkttype, pktid, packet)

    _asyncssh_connection.SSHConnection._packet_handlers[msg] = handler


_allow_repeated_userauth_request()


def load_or_create_host_key(path: str) -> asyncssh.SSHKey:
    """Persist the host key so the decoy's fingerprint is stable across restarts."""
    if os.path.exists(path):
        return asyncssh.read_private_key(path)
    key = asyncssh.generate_private_key("ssh-ed25519")
    key.write_private_key(path)
    return key


def shell_prompt(username: str):
    def prompt(fs: PseudoFilesystem) -> str:
        cwd = "~" + fs.cwd[len(fs.home):] if fs.cwd.startswith(fs.home) else fs.cwd
        return f"{username}@{HOSTNAME}:{cwd}{'#' if username == 'root' else '$'} "
    return prompt


class _DecoySSHServer(asyncssh.SSHServer):
    """One instance per TCP connection."""

    def __init__(self, decoy):
        self.decoy = decoy
        self.session_id = f"session_{uuid.uuid4().hex[:8]}"
        self.source_ip = "0.0.0.0"
        self.conn = None
        self._hassh_logged = False
        self._holds_slot = False

    def connection_made(self, conn: asyncssh.SSHServerConnection):
        self.conn = conn
        self.source_ip = conn.get_extra_info("peername")[0]
        conn.set_extra_info(cerda_session_id=self.session_id)
        self._holds_slot = self.decoy.conn_limiter.acquire(self.source_ip)
        if not self._holds_slot:  # too many connections from this IP (or in total): drop silently
            conn.abort()

    def connection_lost(self, exc):
        if self._holds_slot:
            self._holds_slot = False
            self.decoy.conn_limiter.release(self.source_ip)

    def begin_auth(self, username: str) -> bool:
        return True  # always require (and log) a password

    def password_auth_supported(self) -> bool:
        return True

    def public_key_auth_supported(self) -> bool:
        return True

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        """Log the offered key (reveals the attacker's key reuse across hosts); never accept."""
        self._log_signal("pubkey", f"{username}:{key.get_fingerprint()}")
        return False

    def _log_signal(self, kind: str, value: str):
        if not self._hassh_logged:  # first auth attempt: key exchange is complete
            self._hassh_logged = True
            self.decoy.signal_logger.log(self.session_id, self.source_ip, "SSH", "hassh",
                                         hassh(self.conn._client_kexinit))
        self.decoy.signal_logger.log(self.session_id, self.source_ip, "SSH", kind, value)

    def validate_password(self, username: str, password: str) -> bool:
        self._log_signal("login_attempt", f"{username}:{password}")  # wordlist order within the session
        if len(_attempts_by_ip) >= MAX_TRACKED_IPS:
            _attempts_by_ip.clear()
        attempts = _attempts_by_ip[self.source_ip] = _attempts_by_ip.get(self.source_ip, 0) + 1
        accepted = password in COMMON_PASSWORDS or attempts >= ACCEPT_AFTER_ATTEMPTS
        if accepted:
            _attempts_by_ip.pop(self.source_ip, None)
        self.decoy.auth_logger.log_event(AuthEvent(
            session_id=self.session_id, timestamp_ns=time.time_ns(), source_ip=self.source_ip,
            protocol="SSH", username=username, password=password,
            client_version=self.conn.get_extra_info("client_version") or "", accepted=accepted,
        ))
        return accepted


async def _handle_process(decoy, process: asyncssh.SSHServerProcess):
    conn = process.channel.get_connection()
    session_id = conn.get_extra_info("cerda_session_id")
    username = process.get_extra_info("username") or "root"
    source_ip = conn.get_extra_info("peername")[0]
    fs = filesystem_for(source_ip, username, session_id)

    try:
        if process.command:  # `ssh host "cmd; cmd"` -- common for bots
            async def lines():
                for cmd in process.command.split(";"):
                    yield cmd
            await decoy.run_session(lines(), process.stdout.write, process.stdout.drain, "SSH",
                                    source_ip, prompt=None, session_id=session_id, fs=fs)
        else:
            process.stdout.write("Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-105-generic x86_64)\r\n\r\n")

            async def lines():
                while True:
                    try:
                        line = await process.stdin.readline()
                    except (asyncssh.BreakReceived, asyncssh.TerminalSizeChanged):
                        continue
                    if not line:
                        return
                    yield line
            await decoy.run_session(lines(), process.stdout.write, process.stdout.drain, "SSH",
                                    source_ip, prompt=shell_prompt(username), session_id=session_id, fs=fs)
    finally:
        process.exit(0)


async def start_ssh_decoy(decoy, sock) -> asyncssh.SSHAcceptor:
    """Serve the SSH decoy on an already-bound listening socket."""
    return await asyncssh.listen(
        sock=sock,
        server_factory=lambda: _DecoySSHServer(decoy),
        server_host_keys=[load_or_create_host_key(decoy.config.ssh_host_key_path)],
        server_version=SERVER_VERSION,
        process_factory=lambda process: _handle_process(decoy, process),
        encoding="utf-8",
        login_timeout=60,
        keepalive_interval=30,
    )
