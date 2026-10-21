"""Real SSH-2 decoy (asyncssh): password auth, interactive shell and `ssh host cmd` exec.

Every session runs through DecoyServer.run_session, so perturbation, the pseudo-FS
and telemetry are identical to the raw TCP decoy. Nothing is ever executed on the host.
"""
import os
import time
import uuid

import asyncssh

from .pseudo_fs import PseudoFilesystem
from .telemetry import AuthEvent

# Looks like a stock Ubuntu 22.04 server (asyncssh prefixes "SSH-2.0-").
SERVER_VERSION = "OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
HOSTNAME = "srv-prod-01"
# Credentials bots try first; anything else is accepted on the Nth attempt from the
# same source IP (bots often reconnect per attempt) so brute-forcers "succeed" and
# reveal their post-login behaviour.
COMMON_PASSWORDS = {"123456", "password", "admin", "root", "toor", "12345678", "ubuntu", "1234", "qwerty"}
ACCEPT_AFTER_ATTEMPTS = 3
MAX_TRACKED_IPS = 100_000
_attempts_by_ip: dict = {}


def load_or_create_host_key(path: str) -> asyncssh.SSHKey:
    """Persist the host key so the decoy's fingerprint is stable across restarts."""
    if os.path.exists(path):
        return asyncssh.read_private_key(path)
    key = asyncssh.generate_private_key("ssh-ed25519")
    key.write_private_key(path)
    return key


def shell_prompt(username: str):
    def prompt(fs: PseudoFilesystem) -> str:
        home = "/root" if username == "root" else f"/home/{username}"
        cwd = "~" + fs.cwd[len(home):] if fs.cwd.startswith(home) else fs.cwd
        return f"{username}@{HOSTNAME}:{cwd}{'#' if username == 'root' else '$'} "
    return prompt


class _DecoySSHServer(asyncssh.SSHServer):
    """One instance per TCP connection."""

    def __init__(self, decoy):
        self.decoy = decoy
        self.session_id = f"session_{uuid.uuid4().hex[:8]}"
        self.source_ip = "0.0.0.0"
        self.conn = None

    def connection_made(self, conn: asyncssh.SSHServerConnection):
        self.conn = conn
        self.source_ip = conn.get_extra_info("peername")[0]
        conn.set_extra_info(cerda_session_id=self.session_id)

    def begin_auth(self, username: str) -> bool:
        return True  # always require (and log) a password

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
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
    fs = PseudoFilesystem(session_id)
    if username == "root":
        fs.cwd = "/root"
        fs.virtual_tree.setdefault("/root", [".bashrc", ".ssh"])
        fs.virtual_tree["/"] = sorted(set(fs.virtual_tree["/"]) | {"root"})

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
