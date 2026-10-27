"""HTTP decoy (aiohttp): looks like a stock Ubuntu Apache box with a neglected WordPress.

Each source IP is one decoy session (scanners rarely keep cookies); every request is a
"command" that goes through DecoySession, so per-request timing perturbation and
telemetry match the SSH decoy. Login form posts are logged as credentials.
"""
import html
import socket
import time
from typing import Dict, Tuple

from aiohttp import web

from .llm_provider import LLMProvider
from .signals import header_order
from .telemetry import AuthEvent

SERVER_HEADER = "Apache/2.4.52 (Ubuntu)"
SESSION_IDLE_SECONDS = 300
MAX_SESSIONS = 10_000
# Files scanners hunt for; served as honeytokens (fake credentials).
HONEYTOKEN_PATHS = {"/.env", "/.git/config", "/wp-config.php.bak", "/config.php.bak", "/.aws/credentials"}

APACHE_DEFAULT = """<!DOCTYPE html><html><head><title>Apache2 Ubuntu Default Page: It works</title></head>
<body><h1>Apache2 Ubuntu Default Page</h1><p>It works!</p>
<p>This is the default welcome page used to test the correct operation of the Apache2 server
after installation on Ubuntu systems.</p></body></html>
"""
NOT_FOUND = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr><address>Apache/2.4.52 (Ubuntu) Server at {host} Port 80</address></body></html>
"""
FORBIDDEN = NOT_FOUND.replace("404 Not Found", "403 Forbidden").replace("Not Found</h1>", "Forbidden</h1>").replace(
    "The requested URL was not found on this server.", "You don't have permission to access this resource.")
WP_LOGIN = """<!DOCTYPE html><html lang="en-US"><head><title>Log In &lsaquo; Corp Intranet &#8212; WordPress</title></head>
<body class="login"><div id="login">{error}<form name="loginform" id="loginform" action="/wp-login.php" method="post">
<p><label for="user_login">Username or Email Address</label><input type="text" name="log" id="user_login"></p>
<p><label for="user_pass">Password</label><input type="password" name="pwd" id="user_pass"></p>
<p class="submit"><input type="submit" name="wp-submit" value="Log In"></p></form></div></body></html>
"""
PMA_LOGIN = """<!DOCTYPE html><html><head><title>phpMyAdmin</title></head><body>
<h1>Welcome to phpMyAdmin</h1>{error}<form method="post" action="/phpmyadmin/index.php">
<input type="text" name="pma_username"><input type="password" name="pma_password">
<input type="submit" value="Go"></form></body></html>
"""


class HTTPDecoy:
    def __init__(self, decoy):
        self.decoy = decoy
        self.llm = LLMProvider(use_mock=True)
        self.sessions: Dict[str, "DecoySession"] = {}
        self.runner = None

    # -- lifecycle ---------------------------------------------------------
    async def start(self, sock: socket.socket):
        app = web.Application(client_max_size=64 * 1024)
        app.router.add_route("*", "/{tail:.*}", self.handle)
        self.runner = web.AppRunner(app, access_log=None)
        await self.runner.setup()
        await web.SockSite(self.runner, sock).start()
        self.sockets = [sock]
        return self

    async def close(self):
        for session in self.sessions.values():
            session.close()
        self.sessions.clear()
        if self.runner:
            await self.runner.cleanup()

    # -- request handling ----------------------------------------------------
    def _session_for(self, ip: str):
        from .server import DecoySession
        now = time.monotonic()
        for stale_ip in [k for k, s in self.sessions.items() if now - s.last_activity > SESSION_IDLE_SECONDS]:
            self.sessions.pop(stale_ip).close()
        if ip not in self.sessions and len(self.sessions) >= MAX_SESSIONS:
            oldest = min(self.sessions, key=lambda k: self.sessions[k].last_activity)
            self.sessions.pop(oldest).close()
        if ip not in self.sessions:
            self.sessions[ip] = DecoySession(self.decoy, "HTTP", ip)
        return self.sessions[ip]

    async def handle(self, request: web.Request) -> web.StreamResponse:
        ip = request.remote or "0.0.0.0"
        if not self.decoy.http_limiter.allow(ip):
            return web.Response(status=503, text="Service Unavailable", headers={"Server": SERVER_HEADER})
        if ip in self.decoy.defense.banned_ips():  # address banned because a blocked actor used it: drop the connection
            self.decoy.defense.log_refused(ip, "HTTP")
            request.transport.abort()
            return web.Response(status=403)
        session = self._session_for(ip)
        if session.cmd_index == 0:  # first request of the session
            log = self.decoy.signal_logger.log
            log(session.session_id, ip, "HTTP", "header_order", header_order(request.raw_headers))
            log(session.session_id, ip, "HTTP", "user_agent", request.headers.get("User-Agent", ""))
        form = await request.post() if request.method == "POST" else {}
        await self._capture_uploads(request, form, session)
        raw_cmd = f"{request.method} {request.path_qs}"

        result = {}

        def execute(_cmd: str) -> Tuple[str, str, int]:
            status, body, ctype, weight = self.route(request, form, session)
            result.update(status=status, ctype=ctype)
            return body, request.path, weight

        recorder = self.decoy.recorder
        if recorder:
            recorder.start(session.session_id, "HTTP", ip)
            recorder.event(session.session_id, "o", f"$ {raw_cmd}\r\n")
        body, _ = await session.step(raw_cmd, execute)
        if recorder:
            recorder.event(session.session_id, "o", f"HTTP {result['status']} {result['ctype']} ({len(body)} bytes)\r\n")
        response = web.Response(status=result["status"], text=body, content_type=result["ctype"])
        response.headers["Server"] = SERVER_HEADER
        if result["status"] == 302:
            response.headers["Location"] = "/wp-login.php"
        return response

    async def _capture_uploads(self, request: web.Request, form, session):
        """Quarantine what an attacker pushes: a PUT body or a multipart file field (webshell, dropper)."""
        capture = lambda data, source: self.decoy.capture(data, "upload", source, session.session_id,
                                                          session.source_ip, "HTTP")
        if request.method == "PUT":
            capture(await request.read(), request.path)
        for field in form.values():
            if isinstance(field, web.FileField):
                capture(field.file.read(), f"{request.path} {field.filename}")

    def route(self, request: web.Request, form, session) -> Tuple[int, str, str, int]:
        """-> (status, body, content_type, fs_weight)"""
        path = request.path.rstrip("/") or "/"
        host = html.escape(request.host.split(":")[0])
        if path == "/":
            return 200, APACHE_DEFAULT, "text/html", 0
        if path in HONEYTOKEN_PATHS:
            self.decoy.alerts.send(session.session_id, session.source_ip, "HTTP", "honeytoken_read", path)
            return 200, self.llm.generate_file_content(path, []), "text/plain", 1
        if path == "/wp-login.php":
            error = ""
            if request.method == "POST":
                self._log_creds(session, request, form.get("log", ""), form.get("pwd", ""))
                error = (f"<div id='login_error'><strong>Error:</strong> The password you entered for the username "
                         f"<strong>{html.escape(str(form.get('log', '')))}</strong> is incorrect.</div>")
            return 200, WP_LOGIN.format(error=error), "text/html", 0
        if path.startswith("/wp-admin"):
            return 302, "", "text/html", 0
        if path.startswith("/phpmyadmin"):
            error = ""
            if request.method == "POST":
                self._log_creds(session, request, form.get("pma_username", ""), form.get("pma_password", ""))
                error = "<div class='error'>#1045 - Access denied for user</div>"
            return 200, PMA_LOGIN.format(error=error), "text/html", 1
        if path in ("/server-status", "/.htaccess", "/.htpasswd"):
            return 403, FORBIDDEN.format(host=host), "text/html", 0
        return 404, NOT_FOUND.format(host=host), "text/html", 0

    def _log_creds(self, session, request: web.Request, username, password):
        self.decoy.auth_logger.log_event(AuthEvent(
            session_id=session.session_id, timestamp_ns=time.time_ns(), source_ip=session.source_ip,
            protocol="HTTP", username=str(username)[:256], password=str(password)[:256],
            client_version=request.headers.get("User-Agent", "")[:256], accepted=False,
        ))
