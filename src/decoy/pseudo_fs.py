import posixpath
import re
from typing import Tuple
from . import system_commands as sysinfo
from .llm_provider import LLMProvider, is_honeytoken

HOSTNAME = "srv-prod-01"
KERNEL_RELEASE = "5.15.0-105-generic"
KERNEL_VERSION = "#115-Ubuntu SMP Mon Apr 15 09:52:04 UTC 2024"

# Standard system files are served verbatim so the decoy matches a stock Ubuntu 22.04 box.
STATIC_FILES = {
    "/etc/hostname": f"{HOSTNAME}\n",
    "/etc/issue": "Ubuntu 22.04.4 LTS \\n \\l\n\n",
    "/etc/os-release": (
        'PRETTY_NAME="Ubuntu 22.04.4 LTS"\nNAME="Ubuntu"\nVERSION_ID="22.04"\n'
        'VERSION="22.04.4 LTS (Jammy Jellyfish)"\nVERSION_CODENAME=jammy\nID=ubuntu\nID_LIKE=debian\n'
        'HOME_URL="https://www.ubuntu.com/"\nSUPPORT_URL="https://help.ubuntu.com/"\n'
        'BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"\nUBUNTU_CODENAME=jammy\n'
    ),
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
        "sync:x:4:65534:sync:/bin:/bin/sync\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
        "systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\n"
        "sshd:x:106:65534::/run/sshd:/usr/sbin/nologin\n"
        "mysql:x:113:118:MySQL Server,,,:/nonexistent:/bin/false\n"
    ),
    "/proc/version": f"Linux version {KERNEL_RELEASE} (buildd@lcy02-amd64-033) "
                     f"(gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) "
                     f"{KERNEL_VERSION}\n",
    "/proc/cpuinfo": "".join(
        f"processor\t: {i}\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 85\n"
        f"model name\t: Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz\ncpu MHz\t\t: 2499.998\n"
        f"cache size\t: 36608 KB\ncpu cores\t: 2\n\n" for i in range(2)
    ),
    "/proc/meminfo": "MemTotal:        4015452 kB\nMemFree:          612340 kB\nMemAvailable:    2871204 kB\n"
                     "Buffers:          104512 kB\nCached:          2010388 kB\nSwapTotal:             0 kB\n"
                     "SwapFree:              0 kB\n",
}

BASE_TREE = {
    "/": ["bin", "boot", "dev", "etc", "home", "lib", "opt", "proc", "root", "run", "sbin", "srv", "tmp", "usr", "var"],
    "/etc": ["apt", "cron.d", "hostname", "hosts", "issue", "mysql", "apache2", "os-release", "passwd", "shadow", "ssh"],
    "/home": [],
    "/proc": ["cpuinfo", "meminfo", "version"],
    "/tmp": [],
    "/var": ["backups", "cache", "lib", "log", "www"],
    "/var/www": ["html"],
    "/var/www/html": ["index.html"],
    "/var/log": ["auth.log", "syslog", "dpkg.log"],
    "/opt": [],
    "/usr": ["bin", "lib", "local", "sbin", "share"],
    "/usr/bin": ["bash", "cat", "curl", "ls", "python3", "wget"],
}
BUILTIN_COMMANDS = {"cd", "pwd", "ls", "cat", "echo", "id", "whoami", "hostname", "uname", "nproc", "free",
                    "history", "which", "sudo", "wget", "curl", "touch", "rm", "chmod", "mkdir", "ps",
                    "ifconfig", "python3", "bash", "sh", "ip", "netstat", "ss", "df", "uptime", "w", "who",
                    "date", "env", "printenv", "crontab", "last", "lsb_release", "grep", "head", "tail", "wc"}


class PseudoFilesystem:
    def __init__(self, session_id: str, username: str = "user"):
        self.session_id = session_id
        self.username = username
        self.home = "/root" if username == "root" else f"/home/{username}"
        self.cwd = self.home
        self.command_history = []
        self.written = {}  # path -> contents written via `>` / `>>` / tee
        self.alert = lambda kind, value: None  # set by the session loop: raises canary alerts
        self.on_write = lambda path, data: None  # set by the session loop: hands written files to the malware store
        self.dirty = set()  # files written since the last flush_writes()
        self.on_download = lambda url: None  # set by the session loop: starts a background payload fetch
        self.llm = LLMProvider(use_mock=True)
        self.virtual_tree = {k: list(v) for k, v in BASE_TREE.items()}
        if username == "root":
            self.virtual_tree[self.home] = [".bashrc", ".profile", ".ssh"]
            self.virtual_tree["/root/.ssh"] = ["authorized_keys"]
        else:
            self.virtual_tree["/home"].append(username)
            self.virtual_tree[self.home] = [".bashrc", ".profile", "notes.txt", "script.sh"]

    # -- path helpers ------------------------------------------------------
    def _resolve(self, target: str) -> str:
        if target == "~" or target.startswith("~/"):
            target = self.home + target[1:]
        return posixpath.normpath(posixpath.join(self.cwd, target))

    def _is_dir(self, path: str) -> bool:
        return path in self.virtual_tree

    def _is_file(self, path: str) -> bool:
        parent, name = posixpath.split(path)
        return name in self.virtual_tree.get(parent, []) and not self._is_dir(path)

    def _add_file(self, path: str):
        parent, name = posixpath.split(path)
        if self._is_dir(parent) and name and name not in self.virtual_tree[parent]:
            self.virtual_tree[parent].append(name)

    # -- execution ---------------------------------------------------------
    def execute_command(self, raw_cmd: str) -> Tuple[str, str, int]:
        """Run a command line (`;` / `&&` chains allowed) against the virtual state only."""
        self.command_history.append(raw_cmd)
        outputs, weight = [], 0
        for part in re.split(r"\s*(?:;|&&)\s*", raw_cmd.strip()):
            if part:
                out, w = self._execute_pipeline(part)
                outputs.append(out)
                weight = max(weight, w)
        # `echo -e '\x7f\x45...'` carries raw bytes as lone surrogates (see _echo); never send those to a terminal.
        text = "".join(outputs).encode("utf-8", "surrogateescape").decode("utf-8", "replace")
        return text, self.cwd, weight

    def _execute_pipeline(self, line: str) -> Tuple[str, int]:
        """`cmd | filter | filter > file`: only the first stage is a real command; later stages
        are text filters over its output. Redirects write into the virtual tree."""
        data, weight = "", 0
        for i, stage in enumerate(line.split("|")):
            cmd, target, append = self._strip_redirects(stage)
            if cmd:
                if i == 0:
                    data, weight = self._execute_one(cmd)
                else:
                    data = self._filter(cmd, data)
            if target:
                self._write(target, data, append)
                data = ""
        return data, weight

    @staticmethod
    def _strip_redirects(stage: str):
        stage = re.sub(r"\s*(?:2>\s*\S+|&>\s*\S+|\d>&\d)", "", stage).strip()
        m = re.search(r"\s*(>>?)\s*(\S+)\s*$", stage)
        if m:
            return stage[:m.start()].strip(), m.group(2), m.group(1) == ">>"
        return stage, None, False

    def _write(self, target: str, text: str, append: bool):
        if target == "/dev/null":
            return
        path = self._resolve(target)
        if self._is_dir(posixpath.dirname(path)) and not self._is_dir(path):
            self._add_file(path)
            self.written[path] = (self.written.get(path, "") if append else "") + text
            self.dirty.add(path)

    def _capture(self, path: str):
        if path in self.dirty and path in self.written:
            self.dirty.discard(path)
            self.on_write(path, self.written[path].encode("utf-8", "surrogateescape"))

    def flush_writes(self):
        """Hand every file written since the last flush to the malware store, in its final form. Droppers build a
        binary with many `echo ... >> file` appends; storing each step would fill the quarantine with fragments."""
        for path in sorted(self.dirty):
            self._capture(path)

    def _filter(self, cmd: str, data: str) -> str:
        parts = cmd.split()
        root, args = parts[0], parts[1:]
        flags = [a for a in args if a.startswith("-") and not a[1:].isdigit()]
        targets = [a for a in args if a not in flags]
        lines = data.splitlines()
        text = lambda rows: "".join(row + "\n" for row in rows)
        if root == "grep" and targets:
            pattern = targets[0].strip("'\"")
            try:
                regex = re.compile(pattern, re.I if "-i" in flags else 0)
            except re.error:
                regex = re.compile(re.escape(pattern))
            hits = [ln for ln in lines if bool(regex.search(ln)) != ("-v" in flags)]
            return f"{len(hits)}\n" if "-c" in flags else text(hits)
        if root in ("head", "tail"):
            n = 10
            for i, a in enumerate(args):
                if a == "-n" and i + 1 < len(args) and args[i + 1].isdigit():
                    n = int(args[i + 1])
                elif a.startswith("-") and a[1:].isdigit():
                    n = int(a[1:])
            return text(lines[:n] if root == "head" else lines[-n:] if n else [])
        if root == "wc":
            if "-l" in flags:
                return f"{len(lines)}\n"
            return f"{len(lines):7d} {len(data.split()):7d} {len(data):7d}\n"
        if root == "sort":
            return text(sorted(lines))
        if root == "uniq":
            return text(ln for i, ln in enumerate(lines) if i == 0 or ln != lines[i - 1])
        if root == "tee":
            for t in targets:
                self._write(t, data, "-a" in flags)
            return data
        if root in ("sh", "bash", "python3", "python", "perl"):
            return ""  # piped script: executed nowhere
        return data  # awk, sed, cut, tr, xargs, ...: pass through unchanged

    def _execute_one(self, cmd: str) -> Tuple[str, int]:
        parts = cmd.split()
        root, args = parts[0], parts[1:]
        flags = [a for a in args if a.startswith("-")]
        targets = [a for a in args if not a.startswith("-")]

        if root == "sudo":
            return self._execute_one(" ".join(args)) if args else ("usage: sudo -h | -K | -k | -V\n", 0)

        if root == "cd":
            path = self._resolve(targets[0]) if targets else self.home
            if self._is_dir(path):
                self.cwd = path
                return "", 0
            if self._is_file(path):
                return f"bash: cd: {targets[0]}: Not a directory\n", 0
            return f"bash: cd: {targets[0]}: No such file or directory\n", 0

        if root == "pwd":
            return self.cwd + "\n", 0

        if root == "ls":
            return self._ls(flags, targets), 1

        if root == "cat":
            if not targets:
                return "cat: missing operand\n", 0
            return "".join(self._cat(t) for t in targets), 1

        if root == "echo":
            return self._echo(args), 0

        if root in ("busybox", "/bin/busybox"):
            # IoT bots probe `/bin/busybox NAME` and expect "NAME: applet not found" for a made-up applet.
            if not args:
                return "BusyBox v1.30.1 (Ubuntu 1:1.30.1-7ubuntu3) multi-call binary.\n", 0
            if args[0] in BUILTIN_COMMANDS:
                return self._execute_one(" ".join(args))
            return f"{args[0]}: applet not found\n", 0

        if root == "whoami":
            return self.username + "\n", 0

        if root == "id":
            if self.username == "root":
                return "uid=0(root) gid=0(root) groups=0(root)\n", 0
            return (f"uid=1000({self.username}) gid=1000({self.username}) "
                    f"groups=1000({self.username}),4(adm),27(sudo)\n"), 0

        if root == "hostname":
            return HOSTNAME + "\n", 0

        if root == "uname":
            return self._uname(flags), 0

        if root == "nproc":
            return "2\n", 0

        if root == "free":
            if "-m" in flags or "-h" in flags:
                return ("               total        used        free      shared  buff/cache   available\n"
                        "Mem:            3921        1023         598           2        2299        2803\n"
                        "Swap:              0           0           0\n"), 0
            return ("               total        used        free      shared  buff/cache   available\n"
                    "Mem:         4015452     1048060      612340        2344     2355052     2871204\n"
                    "Swap:              0           0           0\n"), 0

        if root == "history":
            return "".join(f"{i:5d}  {c}\n" for i, c in enumerate(self.command_history, 1)), 0

        if root == "which":
            return "".join(f"/usr/bin/{t}\n" for t in targets if t in BUILTIN_COMMANDS), 0

        if root in ("wget", "curl"):
            return self._fetch(root, flags, targets), 1

        if root == "touch":
            for t in targets:
                self._add_file(self._resolve(t))
            return "", 1

        if root == "mkdir":
            for t in targets:
                path = self._resolve(t)
                if not self._is_dir(path):
                    self._add_file(path)
                    self.virtual_tree[path] = []
            return "", 1

        if root == "rm":
            for t in targets:
                path = self._resolve(t)
                parent, name = posixpath.split(path)
                if name in self.virtual_tree.get(parent, []) and path not in ("/", self.home):
                    self.virtual_tree[parent].remove(name)
                    self._capture(path)  # droppers delete themselves after running: keep what they were
                    self.written.pop(path, None)
            return "", 1

        if root == "chmod":
            return "", 1

        if root == "ps":
            return sysinfo.ps(self.username, flags + targets), 0
        if root == "ifconfig":
            return sysinfo.IFCONFIG, 0
        if root == "ip" and targets[:1] in (["a"], ["addr"], ["address"]):
            return sysinfo.IP_ADDR, 0
        if root == "netstat":
            return sysinfo.netstat(flags, self.username), 0
        if root == "ss":
            return sysinfo.ss(flags), 0
        if root == "df":
            return (sysinfo.DF_H if any(f in ("-h", "-H") for f in flags) else sysinfo.DF), 0
        if root == "uptime":
            return sysinfo.uptime(), 0
        if root in ("who", "w"):
            return (sysinfo.who if root == "who" else sysinfo.w)(self.username), 0
        if root == "date":
            return sysinfo.date(), 0
        if root in ("env", "printenv"):
            return sysinfo.env(self.username, self.home, self.cwd), 0
        if root == "last":
            return sysinfo.last(self.username), 0
        if root == "lsb_release":
            return sysinfo.lsb_release(), 0
        if root == "crontab":
            return sysinfo.crontab(flags, self.username), 0

        # Remaining commands come from the LLM provider (or its mock).
        return self.llm.generate_command_output(cmd, self.command_history), 0

    @staticmethod
    def _echo(args) -> str:
        r"""echo with -n / -e. The escapes \xHH and \NNN produce raw bytes (the classic Mirai dropper writes its
        binary with `echo -ne "\x7f\x45..." >> file`); they are kept as UTF-8 surrogate escapes so the exact
        bytes reach the malware store."""
        newline, escapes = True, False
        while args and re.fullmatch(r"-[neE]+", args[0]):
            newline = newline and "n" not in args[0]
            escapes = ("e" in args[0]) or (escapes and "E" not in args[0])
            args = args[1:]
        text = " ".join(a.strip("'\"") for a in args)
        if escapes:
            simple = {"n": b"\n", "t": b"\t", "r": b"\r", "a": b"\a", "b": b"\b", "f": b"\f", "v": b"\v",
                      "e": b"\x1b", "\\": b"\\"}

            def expand(m):
                esc = m.group(1)
                if esc[0] == "x":
                    return bytes([int(esc[1:], 16)])
                if esc[0].isdigit():
                    return bytes([int(esc, 8) & 0xFF])
                return simple[esc]
            text = re.sub(r"\\(x[0-9a-fA-F]{1,2}|0?[0-7]{1,3}|[ntrabfve\\])",
                          lambda m: expand(m).decode("utf-8", "surrogateescape"), text)
        return text + ("\n" if newline else "")

    def _ls(self, flags, targets) -> str:
        show_all = any("a" in f for f in flags)
        long = any("l" in f for f in flags)
        out = []
        for target in targets or ["."]:
            path = self._resolve(target)
            if self._is_file(path):
                names = [target]
            elif self._is_dir(path):
                names = sorted(self.virtual_tree[path], key=lambda n: n.lstrip(".").lower())
                if not show_all:
                    names = [n for n in names if not n.startswith(".")]
                elif long:
                    names = [".", ".."] + names
            else:
                out.append(f"ls: cannot access '{target}': No such file or directory\n")
                continue
            if long:
                out.append(f"total {4 * len(names)}\n")
                for n in names:
                    is_dir = n in (".", "..") or self._is_dir(posixpath.join(path, n))
                    mode, size = ("drwxr-xr-x", 4096) if is_dir else ("-rw-r--r--", 220 + 37 * len(n))
                    owner = "root" if self.username == "root" or not path.startswith("/home") else self.username
                    out.append(f"{mode} 1 {owner} {owner} {size:5d} Apr 18 09:12 {n}\n")
            elif names:
                out.append("  ".join(names) + "\n")
        return "".join(out)

    def _cat(self, target: str) -> str:
        path = self._resolve(target)
        if self._is_dir(path):
            return f"cat: {target}: Is a directory\n"
        if path in self.written:
            return self.written[path]
        if path in STATIC_FILES:
            return STATIC_FILES[path]
        if path == "/etc/shadow" and self.username != "root":
            return "cat: /etc/shadow: Permission denied\n"
        # Unknown or sensitive files (credentials, configs) are generated as honeytokens.
        if is_honeytoken(path):
            self.alert("honeytoken_read", path)
        return self.llm.generate_file_content(path, self.command_history)

    def _uname(self, flags) -> str:
        fields = {"s": "Linux", "n": HOSTNAME, "r": KERNEL_RELEASE, "v": KERNEL_VERSION,
                  "m": "x86_64", "p": "x86_64", "i": "x86_64", "o": "GNU/Linux"}
        letters = "".join(f.lstrip("-") for f in flags)
        if not letters:
            return "Linux\n"
        if "a" in letters:
            letters = "snrvmpio"
        return " ".join(fields[c] for c in "snrvmpio" if c in letters) + "\n"

    def _fetch(self, tool: str, flags, targets) -> str:
        urls = [t for t in targets if "://" in t]
        if not urls:
            return f"{tool}: missing URL\n"
        url = urls[0]
        self.alert("download_attempt", url)
        self.on_download(url)  # the reply below never waits for it; the decoy fetches in the background if enabled
        name = posixpath.basename(url.split("?")[0].rstrip("/")) or "index.html"
        # The attacker sees a canned reply and the file only appears in the virtual tree.
        if tool == "curl":
            if "-O" in flags:
                self._add_file(self._resolve(name))
            return ""
        self._add_file(self._resolve(name))
        host = url.split("://", 1)[1].split("/")[0]
        return (f"--2024-04-18 09:14:02--  {url}\nResolving {host}... connected.\n"
                f"HTTP request sent, awaiting response... 200 OK\nLength: 4812 (4.7K) [application/octet-stream]\n"
                f"Saving to: '{name}'\n\n'{name}' saved [4812/4812]\n\n")
