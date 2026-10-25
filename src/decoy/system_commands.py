"""Static, mutually consistent output for status commands (ps, netstat/ss, ifconfig/ip, df, uptime, ...).

All of them describe one imaginary Ubuntu 22.04 web/DB server: sshd :22, apache2 :80,
mysqld :3306 (localhost only), systemd-resolved :53 (localhost only), eth0 = 10.0.0.55.
"""
import time

# (user, pid, %cpu, %mem, vsz, rss, tty, stat, start, time, command)
_PROCESSES = [
    ("root", 1, "0.0", "0.3", 168936, 12568, "?", "Ss", "Apr15", "0:03", "/sbin/init"),
    ("root", 289, "0.0", "0.4", 50680, 16364, "?", "S<s", "Apr15", "0:01", "/lib/systemd/systemd-journald"),
    ("root", 327, "0.0", "0.1", 25504, 6128, "?", "Ss", "Apr15", "0:00", "/lib/systemd/systemd-udevd"),
    ("systemd+", 612, "0.0", "0.2", 14824, 8320, "?", "Ss", "Apr15", "0:00", "/lib/systemd/systemd-resolved"),
    ("root", 701, "0.0", "0.1", 6816, 2988, "?", "Ss", "Apr15", "0:00", "/usr/sbin/cron -f -P"),
    ("root", 742, "0.0", "0.2", 15440, 7820, "?", "Ss", "Apr15", "0:00", "sshd: /usr/sbin/sshd -D [listener]"),
    ("root", 811, "0.0", "0.3", 6176, 4244, "?", "Ss", "Apr15", "0:00", "/usr/sbin/apache2 -k start"),
    ("www-data", 835, "0.0", "0.3", 1998504, 8880, "?", "Sl", "Apr15", "0:02", "/usr/sbin/apache2 -k start"),
    ("mysql", 902, "0.4", "9.1", 1789276, 372840, "?", "Ssl", "Apr15", "41:12", "/usr/sbin/mysqld"),
]

_LISTENERS = [  # proto, local address, port, pid/program
    ("tcp", "127.0.0.53", 53, "612/systemd-resolve"),
    ("tcp", "0.0.0.0", 22, "742/sshd: /usr/sbin"),
    ("tcp", "127.0.0.1", 3306, "902/mysqld"),
    ("tcp6", "::", 22, "742/sshd: /usr/sbin"),
    ("tcp6", ":::", 80, "811/apache2"),
]

IFCONFIG = (
    "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
    "        inet 10.0.0.55  netmask 255.255.255.0  broadcast 10.0.0.255\n"
    "        inet6 fe80::4a3:7bff:fe21:9c10  prefixlen 64  scopeid 0x20<link>\n"
    "        ether 06:a3:7b:21:9c:10  txqueuelen 1000  (Ethernet)\n"
    "        RX packets 4187231  bytes 1961573204 (1.9 GB)\n"
    "        TX packets 2290417  bytes 372195804 (372.1 MB)\n\n"
    "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
    "        inet 127.0.0.1  netmask 255.0.0.0\n"
    "        inet6 ::1  prefixlen 128  scopeid 0x10<host>\n"
    "        loop  txqueuelen 1000  (Local Loopback)\n"
    "        RX packets 18204  bytes 1790213 (1.7 MB)\n"
    "        TX packets 18204  bytes 1790213 (1.7 MB)\n\n"
)
IP_ADDR = (
    "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
    "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
    "    inet 127.0.0.1/8 scope host lo\n       valid_lft forever preferred_lft forever\n"
    "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000\n"
    "    link/ether 06:a3:7b:21:9c:10 brd ff:ff:ff:ff:ff:ff\n"
    "    inet 10.0.0.55/24 metric 100 brd 10.0.0.255 scope global dynamic eth0\n"
    "       valid_lft 2815sec preferred_lft 2815sec\n"
)
DF_H = (
    "Filesystem      Size  Used Avail Use% Mounted on\n"
    "tmpfs           392M  1.1M  391M   1% /run\n"
    "/dev/nvme0n1p1   49G   12G   37G  25% /\n"
    "tmpfs           2.0G     0  2.0G   0% /dev/shm\n"
    "tmpfs           5.0M     0  5.0M   0% /run/lock\n"
    "/dev/nvme0n1p15 105M  6.1M   99M   6% /boot/efi\n"
    "tmpfs           392M  4.0K  392M   1% /run/user/1000\n"
)
DF = (
    "Filesystem     1K-blocks     Used Available Use% Mounted on\n"
    "tmpfs             401548     1112    400436   1% /run\n"
    "/dev/nvme0n1p1  50620264 12251792  38351688  25% /\n"
    "tmpfs            2007724        0   2007724   0% /dev/shm\n"
    "tmpfs               5120        0      5120   0% /run/lock\n"
    "/dev/nvme0n1p15   106832     6186    100646   6% /boot/efi\n"
    "tmpfs             401544        4    401540   1% /run/user/1000\n"
)
UPTIME_LOAD = "load average: 0.08, 0.03, 0.01"


def _ps_row_aux(p, width):
    user, pid, cpu, mem, vsz, rss, tty, stat, start, cpu_time, cmd = p
    return f"{user:<8} {pid:>7} {cpu:>4} {mem:>4} {vsz:>7} {rss:>6} {tty:<8} {stat:<4} {start:<6} {cpu_time:>5} {cmd}\n"


def ps(username: str, flags) -> str:
    letters = "".join(f.lstrip("-") for f in flags)  # BSD style (`ps aux`) arrives without a dash
    me = (username, 1431, "0.0", "0.1", 8272, 5296, "pts/0", "Ss", "09:12", "0:00", "-bash")
    ps_self = (username, 1502, "0.0", "0.0", 10072, 3304, "pts/0", "R+", "09:14", "0:00", "ps " + " ".join(flags)
               if flags else "ps")
    if not letters:
        return "    PID TTY          TIME CMD\n   1431 pts/0    00:00:00 bash\n   1502 pts/0    00:00:00 ps\n"
    session = ("root", 1398, "0.0", "0.3", 17192, 10904, "?", "Ss", "09:12", "0:00", f"sshd: {username}@pts/0")
    rows = _PROCESSES + [session, me, ps_self]
    if "e" in letters and "f" in letters and "a" not in letters:  # ps -ef
        out = "UID          PID    PPID  C STIME TTY          TIME CMD\n"
        for user, pid, _c, _m, _v, _r, tty, _s, start, cpu_time, cmd in rows:
            ppid = 1 if pid not in (1, 835) else (0 if pid == 1 else 811)
            out += f"{user:<8} {pid:>7} {ppid:>7}  0 {start:<5} {tty:<8} 00:{cpu_time.zfill(5)} {cmd}\n"
        return out
    out = "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
    return out + "".join(_ps_row_aux(p, 0) for p in rows)


def netstat(flags, username: str) -> str:
    letters = "".join(f.lstrip("-") for f in flags)
    out = ("Active Internet connections (only servers)\n" if "l" in letters else
           "Active Internet connections (servers and established)\n")
    out += "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n"
    for proto, addr, port, prog in _LISTENERS:
        out += f"{proto:<5}        0      0 {addr + ':' + str(port):<23} {'0.0.0.0:*':<23} LISTEN      {prog}\n"
    if "l" not in letters:
        out += f"{'tcp':<5}        0      0 {'10.0.0.55:22':<23} {'10.0.0.2:51342':<23} ESTABLISHED 1398/sshd: {username}@pts\n"
    return out


def ss(flags) -> str:
    out = "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n"
    for proto, addr, port, prog in _LISTENERS:
        out += f"{proto[:3]:<5} LISTEN 0      128    {addr + ':' + str(port):<19} {'0.0.0.0:*':<17}\n"
    return out


def uptime() -> str:
    return f" {time.strftime('%H:%M:%S', time.gmtime())} up 12 days,  3:41,  1 user,  {UPTIME_LOAD}\n"


def who(username: str) -> str:
    return f"{username}     pts/0        2024-04-18 09:12 (10.0.0.2)\n"


def w(username: str) -> str:
    return (uptime() + "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
            f"{username:<8} pts/0    10.0.0.2         09:12    0.00s  0.02s  0.00s w\n")


def date() -> str:
    return time.strftime("%a %b %e %H:%M:%S UTC %Y\n", time.gmtime())


def env(username: str, home: str, cwd: str) -> str:
    return (f"SHELL=/bin/bash\nPWD={cwd}\nLOGNAME={username}\nHOME={home}\nLANG=en_US.UTF-8\nUSER={username}\n"
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games\n"
            "SSH_TTY=/dev/pts/0\nTERM=xterm\n")


def last(username: str) -> str:
    return (f"{username:<8} pts/0        10.0.0.2         Thu Apr 18 09:12   still logged in\n"
            f"{username:<8} pts/0        10.0.0.2         Wed Apr 17 17:03 - 17:41  (00:37)\n"
            "reboot   system boot  5.15.0-105-gener Mon Apr  6 05:30   still running\n\n"
            "wtmp begins Mon Apr  6 05:30:11 2024\n")


def lsb_release() -> str:
    return ("No LSB modules are available.\nDistributor ID:\tUbuntu\nDescription:\tUbuntu 22.04.4 LTS\n"
            "Release:\t22.04\nCodename:\tjammy\n")


def crontab(flags, username: str) -> str:
    return f"no crontab for {username}\n" if "-l" in flags else "usage: crontab [-u user] file\n"
