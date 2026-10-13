"""Heuristic MITRE ATT&CK mapping for what attackers type into the fake shell.

Each command line is split into simple commands (on ; && || | and newlines),
and each simple command is matched by program name and by text patterns.
This is deliberately simple and explainable - it labels what a session tried
to do, it does not prove intent.
"""
from __future__ import annotations

import re
from typing import Iterable

# id -> (name, tactic)
TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1110.001": ("Brute Force: Password Guessing", "Credential Access"),
    "T1082": ("System Information Discovery", "Discovery"),
    "T1033": ("System Owner/User Discovery", "Discovery"),
    "T1087.001": ("Account Discovery: Local Account", "Discovery"),
    "T1057": ("Process Discovery", "Discovery"),
    "T1016": ("System Network Configuration Discovery", "Discovery"),
    "T1083": ("File and Directory Discovery", "Discovery"),
    "T1059.004": ("Command and Scripting Interpreter: Unix Shell", "Execution"),
    "T1098.004": ("Account Manipulation: SSH Authorized Keys", "Persistence"),
    "T1098": ("Account Manipulation", "Persistence"),
    "T1136.001": ("Create Account: Local Account", "Persistence"),
    "T1053.003": ("Scheduled Task/Job: Cron", "Persistence"),
    "T1543.002": ("Create or Modify System Process: Systemd Service", "Persistence"),
    "T1037.004": ("Boot or Logon Initialization Scripts: RC Scripts", "Persistence"),
    "T1070.003": ("Indicator Removal: Clear Command History", "Defense Evasion"),
    "T1070.004": ("Indicator Removal: File Deletion", "Defense Evasion"),
    "T1222.002": ("File and Directory Permissions Modification", "Defense Evasion"),
    "T1562.004": ("Impair Defenses: Disable or Modify System Firewall", "Defense Evasion"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1496": ("Resource Hijacking", "Impact"),
}

TACTIC_ORDER = [
    "Credential Access", "Discovery", "Execution", "Persistence",
    "Defense Evasion", "Command and Control", "Impact",
]

# Programs that identify a technique on their own.
_PROGRAMS = {
    "T1082": "uname lscpu nproc free dmidecode hostnamectl uptime lspci lsb_release",
    "T1033": "whoami id w who last users",
    "T1057": "ps top htop pgrep pidof",
    "T1016": "ifconfig ip netstat ss route arp iwconfig",
    "T1083": "ls find locate tree",
    "T1059.004": "sh bash dash ash zsh",
    "T1098": "chpasswd passwd usermod",
    "T1136.001": "useradd adduser",
    "T1053.003": "crontab",
    "T1070.004": "rm shred unlink",
    "T1222.002": "chmod chattr chown",
    "T1105": "wget curl tftp ftpget scp sftp lwp-download",
}
BY_PROGRAM = {program: tid for tid, names in _PROGRAMS.items() for program in names.split()}

# Text patterns, matched against each simple command.
BY_PATTERN: list[tuple[str, re.Pattern[str]]] = [
    ("T1082", re.compile(r"/proc/(cpuinfo|meminfo|version)|/etc/(os-release|issue|lsb-release)")),
    ("T1087.001", re.compile(r"/etc/(passwd|shadow|group)\b")),
    ("T1098.004", re.compile(r"authorized_keys")),
    ("T1053.003", re.compile(r"/etc/cron|/var/spool/cron")),
    ("T1543.002", re.compile(r"systemctl\s+enable|/etc/systemd/system/|/lib/systemd/system/")),
    ("T1037.004", re.compile(r"/etc/rc\.local|/etc/init\.d/")),
    ("T1070.003", re.compile(r"history\s+-c|HISTFILE|\.bash_history|unset\s+HIST")),
    ("T1562.004", re.compile(r"iptables\s+(-F|--flush)|ufw\s+disable|nft\s+flush|"
                             r"systemctl\s+(stop|disable)\s+(firewalld|ufw|iptables)")),
    ("T1105", re.compile(r"/dev/tcp/")),
    ("T1496", re.compile(r"xmrig|minerd|cpuminer|stratum\+(tcp|ssl)://|nicehash|"
                         r"\bmonero\b|c3pool|supportxmr|moneroocean", re.IGNORECASE)),
]

_SPLIT = re.compile(r"\s*(?:;|&&|\|\||\||\n)\s*")
_WRAPPERS = {"sudo", "busybox", "nohup", "exec", "command", "env", "nice", "timeout"}
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def simple_commands(line: str) -> Iterable[tuple[str, str]]:
    """Yield (program, text) for each simple command in a shell line."""
    for part in _SPLIT.split(line):
        tokens = part.split()
        while tokens and (tokens[0] in _WRAPPERS or _ASSIGNMENT.match(tokens[0])):
            tokens = tokens[1:]
        if tokens:
            yield tokens[0].rsplit("/", 1)[-1], part


def classify(commands: Iterable[str]) -> set[str]:
    """ATT&CK technique ids observed in a session's command lines."""
    found: set[str] = set()
    for line in commands:
        for program, text in simple_commands(line):
            tid = BY_PROGRAM.get(program)
            if tid:
                found.add(tid)
            for tid, pattern in BY_PATTERN:
                if pattern.search(text):
                    found.add(tid)
    return found


def technique_url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"
