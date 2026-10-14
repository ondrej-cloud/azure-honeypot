"""Turn one day of raw Cowrie events into a compact, mergeable daily summary.

The summary is what gets committed to data/daily/. It keeps per-IP counters
(needed for unique-IP counts and geolocation) and capped top lists of the long
tail (passwords, commands, ...), but never the raw event stream.
"""
from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter
from typing import Iterable, Sequence, Union

from .attack import classify

SCHEMA = 1
TOP_N = 500        # per-day cap for long-tail counters
MAX_TEXT = 500     # longest string kept from attacker input


def _text(value: object) -> str:
    if value is None:
        return ""
    return str(value).replace("\x00", "")[:MAX_TEXT]


def _top(counter: Counter, n: int = TOP_N) -> list:
    return [[key, count] for key, count in counter.most_common(n)]


Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


def parse_networks(text: str) -> tuple[Network, ...]:
    """Parse the IGNORE_IPS list: IPs or CIDRs separated by commas or whitespace."""
    networks = []
    for item in re.split(r"[\s,]+", text.strip()):
        if item:
            try:
                networks.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                # Don't echo the entry: it is part of a secret.
                raise ValueError("IGNORE_IPS has an entry that is not an IP address or CIDR") from None
    return tuple(networks)


def summarize(lines: Iterable[str | bytes], day: str, ignore: Sequence[Network] = ()) -> dict:
    """Summarize Cowrie JSON lines (one event per line) for a UTC day.

    Events from `ignore` (the operator's own addresses) are dropped entirely.
    """
    totals: Counter = Counter()
    hourly = [0] * 24
    protocols: Counter = Counter()
    sensors: Counter = Counter()
    ips: dict[str, list[int]] = {}   # ip -> [sessions, login attempts, successful logins, commands]
    usernames: Counter = Counter()
    passwords: Counter = Counter()
    credentials: Counter = Counter()
    commands: Counter = Counter()
    clients: Counter = Counter()
    hassh: Counter = Counter()
    downloads: dict[str, dict] = {}
    sessions: dict[str, dict] = {}   # session id -> {"commands": [...], "logins": n}
    ignored: dict[str, bool] = {}

    for raw in lines:
        try:
            event = json.loads(raw)
        except ValueError:
            totals["malformed_lines"] += 1
            continue
        if not isinstance(event, dict):
            continue
        ip, sid = event.get("src_ip"), event.get("session")
        if not isinstance(ip, str) or not sid:
            continue
        if ignore:
            if ip not in ignored:
                try:
                    ignored[ip] = any(ipaddress.ip_address(ip) in net for net in ignore)
                except ValueError:
                    ignored[ip] = False
            if ignored[ip]:
                continue
        eid = event.get("eventid", "")
        ts = str(event.get("timestamp", ""))
        counters = ips.setdefault(ip, [0, 0, 0, 0])
        session = sessions.setdefault(sid, {"commands": [], "logins": 0})

        if eid == "cowrie.session.connect":
            totals["sessions"] += 1
            counters[0] += 1
            protocols[_text(event.get("protocol")) or "ssh"] += 1
            sensors[_text(event.get("sensor"))] += 1
            if ts[11:13].isdigit():
                hourly[int(ts[11:13]) % 24] += 1
        elif eid in ("cowrie.login.failed", "cowrie.login.success"):
            user, password = _text(event.get("username")), _text(event.get("password"))
            totals["login_attempts"] += 1
            counters[1] += 1
            session["logins"] += 1
            usernames[user] += 1
            passwords[password] += 1
            credentials[(user, password)] += 1
            if eid == "cowrie.login.success":
                totals["login_success"] += 1
                counters[2] += 1
        elif eid == "cowrie.command.input":
            command = _text(event.get("input")).strip()
            totals["commands"] += 1
            counters[3] += 1
            commands[command] += 1
            session["commands"].append(command)
        elif eid == "cowrie.client.version":
            clients[_text(event.get("version"))] += 1
        elif eid == "cowrie.client.kex" and event.get("hassh"):
            hassh[_text(event.get("hassh"))] += 1
        elif eid in ("cowrie.session.file_download", "cowrie.session.file_upload"):
            sha = event.get("shasum")
            if isinstance(sha, str) and sha:
                item = downloads.setdefault(sha, {
                    "sha256": sha,
                    "url": _text(event.get("url") or event.get("filename")),
                    "count": 0, "first": ts, "last": ts,
                })
                item["count"] += 1
                item["first"], item["last"] = min(item["first"], ts), max(item["last"], ts)

    techniques: Counter = Counter()
    for session in sessions.values():
        found = classify(session["commands"])
        if session["logins"]:
            found.add("T1110.001")
        techniques.update(found)
    totals["interactive_sessions"] = sum(1 for s in sessions.values() if s["commands"])
    totals["downloads"] = len(downloads)

    return {
        "schema": SCHEMA,
        "date": day,
        "sensor": sensors.most_common(1)[0][0] if sensors else "",
        "totals": {k: totals[k] for k in (
            "sessions", "login_attempts", "login_success", "commands",
            "interactive_sessions", "downloads", "malformed_lines")},
        "unique_ips": len([ip for ip, c in ips.items() if c[0]]),
        "hourly": hourly,
        "protocols": dict(protocols),
        "ips": {ip: c for ip, c in sorted(ips.items()) if any(c)},
        "usernames": _top(usernames),
        "passwords": _top(passwords),
        "credentials": [[u, p, n] for (u, p), n in credentials.most_common(TOP_N)],
        "commands": _top(commands),
        "clients": _top(clients),
        "hassh": _top(hassh),
        "techniques": dict(techniques.most_common()),
        "downloads": sorted(downloads.values(), key=lambda d: (-d["count"], d["sha256"])),
    }
