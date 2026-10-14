"""Turn one day of raw Cowrie events into a compact, mergeable daily summary.

The summary is what gets committed to data/daily/. It keeps per-IP counters
(needed for unique-IP counts and geolocation), capped top lists of the long
tail (passwords, commands, ...), per-campaign and per-IP digests and the
day's records, but never the raw event stream.
"""
from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter
from typing import Iterable, Sequence, Union

from . import campaigns as campaign_rules
from .attack import classify

SCHEMA = 2
TOP_N = 500        # per-day cap for long-tail counters
MAX_TEXT = 500     # longest string kept from attacker input
SHORT_TEXT = 300   # strings inside campaign and profile digests
SHA256 = re.compile(r"^[0-9a-f]{64}$")
EMPTY_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

MAX_CAMPAIGNS = 100
MAX_CAMPAIGN_IPS = 200
MAX_SAMPLE_COMMANDS = 25
MAX_REPLAYS = 60
REPLAYS_PER_CAMPAIGN = 2
MAX_PROFILES = 1000
PROFILE_TOP = 10
MAX_PASSWORD_SHOWN = 120


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


def _new_session(ip: str, ts: str) -> dict:
    return {"ip": ip, "protocol": "", "start": ts, "commands": [], "logins": 0,
            "duration_ms": None, "tty": None, "downloads": []}


def _new_profile(ts: str) -> dict:
    return {"first": ts, "last": ts, "protocols": Counter(), "credentials": Counter(),
            "commands": Counter(), "campaigns": Counter(), "downloads": [], "clients": Counter(),
            "replays": []}


def _append_unique(items: list, value: object, cap: int) -> None:
    if value not in items and len(items) < cap:
        items.append(value)


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
    failed: Counter = Counter()
    sessions: dict[str, dict] = {}
    profiles: dict[str, dict] = {}
    longest_password = None
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
        if not isinstance(ip, str) or not sid or not isinstance(sid, str):
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
        ts = _text(event.get("timestamp"))[:40]
        counters = ips.setdefault(ip, [0, 0, 0, 0])
        session = sessions.get(sid)
        if session is None:
            session = sessions[sid] = _new_session(ip, ts)
        profile = profiles.get(ip)
        if profile is None:
            profile = profiles[ip] = _new_profile(ts)
        profile["first"], profile["last"] = min(profile["first"], ts), max(profile["last"], ts)

        if eid == "cowrie.session.connect":
            proto = _text(event.get("protocol"))[:16] or "ssh"
            totals["sessions"] += 1
            counters[0] += 1
            protocols[proto] += 1
            profile["protocols"][proto] += 1
            session["protocol"], session["start"] = proto, ts
            sensors[_text(event.get("sensor"))] += 1
            if ts[11:13].isdigit():
                hourly[int(ts[11:13]) % 24] += 1
        elif eid in ("cowrie.login.failed", "cowrie.login.success"):
            raw_password = "" if event.get("password") is None else str(event.get("password")).replace("\x00", "")
            user, password = _text(event.get("username")), raw_password[:MAX_TEXT]
            totals["login_attempts"] += 1
            counters[1] += 1
            session["logins"] += 1
            usernames[user] += 1
            passwords[password] += 1
            credentials[(user, password)] += 1
            profile["credentials"][(user[:SHORT_TEXT], password[:SHORT_TEXT])] += 1
            if longest_password is None or len(raw_password) > longest_password["length"]:
                longest_password = {"length": len(raw_password), "password": raw_password[:MAX_PASSWORD_SHOWN],
                                    "ip": ip, "ts": ts}
            if eid == "cowrie.login.success":
                totals["login_success"] += 1
                counters[2] += 1
        elif eid == "cowrie.command.input":
            command = _text(event.get("input")).strip()
            totals["commands"] += 1
            counters[3] += 1
            commands[command] += 1
            session["commands"].append(command)
            profile["commands"][command[:SHORT_TEXT]] += 1
        elif eid == "cowrie.client.version":
            version = _text(event.get("version"))
            clients[version] += 1
            profile["clients"][version[:SHORT_TEXT]] += 1
        elif eid == "cowrie.client.kex" and event.get("hassh"):
            hassh[_text(event.get("hassh"))] += 1
        elif eid in ("cowrie.session.file_download", "cowrie.session.file_upload"):
            sha = event.get("shasum")
            if isinstance(sha, str) and sha:
                item = downloads.setdefault(sha, {
                    "sha256": sha,
                    "url": _text(event.get("url") or event.get("filename")),
                    "count": 0, "first": ts, "last": ts, "ips": [], "_sessions": [],
                })
                item["count"] += 1
                item["first"], item["last"] = min(item["first"], ts), max(item["last"], ts)
                _append_unique(item["ips"], ip, 20)
                _append_unique(item["_sessions"], sid, 200)
                _append_unique(session["downloads"], sha, 10)
                _append_unique(profile["downloads"], sha, PROFILE_TOP)
        elif eid == "cowrie.session.file_download.failed":
            url = _text(event.get("url"))[:SHORT_TEXT]
            if url:
                failed[url] += 1
        elif eid == "cowrie.session.closed":
            duration = event.get("duration_ms")
            if isinstance(duration, (int, float)) and duration >= 0:
                session["duration_ms"] = int(duration)
        elif eid == "cowrie.log.closed":
            sha = event.get("shasum")
            size = event.get("size")
            if isinstance(sha, str) and SHA256.match(sha) and sha != EMPTY_SHA:
                session["tty"] = (sha, int(size) if isinstance(size, (int, float)) and size >= 0 else 0)
                if session["duration_ms"] is None and isinstance(event.get("duration_ms"), (int, float)):
                    session["duration_ms"] = int(event["duration_ms"])

    # Per session: ATT&CK techniques and campaign membership.
    techniques: Counter = Counter()
    groups: dict[str, dict] = {}
    session_campaign: dict[str, str] = {}
    for sid, session in sessions.items():
        found = classify(session["commands"])
        if session["logins"]:
            found.add("T1110.001")
        techniques.update(found)
        if not session["commands"]:
            continue
        cid, name, known = campaign_rules.classify(session["commands"])
        session_campaign[sid] = cid
        group = groups.setdefault(cid, {
            "name": name, "known": known, "sessions": 0, "ips": Counter(),
            "first": session["start"], "last": session["start"], "commands": [], "_sample_len": -1,
            "techniques": Counter(), "downloads": [], "protocols": Counter()})
        group["sessions"] += 1
        group["ips"][session["ip"]] += 1
        group["first"], group["last"] = min(group["first"], session["start"]), max(group["last"], session["start"])
        if len(session["commands"]) > group["_sample_len"]:
            group["_sample_len"] = len(session["commands"])
            group["commands"] = [c[:SHORT_TEXT] for c in session["commands"][:MAX_SAMPLE_COMMANDS]]
        group["techniques"].update(found)
        for sha in session["downloads"]:
            _append_unique(group["downloads"], sha, 10)
        group["protocols"][session["protocol"] or "ssh"] += 1
        profiles[session["ip"]]["campaigns"][cid] += 1

    campaigns_out = {}
    for cid, group in sorted(groups.items(), key=lambda kv: (-kv[1]["sessions"], kv[0]))[:MAX_CAMPAIGNS]:
        campaigns_out[cid] = {
            "name": group["name"], "known": group["known"], "sessions": group["sessions"],
            "ips": dict(sorted(group["ips"].items(), key=lambda kv: (-kv[1], kv[0]))[:MAX_CAMPAIGN_IPS]),
            "first": group["first"], "last": group["last"], "commands": group["commands"],
            "techniques": dict(group["techniques"].most_common()), "downloads": group["downloads"],
            "protocols": dict(group["protocols"].most_common()),
        }

    records = _records(sessions, ips, longest_password)
    replays = _replay_candidates(sessions, session_campaign, records)
    for row in replays:
        _append_unique(profiles[row["ip"]]["replays"], row["sha"], 5)

    for item in downloads.values():
        cids: list[str] = []
        for sid in item.pop("_sessions"):
            if sid in session_campaign:
                _append_unique(cids, session_campaign[sid], 5)
        item["campaigns"] = cids
    totals["interactive_sessions"] = sum(1 for s in sessions.values() if s["commands"])
    totals["downloads"] = len(downloads)

    ranked = sorted(profiles, key=lambda ip: (-ips.get(ip, [0])[0], -sum(ips.get(ip, [0])), ip))[:MAX_PROFILES]
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
        "failed_downloads": _top(failed, 50),
        "campaigns": campaigns_out,
        "replays": replays,
        "records": records,
        "profiles": {ip: _profile_out(profiles[ip]) for ip in sorted(ranked)},
    }


def _records(sessions: dict[str, dict], ips: dict[str, list[int]], longest_password) -> dict:
    longest = most = None
    for sid, s in sorted(sessions.items(), key=lambda kv: (kv[1]["start"], kv[0])):
        if s["duration_ms"] is not None and (longest is None or s["duration_ms"] > longest["duration_ms"]):
            longest = {"duration_ms": s["duration_ms"], "session": sid, "ip": s["ip"],
                       "protocol": s["protocol"], "ts": s["start"]}
        if s["commands"] and (most is None or len(s["commands"]) > most["commands"]):
            most = {"commands": len(s["commands"]), "session": sid, "ip": s["ip"], "ts": s["start"]}
    attempts = min(((-c[1], ip) for ip, c in ips.items() if c[1]), default=None)   # most, then lowest IP
    return {
        "longest_session": longest,
        "most_commands": most,
        "longest_password": longest_password if longest_password and longest_password["length"] else None,
        "most_attempts_ip": {"attempts": -attempts[0], "ip": attempts[1]} if attempts else None,
    }


def _replay_candidates(sessions: dict[str, dict], session_campaign: dict[str, str], records: dict) -> list[dict]:
    """Sessions worth turning into replays: the best per campaign and the record holders."""
    def row(sid: str) -> dict:
        s = sessions[sid]
        sha, size = s["tty"]
        return {"sha": sha, "session": sid, "ip": s["ip"], "protocol": s["protocol"], "ts": s["start"],
                "duration_ms": s["duration_ms"] or 0, "size": size, "commands": len(s["commands"]),
                "campaign": session_campaign.get(sid)}

    with_tty = [sid for sid, s in sessions.items() if s["tty"] and (s["tty"][1] > 0 or s["commands"])]
    by_campaign: dict[str, list[str]] = {}
    for sid in with_tty:
        if sid in session_campaign:
            by_campaign.setdefault(session_campaign[sid], []).append(sid)
    chosen: list[str] = []
    for rec in ("longest_session", "most_commands"):
        sid = (records.get(rec) or {}).get("session")
        if sid and sessions.get(sid, {}).get("tty") and sid not in chosen:
            chosen.append(sid)
    picks: list[str] = []
    for sids in by_campaign.values():
        sids.sort(key=lambda sid: (-len(sessions[sid]["commands"]), -sessions[sid]["tty"][1], sessions[sid]["start"], sid))
        seen: set[str] = set()
        for sid in sids:
            if sessions[sid]["tty"][0] not in seen:   # identical recordings share one file
                seen.add(sessions[sid]["tty"][0])
                picks.append(sid)
                if len(seen) == REPLAYS_PER_CAMPAIGN:
                    break
    picks.sort(key=lambda sid: (-len(sessions[sid]["commands"]), -sessions[sid]["tty"][1], sid))
    for sid in picks:
        if sid not in chosen:
            chosen.append(sid)
    return [row(sid) for sid in chosen[:MAX_REPLAYS]]


def _profile_out(p: dict) -> dict:
    return {
        "first": p["first"], "last": p["last"], "protocols": dict(p["protocols"].most_common()),
        "credentials": [[u, pw, n] for (u, pw), n in p["credentials"].most_common(PROFILE_TOP)],
        "commands": _top(p["commands"], PROFILE_TOP),
        "campaigns": dict(p["campaigns"].most_common()),
        "downloads": p["downloads"],
        "clients": _top(p["clients"], 3),
        "replays": p["replays"],
    }
