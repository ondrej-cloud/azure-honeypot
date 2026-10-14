"""Merge daily summaries into the dashboard's stats.json and profiles.json.

The dashboard offers three time windows (last 7 days, last 30 days, all time);
each is precomputed here so every chart on the page can be re-scoped instantly.
Per-IP profiles are big and only needed when someone opens one, so they go to
a separate file the page loads lazily.
"""
from __future__ import annotations

import datetime as dt
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlsplit

from .attack import TACTIC_ORDER, TECHNIQUES
from .geo import GeoDB

SCHEMA = 2
TOP = 15
WINDOWS = [("7d", "Last 7 days", 7), ("30d", "Last 30 days", 30), ("all", "All time", None)]
TOTAL_KEYS = ("sessions", "unique_ips", "login_attempts", "login_success",
              "commands", "interactive_sessions", "downloads", "countries")
MAX_CAMPAIGNS = 30
MAX_CAMPAIGN_COMMANDS = 15
MAX_TEXT = 300
MAX_WINDOW_REPLAYS = 30
MAX_DOWNLOADS = 50
MAX_FAILED = 15
PROFILE_DAYS = 30
MAX_PROFILES = 1500
SHA256 = re.compile(r"^[0-9a-f]{64}$")
REPLAY_ID = re.compile(r"^[0-9a-f]{16}$")
MALWARE_KINDS = {"elf", "script", "archive", "html", "text", "data", "empty"}
_TOKEN = re.compile(r"^[a-z0-9_]{1,16}$")
_TAG = re.compile(r"^[a-z0-9_-]{1,24}$")


def load_days(daily_dir: Path) -> list[dict]:
    days = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(daily_dir.glob("*.json"))]
    return sorted(days, key=lambda d: d["date"])


def load_malware(malware_dir: Path) -> dict[str, dict]:
    """sha256 -> analyzer metadata (data/malware/<sha256>.json); unreadable files are skipped."""
    out: dict[str, dict] = {}
    for path in sorted(malware_dir.glob("*.json")) if malware_dir.is_dir() else []:
        try:
            meta = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            continue
        if isinstance(meta, dict) and SHA256.match(path.stem):
            out[path.stem] = meta
    return out


def defang(url: str) -> str:
    """Make a captured malware URL unclickable: hxxp://203.0.113[.]5/x.sh"""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url.replace(".", "[.]")
    if not parts.scheme or not parts.netloc:
        return url.replace(".", "[.]")
    scheme = parts.scheme.replace("t", "x")  # http -> hxxp, ftp -> fxp
    rest = url[len(parts.scheme) + 3 + len(parts.netloc):]
    return f"{scheme}://{parts.netloc.replace('.', '[.]')}{rest}"


URL_IN_TEXT = re.compile(r"(?i)\b(?:https?|ftps?|tftp)://[^\s'\"<>;|&()`]+")


def defang_text(text: str) -> str:
    """Defang every URL inside free text such as a command line or a campaign name."""
    return URL_IN_TEXT.sub(lambda m: defang(m.group(0)), text)


def _clean(value: object, limit: int = MAX_TEXT) -> str | None:
    """Printable, bounded text from third-party metadata, or None."""
    if not isinstance(value, str) or not value:
        return None
    text = "".join(ch if ch.isprintable() else "?" for ch in value)
    return text[:limit]


def _merge_top(days: list[dict], key: str, n: int = TOP) -> list:
    counter: Counter = Counter()
    for day in days:
        for item in day.get(key, []):
            *k, count = item
            counter[tuple(k) if len(k) > 1 else k[0]] += count
    out = []
    for k, count in counter.most_common(n):
        out.append([*k, count] if isinstance(k, tuple) else [k, count])
    return out


def _date_range(start: dt.date, end: dt.date) -> list[str]:
    return [(start + dt.timedelta(days=i)).isoformat() for i in range((end - start).days + 1)]


def window_ranges(all_days: list[dict]) -> list[tuple[str, str, dt.date, dt.date]]:
    """(key, label, start, end) of each dashboard window, anchored on the latest day."""
    if not all_days:
        return []
    first = dt.date.fromisoformat(all_days[0]["date"])
    end = dt.date.fromisoformat(all_days[-1]["date"])
    out = []
    for key, label, length in WINDOWS:
        start = first if length is None else max(first, end - dt.timedelta(days=length - 1))
        out.append((key, label, start, end))
    return out


def _totals(days: list[dict], geo: GeoDB) -> dict:
    out: Counter = Counter()
    ips: set[str] = set()
    shas: set[str] = set()
    for day in days:
        for key in ("sessions", "login_attempts", "login_success", "commands", "interactive_sessions"):
            out[key] += day["totals"].get(key, 0)
        ips.update(ip for ip, c in day["ips"].items() if c[0])
        shas.update(d["sha256"] for d in day.get("downloads", []))
    out["unique_ips"] = len(ips)
    out["downloads"] = len(shas)
    out["countries"] = len({geo.lookup(ip)[0] for ip in ips} - {"??"})
    return {k: out[k] for k in TOTAL_KEYS}


def _merge_ips(days: list[dict]) -> dict[str, list[int]]:
    ips: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0, 0])
    for day in days:
        for ip, counters in day["ips"].items():
            merged = ips[ip]
            for i, value in enumerate(counters):
                merged[i] += value
    return ips


def merge_records(days: list[dict], ips: dict[str, list[int]] | None = None) -> dict:
    """Records over several days. Session-based records keep their session id."""
    ips = _merge_ips(days) if ips is None else ips
    longest = most = password = None
    for day in days:
        records = day.get("records") or {}
        r = records.get("longest_session")
        if r and (longest is None or r["duration_ms"] > longest["duration_ms"]):
            longest = r
        r = records.get("most_commands")
        if r and (most is None or r["commands"] > most["commands"]):
            most = r
        r = records.get("longest_password")
        if r and (password is None or r["length"] > password["length"]):
            password = r
    attempts = min(((-c[1], ip) for ip, c in ips.items() if c[1]), default=None)
    active: Counter = Counter()
    for day in days:
        active.update(ip for ip, c in day["ips"].items() if c[0])
    persistent = min(((-n, -ips[ip][0], ip) for ip, n in active.items()), default=None)
    return {
        "longest_session": dict(longest) if longest else None,
        "most_commands": dict(most) if most else None,
        "longest_password": ({"length": password["length"], "password": password["password"], "ip": password["ip"]}
                             if password else None),
        "most_attempts_ip": {"attempts": -attempts[0], "ip": attempts[1]} if attempts else None,
        "most_persistent_ip": {"days": -persistent[0], "ip": persistent[2]} if persistent else None,
    }


def _replay_id(candidate: dict, replay_ids: frozenset) -> str | None:
    rid = str(candidate.get("sha", ""))[:16]
    return rid if rid in replay_ids else None


def _best_replay(candidates: list[dict], replay_ids: frozenset) -> str | None:
    """Most commands, then latest."""
    best = None
    for c in candidates:
        rid = _replay_id(c, replay_ids)
        if rid and (best is None or (c["commands"], c["ts"]) > (best[0]["commands"], best[0]["ts"])):
            best = (c, rid)
    return best[1] if best else None


# ------------------------------------------------------------------ malware

def _elf_arch(meta: dict) -> str | None:
    elf = meta.get("elf")
    if meta.get("kind") != "elf" or not isinstance(elf, dict):
        return None
    # A truncated ELF can come with bits/endian but no machine.
    machine = _clean(elf.get("machine"), 40)
    bits = elf.get("bits") if elf.get("bits") in (32, 64) else None
    endian = {"little": "LE", "big": "BE"}.get(elf.get("endian"))
    if not (machine or bits or endian):
        return "ELF (truncated)"
    return " ".join(part for part in (machine or "ELF", f"{bits}-bit" if bits else None, endian) if part)


def type_label(meta: dict | None) -> str:
    """Bucket for the "malware by file type" chart."""
    if not meta:
        return "Not analyzed"
    kind = meta.get("kind")
    if kind == "elf":
        return _elf_arch(meta) or "ELF"
    return {"script": "Shell script", "empty": "Empty file"}.get(kind, "Other")


def malware_view(meta: dict | None) -> dict | None:
    """The published subset of analyzer metadata, with every field re-validated."""
    if not isinstance(meta, dict):
        return None
    kind = meta.get("kind") if meta.get("kind") in MALWARE_KINDS else "data"
    elf = meta.get("elf") if isinstance(meta.get("elf"), dict) else {}
    script = meta.get("script") if isinstance(meta.get("script"), dict) else {}
    size = meta.get("size")
    flag = lambda v: v if isinstance(v, bool) else None   # noqa: E731
    return {
        "kind": kind,
        "size": size if isinstance(size, int) and size >= 0 else None,
        "arch": _elf_arch(meta),
        "static": flag(elf.get("static")),
        "stripped": flag(elf.get("stripped")),
        "packer": _clean(meta.get("packer"), 20),
        "script_urls": [defang(u[:MAX_TEXT]) for u in script.get("urls", []) if isinstance(u, str) and u][:20],
        "script_archs": [a for a in script.get("archs", []) if isinstance(a, str) and _TOKEN.match(a)][:20],
        "hints": [h for h in meta.get("hints", []) if isinstance(h, str) and _TAG.match(h)][:10],
    }


def intel_view(meta: dict | None) -> dict | None:
    intel = meta.get("intel") if isinstance(meta, dict) else None
    if not isinstance(intel, dict):
        return None
    vt, mb = intel.get("vt"), intel.get("mb")
    vt_out = mb_out = None
    if isinstance(vt, dict) and isinstance(vt.get("malicious"), int) and isinstance(vt.get("total"), int):
        vt_out = {"malicious": vt["malicious"], "total": vt["total"], "label": _clean(vt.get("label"), 80)}
    if isinstance(mb, dict):
        tags = [t[:40] for t in mb.get("tags", []) if isinstance(t, str) and t.isprintable() and t][:10]
        mb_out = {"signature": _clean(mb.get("signature"), 80), "tags": tags}
    return {"vt": vt_out, "mb": mb_out} if vt_out or mb_out else None


# ------------------------------------------------------------------ windows

def build_window(all_days: list[dict], start: dt.date, end: dt.date, geo: GeoDB, *,
                 malware: dict[str, dict] | None = None, replay_ids: frozenset = frozenset(),
                 first_seen: dict[str, str] | None = None, campaign_names: dict[str, str] | None = None,
                 is_all: bool = False) -> dict:
    malware = malware or {}
    first_seen = first_seen or {}
    campaign_names = campaign_names or {}
    by_date = {d["date"]: d for d in all_days}
    dates = _date_range(start, end)
    days = [by_date[d] for d in dates if d in by_date]

    ips = _merge_ips(days)
    heatmap = [[0] * 24 for _ in range(7)]
    protocols: Counter = Counter()
    techniques: Counter = Counter()
    downloads: dict[str, dict] = {}
    failed: Counter = Counter()
    candidates: list[dict] = []
    for day in days:
        weekday = dt.date.fromisoformat(day["date"]).weekday()
        for hour, value in enumerate(day["hourly"]):
            heatmap[weekday][hour] += value
        protocols.update(day.get("protocols", {}))
        techniques.update(day.get("techniques", {}))
        for d in day.get("downloads", []):
            item = downloads.setdefault(d["sha256"], {"sha256": d["sha256"], "url": d.get("url", ""), "count": 0,
                                                      "first": d["first"], "last": d["last"], "ips": Counter(),
                                                      "campaigns": []})
            item["count"] += d["count"]
            item["first"], item["last"] = min(item["first"], d["first"]), max(item["last"], d["last"])
            item["ips"].update(d.get("ips", []))
            for cid in d.get("campaigns", []):
                if cid not in item["campaigns"]:
                    item["campaigns"].append(cid)
        for url, n in day.get("failed_downloads", []):
            failed[url] += n
        candidates.extend(day.get("replays", []))

    countries: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    country_ips: dict[str, list[tuple[int, str]]] = defaultdict(list)
    country_asns: dict[str, Counter] = defaultdict(Counter)
    asns: dict[int, dict] = {}
    for ip, (sessions, *_rest) in ips.items():
        cc, asn, name = geo.lookup(ip)
        if sessions:
            countries[cc][0] += sessions
            countries[cc][1] += 1
            country_ips[cc].append((sessions, ip))
            if asn:
                country_asns[cc][(asn, name)] += sessions
        if asn:
            a = asns.setdefault(asn, {"asn": asn, "name": name, "cc": cc, "sessions": 0, "ips": 0})
            a["sessions"] += sessions
            a["ips"] += 1 if sessions else 0

    campaigns = _window_campaigns(days, geo, candidates, replay_ids, first_seen, start, is_all)
    country_campaigns: dict[str, Counter] = defaultdict(Counter)
    for camp in campaigns.values():
        for ip, n in camp["_ips"].items():
            country_campaigns[geo.lookup(ip)[0]][camp["id"]] += n

    top_ips = sorted(ips.items(), key=lambda kv: (-kv[1][0], -kv[1][1], kv[0]))[:TOP]
    daily = []
    for date in dates:
        day = by_date.get(date)
        t = day["totals"] if day else {}
        daily.append({
            "date": date,
            "sessions": t.get("sessions", 0),
            "unique_ips": day["unique_ips"] if day else 0,
            "login_attempts": t.get("login_attempts", 0),
            "login_success": t.get("login_success", 0),
            "commands": t.get("commands", 0),
        })

    technique_rows = [
        {"id": tid, "name": TECHNIQUES[tid][0], "tactic": TECHNIQUES[tid][1], "sessions": n}
        for tid, n in techniques.items() if tid in TECHNIQUES
    ]
    technique_rows.sort(key=lambda r: (TACTIC_ORDER.index(r["tactic"]), -r["sessions"]))

    records = merge_records(days, ips)
    by_session = {c["session"]: c for c in candidates}
    for key in ("longest_session", "most_commands"):
        if records[key]:
            c = by_session.get(records[key]["session"])
            records[key]["replay"] = _replay_id(c, replay_ids) if c else None

    replays: dict[str, dict] = {}
    for c in candidates:
        rid = _replay_id(c, replay_ids)
        if rid and (rid not in replays or (c["commands"], c["ts"]) > (replays[rid]["commands"], replays[rid]["ts"])):
            replays[rid] = c
    replay_rows = [
        {"id": rid, "session": c["session"], "ip": c["ip"], "cc": geo.lookup(c["ip"])[0], "protocol": c["protocol"],
         "ts": c["ts"], "duration_ms": c["duration_ms"], "commands": c["commands"], "campaign": c.get("campaign"),
         "campaign_name": campaign_names.get(c.get("campaign") or "")}
        for rid, c in sorted(replays.items(), key=lambda kv: (-kv[1]["commands"], _desc(kv[1]["ts"]), kv[0]))
    ][:MAX_WINDOW_REPLAYS]

    arch: Counter = Counter(type_label(malware.get(sha)) for sha in downloads)
    arch.pop("Not analyzed", None)

    return {
        "start": start.isoformat(),
        "end": end.isoformat(),
        "days": len(dates),
        "totals": _totals(days, geo),
        "daily": daily,
        "heatmap": heatmap,
        "protocols": dict(protocols.most_common()),
        "countries": sorted(
            ({"cc": cc, "sessions": s, "ips": n,
              "top_ips": [ip for _s, ip in sorted(country_ips[cc], key=lambda t: (-t[0], t[1]))[:5]],
              "asns": [[asn, name, v] for (asn, name), v in
                       sorted(country_asns[cc].items(), key=lambda kv: (-kv[1], kv[0][0]))[:3]],
              "campaigns": [[cid, v] for cid, v in
                            sorted(country_campaigns[cc].items(), key=lambda kv: (-kv[1], kv[0]))[:3]]}
             for cc, (s, n) in countries.items()),
            key=lambda r: (-r["sessions"], r["cc"])),
        "asns": sorted(asns.values(), key=lambda r: (-r["sessions"], r["asn"]))[:TOP],
        "ips": [
            {"ip": ip, "cc": geo.lookup(ip)[0], "asn": geo.lookup(ip)[1], "as_name": geo.lookup(ip)[2],
             "sessions": c[0], "login_attempts": c[1], "login_success": c[2], "commands": c[3]}
            for ip, c in top_ips
        ],
        "usernames": _merge_top(days, "usernames"),
        "passwords": _merge_top(days, "passwords"),
        "credentials": _merge_top(days, "credentials"),
        "commands": [[defang_text(cmd), n] for cmd, n in _merge_top(days, "commands")],
        "clients": _merge_top(days, "clients"),
        "hassh": _merge_top(days, "hassh", 10),
        "techniques": technique_rows,
        "downloads": [
            {"sha256": d["sha256"], "url": defang(d["url"]), "count": d["count"],
             "first": d["first"], "last": d["last"], "ips": len(d["ips"]),
             "top_ips": [ip for ip, _n in sorted(d["ips"].items(), key=lambda kv: (-kv[1], kv[0]))[:5]],
             "campaigns": d["campaigns"][:3],
             "meta": malware_view(malware.get(d["sha256"])), "intel": intel_view(malware.get(d["sha256"]))}
            for d in sorted(downloads.values(), key=lambda d: (-d["count"], d["last"]))[:MAX_DOWNLOADS]
        ],
        "malware_arch": [[label, n] for label, n in sorted(arch.items(), key=lambda kv: (-kv[1], kv[0]))],
        "failed_downloads": [[defang(url), n] for url, n in failed.most_common(MAX_FAILED)],
        "campaigns": [{k: v for k, v in c.items() if not k.startswith("_")}
                      for c in sorted(campaigns.values(), key=lambda c: (-c["sessions"], c["id"]))[:MAX_CAMPAIGNS]],
        "replays": replay_rows,
        "records": records,
    }


def _desc(ts: str) -> tuple:
    """Sort key that orders timestamps newest first."""
    return tuple(-ord(ch) for ch in ts)


def _window_campaigns(days: list[dict], geo: GeoDB, candidates: list[dict], replay_ids: frozenset,
                      first_seen: dict[str, str], start: dt.date, is_all: bool) -> dict[str, dict]:
    merged: dict[str, dict] = {}
    for day in days:
        for cid, c in day.get("campaigns", {}).items():
            m = merged.setdefault(cid, {"id": cid, "name": c["name"], "known": c["known"], "sessions": 0,
                                        "ips": 0, "countries": [], "first": c["first"], "last": c["last"],
                                        "techniques": [], "commands": [], "downloads": [], "replay": None,
                                        "new": False, "_ips": Counter(), "_techniques": Counter()})
            m["name"], m["known"] = defang_text(c["name"]), c["known"]   # days are in order: the latest name wins
            m["sessions"] += c["sessions"]
            m["_ips"].update(c.get("ips", {}))
            m["first"], m["last"] = min(m["first"], c["first"]), max(m["last"], c["last"])
            m["_techniques"].update(c.get("techniques", {}))
            if len(c.get("commands", [])) > len(m["commands"]):
                m["commands"] = [defang_text(cmd[:MAX_TEXT]) for cmd in c["commands"][:MAX_CAMPAIGN_COMMANDS]]
            for sha in c.get("downloads", []):
                if sha not in m["downloads"] and len(m["downloads"]) < 5:
                    m["downloads"].append(sha)
    by_campaign: dict[str, list[dict]] = defaultdict(list)
    for c in candidates:
        if c.get("campaign"):
            by_campaign[c["campaign"]].append(c)
    for cid, m in merged.items():
        m["ips"] = len(m["_ips"])
        cc_counts: Counter = Counter()
        for ip, n in m["_ips"].items():
            cc_counts[geo.lookup(ip)[0]] += n
        m["countries"] = [[cc, n] for cc, n in sorted(cc_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:5]]
        m["techniques"] = [tid for tid, _n in sorted(m["_techniques"].items(), key=lambda kv: (-kv[1], kv[0]))
                           if tid in TECHNIQUES]
        m["replay"] = _best_replay(by_campaign.get(cid, []), replay_ids)
        m["new"] = not is_all and first_seen.get(cid, "")[:10] >= start.isoformat()
    return merged


def build(all_days: list[dict], geo: GeoDB, *, now: dt.datetime | None = None, demo: bool = False,
          malware: dict[str, dict] | None = None, replay_ids: set[str] | frozenset | None = None) -> dict:
    """stats.json. `replay_ids` are the replay files that exist; only those get linked."""
    now = now or dt.datetime.now(dt.timezone.utc)
    replay_ids = frozenset(r for r in (replay_ids or ()) if REPLAY_ID.match(r))
    stats: dict = {
        "schema": SCHEMA,
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "demo": demo,
        "sensor": None,
        "windows": {},
    }
    if not all_days:
        return stats
    first_seen: dict[str, str] = {}
    names: dict[str, str] = {}
    for day in all_days:
        for cid, c in day.get("campaigns", {}).items():
            first_seen[cid] = min(first_seen.get(cid, c["first"]), c["first"])
            names[cid] = defang_text(c["name"])
    ranges = window_ranges(all_days)
    first, end = dt.date.fromisoformat(all_days[0]["date"]), ranges[0][3]
    stats["sensor"] = {"name": all_days[-1].get("sensor", ""), "first_day": first.isoformat(),
                       "last_day": end.isoformat()}
    for key, label, start, end in ranges:
        window = build_window(all_days, start, end, geo, malware=malware, replay_ids=replay_ids,
                              first_seen=first_seen, campaign_names=names, is_all=key == "all")
        window["label"] = label
        window["previous"] = None
        length = dict((k, n) for k, _l, n in WINDOWS)[key]
        if length is not None:
            prev_end = start - dt.timedelta(days=1)
            prev_start = prev_end - dt.timedelta(days=length - 1)
            prev_days = [d for d in all_days if prev_start.isoformat() <= d["date"] <= prev_end.isoformat()]
            # Only compare against a full previous period, otherwise the delta is noise.
            if prev_days and first <= prev_start:
                window["previous"] = _totals(prev_days, geo)
        stats["windows"][key] = window
    return stats


# ------------------------------------------------------------------ profiles

def build_profiles(all_days: list[dict], geo: GeoDB, *, replay_ids: set[str] | frozenset | None = None,
                   now: dt.datetime | None = None) -> dict:
    """profiles.json: an all-time digest of every IP active in the last 30 days."""
    now = now or dt.datetime.now(dt.timezone.utc)
    replay_ids = frozenset(replay_ids or ())
    out: dict = {"generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "ips": {}}
    if not all_days:
        return out
    cutoff = (dt.date.fromisoformat(all_days[-1]["date"]) - dt.timedelta(days=PROFILE_DAYS - 1)).isoformat()
    recent: Counter = Counter()
    for day in all_days:
        if day["date"] >= cutoff:
            for ip, c in day["ips"].items():
                recent[ip] += c[0] or 0
                recent.setdefault(ip, 0)
    chosen = sorted(recent, key=lambda ip: (-recent[ip], ip))[:MAX_PROFILES]
    agg = {ip: {"first": None, "last": None, "days_active": 0, "counters": [0, 0, 0, 0], "protocols": Counter(),
                "daily": [], "credentials": Counter(), "commands": Counter(), "campaigns": Counter(),
                "downloads": [], "clients": Counter(), "replays": []} for ip in chosen}
    for day in all_days:
        date = day["date"]
        profiles = day.get("profiles", {})
        for ip, c in day["ips"].items():
            a = agg.get(ip)
            if a is None:
                continue
            for i, value in enumerate(c):
                a["counters"][i] += value
            if c[0]:
                a["days_active"] += 1
                if date >= cutoff:
                    a["daily"].append([date, c[0]])
            p = profiles.get(ip) or {}
            first, last = p.get("first") or date, p.get("last") or date
            a["first"] = first if a["first"] is None else min(a["first"], first)
            a["last"] = last if a["last"] is None else max(a["last"], last)
            a["protocols"].update(p.get("protocols", {}))
            for u, pw, n in p.get("credentials", []):
                a["credentials"][(u, pw)] += n
            for cmd, n in p.get("commands", []):
                a["commands"][cmd] += n
            a["campaigns"].update(p.get("campaigns", {}))
            for sha in p.get("downloads", []):
                if sha not in a["downloads"] and len(a["downloads"]) < 10:
                    a["downloads"].append(sha)
            for banner, n in p.get("clients", []):
                a["clients"][banner] += n
            for sha in p.get("replays", []):
                rid = str(sha)[:16]
                if rid in replay_ids and rid not in a["replays"] and len(a["replays"]) < 5:
                    a["replays"].append(rid)
    for ip in sorted(chosen):
        a = agg[ip]
        cc, asn, as_name = geo.lookup(ip)
        sessions, attempts, success, commands = a["counters"]
        out["ips"][ip] = {
            "cc": cc, "asn": asn, "as_name": as_name, "first": a["first"], "last": a["last"],
            "days_active": a["days_active"], "sessions": sessions, "login_attempts": attempts,
            "login_success": success, "commands": commands, "protocols": dict(a["protocols"].most_common()),
            "daily": a["daily"],
            "credentials": [[u, pw, n] for (u, pw), n in a["credentials"].most_common(10)],
            "top_commands": [[defang_text(cmd), n] for cmd, n in a["commands"].most_common(10)],
            "campaigns": [[cid, n] for cid, n in sorted(a["campaigns"].items(), key=lambda kv: (-kv[1], kv[0]))],
            "downloads": a["downloads"],
            "clients": [[b, n] for b, n in a["clients"].most_common(3)],
            "replays": a["replays"],
        }
    return out
