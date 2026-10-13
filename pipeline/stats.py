"""Merge daily summaries into the dashboard's stats.json.

The dashboard offers three time windows (last 7 days, last 30 days, all time);
each is precomputed here so every chart on the page can be re-scoped instantly.
"""
from __future__ import annotations

import datetime as dt
import json
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlsplit

from .attack import TACTIC_ORDER, TECHNIQUES
from .geo import GeoDB

SCHEMA = 1
TOP = 15
WINDOWS = [("7d", "Last 7 days", 7), ("30d", "Last 30 days", 30), ("all", "All time", None)]
TOTAL_KEYS = ("sessions", "unique_ips", "login_attempts", "login_success",
              "commands", "interactive_sessions", "downloads", "countries")


def load_days(daily_dir: Path) -> list[dict]:
    days = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(daily_dir.glob("*.json"))]
    return sorted(days, key=lambda d: d["date"])


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


def build_window(all_days: list[dict], start: dt.date, end: dt.date, geo: GeoDB) -> dict:
    by_date = {d["date"]: d for d in all_days}
    dates = _date_range(start, end)
    days = [by_date[d] for d in dates if d in by_date]

    ips: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0, 0])
    heatmap = [[0] * 24 for _ in range(7)]
    protocols: Counter = Counter()
    techniques: Counter = Counter()
    downloads: dict[str, dict] = {}
    for day in days:
        for ip, counters in day["ips"].items():
            merged = ips[ip]
            for i, value in enumerate(counters):
                merged[i] += value
        weekday = dt.date.fromisoformat(day["date"]).weekday()
        for hour, value in enumerate(day["hourly"]):
            heatmap[weekday][hour] += value
        protocols.update(day.get("protocols", {}))
        techniques.update(day.get("techniques", {}))
        for d in day.get("downloads", []):
            item = downloads.setdefault(d["sha256"], {**d, "count": 0})
            item["count"] += d["count"]
            item["first"], item["last"] = min(item["first"], d["first"]), max(item["last"], d["last"])

    countries: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    asns: dict[int, dict] = {}
    for ip, (sessions, *_rest) in ips.items():
        cc, asn, name = geo.lookup(ip)
        if sessions:
            countries[cc][0] += sessions
            countries[cc][1] += 1
        if asn:
            a = asns.setdefault(asn, {"asn": asn, "name": name, "cc": cc, "sessions": 0, "ips": 0})
            a["sessions"] += sessions
            a["ips"] += 1 if sessions else 0

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

    return {
        "start": start.isoformat(),
        "end": end.isoformat(),
        "days": len(dates),
        "totals": _totals(days, geo),
        "daily": daily,
        "heatmap": heatmap,
        "protocols": dict(protocols.most_common()),
        "countries": sorted(
            ({"cc": cc, "sessions": s, "ips": n} for cc, (s, n) in countries.items()),
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
        "commands": _merge_top(days, "commands"),
        "clients": _merge_top(days, "clients"),
        "hassh": _merge_top(days, "hassh", 10),
        "techniques": technique_rows,
        "downloads": [
            {"sha256": d["sha256"], "url": defang(d["url"]), "count": d["count"],
             "first": d["first"], "last": d["last"]}
            for d in sorted(downloads.values(), key=lambda d: (-d["count"], d["last"]))[:20]
        ],
    }


def build(all_days: list[dict], geo: GeoDB, *, now: dt.datetime | None = None, demo: bool = False) -> dict:
    now = now or dt.datetime.now(dt.timezone.utc)
    stats: dict = {
        "schema": SCHEMA,
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "demo": demo,
        "sensor": None,
        "windows": {},
    }
    if not all_days:
        return stats
    first = dt.date.fromisoformat(all_days[0]["date"])
    end = dt.date.fromisoformat(all_days[-1]["date"])
    stats["sensor"] = {"name": all_days[-1].get("sensor", ""), "first_day": first.isoformat(),
                       "last_day": end.isoformat()}
    for key, label, length in WINDOWS:
        start = first if length is None else max(first, end - dt.timedelta(days=length - 1))
        window = build_window(all_days, start, end, geo)
        window["label"] = label
        window["previous"] = None
        if length is not None:
            prev_end = start - dt.timedelta(days=1)
            prev_start = prev_end - dt.timedelta(days=length - 1)
            prev_days = [d for d in all_days if prev_start.isoformat() <= d["date"] <= prev_end.isoformat()]
            # Only compare against a full previous period, otherwise the delta is noise.
            if prev_days and first <= prev_start:
                window["previous"] = _totals(prev_days, geo)
        stats["windows"][key] = window
    return stats
