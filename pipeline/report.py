"""Weekly Markdown reports: reports/YYYY-Www.md for every ISO week with data, plus an index.

Everything is computed from the daily summaries in data/daily/, so any week can be rebuilt at
any time and its file only changes when that week's data does. Attacker strings go through
render.md_code and URLs through stats.defang, like the README block; links are only built from
values that pass a strict format check.
"""
from __future__ import annotations

import datetime as dt
import re
from collections import Counter, defaultdict
from pathlib import Path

from .geo import GeoDB
from .render import country_name, md_code
from .stats import defang

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
SHA256 = re.compile(r"^[0-9a-f]{64}$")
REPLAY_ID = re.compile(r"^[0-9a-f]{16}$")
CAMPAIGN_ID = re.compile(r"^[a-z0-9-]{1,40}$")
IPV4 = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
KIND_LABELS = {"script": "Shell script", "archive": "Archive", "html": "HTML", "text": "Text",
               "data": "Data", "empty": "Empty file"}
NOTHING = "_Nothing recorded this week._"


# ------------------------------------------------------------------ formatting

def _day(d: dt.date, year: bool = True) -> str:
    return f"{MONTHS[d.month - 1]} {d.day}" + (f", {d.year}" if year else "")


def _span(start: dt.date, end: dt.date) -> str:
    if start.year != end.year:
        return f"{_day(start)} – {_day(end)}"
    return f"{_day(start, year=False)} – {_day(end)}"


def _ts_day(ts: str) -> str:
    try:
        return _day(dt.date.fromisoformat(str(ts)[:10]), year=False)
    except ValueError:
        return "–"


def _text(value: object, limit: int = 80) -> str:
    """Plain Markdown text for a table cell: one line, no markup, no HTML."""
    text = "".join(ch for ch in " ".join(str(value).split()) if ch.isprintable())
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return re.sub(r"([\\`*_\[\]<>|~&#!])", r"\\\1", text)


def _change(current: int, previous: int | None) -> str:
    if previous is None:
        return "–"
    if previous == 0:
        return "new" if current else "±0%"
    pct = (current - previous) * 100 / previous
    if abs(pct) < 0.5:
        return "±0%"
    return f"{'+' if pct > 0 else '−'}{abs(pct):.0f}%"


def _size(n: object) -> str:
    if not isinstance(n, int) or n < 0:
        return "–"
    for unit, step in (("MB", 1 << 20), ("KB", 1 << 10)):
        if n >= step:
            return f"{n / step:.1f} {unit}"
    return f"{n} B"


def _duration(ms: int) -> str:
    seconds = ms / 1000
    if seconds < 60:
        return f"{seconds:.1f} s"
    minutes, sec = divmod(int(round(seconds)), 60)
    if minutes < 60:
        return f"{minutes} min {sec} s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} h {minutes} min"


def _table(header: list[str], align: str, rows: list[list[str]]) -> list[str]:
    seps = ["---:" if a == "r" else "---" for a in align]
    return ["| " + " | ".join(header) + " |", "|" + "|".join(seps) + "|"] + [
        "| " + " | ".join(r) + " |" for r in rows]


class Links:
    """Dashboard, VirusTotal and replay links, built only from validated values."""

    def __init__(self, site_url: str, replay_ids: set[str] | None) -> None:
        self.site = site_url
        self.replay_ids = replay_ids or set()

    def ip(self, ip: str) -> str:
        return f"[{ip}]({self.site}#all&ip={ip})" if IPV4.match(ip) else _text(ip, 45)

    def campaign(self, cid: str) -> str:
        return f"[Dashboard]({self.site}#all&campaign={cid})" if CAMPAIGN_ID.match(cid) else ""

    def replay(self, sha: str | None) -> str:
        rid = (sha or "")[:16]
        if REPLAY_ID.match(rid) and rid in self.replay_ids:
            return f"[Replay]({self.site}#all&replay={rid})"
        return ""

    @staticmethod
    def sample(sha: str) -> str:
        if not SHA256.match(sha):
            return _text(sha, 20)
        return f"[`{sha[:12]}…`](https://www.virustotal.com/gui/file/{sha})"


def _join(*parts: str) -> str:
    return " · ".join(p for p in parts if p) or "–"


# ------------------------------------------------------------------ aggregation

def _week_of(date: str) -> tuple[int, int]:
    year, week, _ = dt.date.fromisoformat(date).isocalendar()
    return year, week


def _name(year: int, week: int) -> str:
    return f"{year}-W{week:02d}"


def _first_seen(days: list[dict]) -> dict[str, dict[str, str]]:
    """Date each sample, campaign and password first appeared in any daily summary."""
    seen: dict[str, dict[str, str]] = {"sha": {}, "campaign": {}, "password": {}}
    for day in days:
        for d in day.get("downloads") or []:
            seen["sha"].setdefault(str(d.get("sha256", "")), day["date"])
        for cid in day.get("campaigns") or {}:
            seen["campaign"].setdefault(cid, day["date"])
        for item in day.get("passwords") or []:
            seen["password"].setdefault(str(item[0]), day["date"])
    return seen


def _better(current: dict | None, candidate: object, key: str) -> dict | None:
    if not isinstance(candidate, dict) or not isinstance(candidate.get(key), int) or candidate[key] <= 0:
        return current
    if current is None or (candidate[key], str(candidate.get("ts", ""))) > (current[key], str(current.get("ts", ""))):
        return candidate
    return current


def _aggregate(days: list[dict], geo: GeoDB) -> dict:
    totals: Counter = Counter()
    ips: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0, 0])
    ip_days: Counter = Counter()
    credentials: Counter = Counter()
    passwords: Counter = Counter()
    campaigns: dict[str, dict] = {}
    downloads: dict[str, dict] = {}
    sessions_to_tty: dict[str, str] = {}
    campaign_ttys: dict[str, dict[str, int]] = defaultdict(dict)   # campaign -> recording -> commands
    fallback_passwords: set[str] = set()
    records: dict[str, dict | None] = {"longest_session": None, "most_commands": None, "longest_password": None}
    for day in days:
        t = day.get("totals") or {}
        for key in ("sessions", "login_attempts", "login_success", "commands"):
            totals[key] += int(t.get(key, 0) or 0)
        for ip, counters in (day.get("ips") or {}).items():
            merged = ips[ip]
            for i, value in enumerate(counters[:4]):
                merged[i] += value
            if any(counters):
                ip_days[ip] += 1
        for user, password, n in day.get("credentials") or []:
            credentials[(str(user), str(password))] += n
        for password, n in day.get("passwords") or []:
            passwords[str(password)] += n
        for cid, c in (day.get("campaigns") or {}).items():
            m = campaigns.setdefault(cid, {"id": cid, "name": str(c.get("name") or cid), "sessions": 0,
                                           "ips": Counter(), "first": "", "last": ""})
            m["sessions"] += int(c.get("sessions", 0) or 0)
            m["ips"].update(c.get("ips") or {})
            first, last = str(c.get("first") or ""), str(c.get("last") or "")
            if first and (not m["first"] or first < m["first"]):
                m["first"] = first
            if last >= m["last"]:
                m["last"], m["name"] = last, str(c.get("name") or m["name"])
        for d in day.get("downloads") or []:
            sha = str(d.get("sha256", ""))
            m = downloads.setdefault(sha, {"sha256": sha, "url": str(d.get("url", "")), "count": 0,
                                           "first": str(d.get("first", "")), "ips": set()})
            m["count"] += int(d.get("count", 0) or 0)
            m["first"] = min(m["first"], str(d.get("first", m["first"])))
            m["ips"].update(d.get("ips") or [])
        for r in day.get("replays") or []:
            if isinstance(r, dict) and r.get("session") and r.get("sha"):
                sha = str(r["sha"])
                sessions_to_tty.setdefault(str(r["session"]), sha)
                if r.get("campaign"):
                    best = campaign_ttys[str(r["campaign"])]
                    best[sha] = max(best.get(sha, 0), int(r.get("commands", 0) or 0))
        if "records" not in day:   # schema 1: only the daily top lists know about passwords
            fallback_passwords.update(str(item[0]) for item in day.get("passwords") or [])
        rec = day.get("records") or {}
        records["longest_session"] = _better(records["longest_session"], rec.get("longest_session"), "duration_ms")
        records["most_commands"] = _better(records["most_commands"], rec.get("most_commands"), "commands")
        records["longest_password"] = _better(records["longest_password"], rec.get("longest_password"), "length")
    for password in sorted(fallback_passwords):
        if password and (not records["longest_password"] or len(password) > records["longest_password"]["length"]):
            records["longest_password"] = {"length": len(password), "password": password, "ip": "", "ts": ""}

    active = {ip: c for ip, c in ips.items() if c[0]}
    countries: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    asns: dict[int, dict] = {}
    for ip, c in active.items():
        cc, asn, as_name = geo.lookup(ip)
        countries[cc][0] += c[0]
        countries[cc][1] += 1
        if asn:
            a = asns.setdefault(asn, {"asn": asn, "name": as_name, "cc": cc, "sessions": 0, "ips": 0})
            a["sessions"] += c[0]
            a["ips"] += 1
    attempts = max(ips.items(), key=lambda kv: (kv[1][1], kv[0]), default=None)
    persistent = max(ip_days.items(), key=lambda kv: (kv[1], ips[kv[0]][0], kv[0]), default=None)
    records["most_attempts_ip"] = {"attempts": attempts[1][1], "ip": attempts[0]} if attempts and attempts[1][1] else None
    records["most_persistent_ip"] = {"days": persistent[1], "ip": persistent[0]} if persistent else None
    return {
        "dates": sorted(d["date"] for d in days),
        "sensor": next((d.get("sensor") for d in reversed(days) if d.get("sensor")), ""),
        "totals": {**{k: totals[k] for k in ("sessions", "login_attempts", "login_success", "commands")},
                   "unique_ips": len(active), "countries": len(set(countries) - {"??"})},
        "ips": ips,
        "countries": sorted(countries.items(), key=lambda kv: (-kv[1][0], kv[0])),
        "asns": sorted(asns.values(), key=lambda a: (-a["sessions"], a["asn"])),
        "credentials": sorted(credentials.items(), key=lambda kv: (-kv[1], kv[0])),
        "passwords": passwords,
        "campaigns": sorted(campaigns.values(), key=lambda c: (-c["sessions"], c["id"])),
        "downloads": downloads,
        "sessions_to_tty": sessions_to_tty,
        "campaign_ttys": {cid: [sha for sha, _ in sorted(best.items(), key=lambda kv: (-kv[1], kv[0]))]
                          for cid, best in campaign_ttys.items()},
        "records": records,
    }


# ------------------------------------------------------------------ week report

def _file_type(meta: dict | None) -> str:
    if not meta:
        return "–"
    elf = meta.get("elf") if isinstance(meta.get("elf"), dict) else None
    if meta.get("kind") == "elf" and elf:
        label = f"{elf.get('machine') or 'ELF'} {elf.get('bits', '?')}-bit {'LE' if elf.get('endian') == 'little' else 'BE'}"
        if elf.get("static"):
            label += ", static"
    else:
        label = KIND_LABELS.get(str(meta.get("kind")), "Other")
    if meta.get("packer"):
        label += f", {meta['packer']} packed"
    return _text(label, 40)


def _detections(meta: dict | None) -> str:
    intel = (meta or {}).get("intel") or {}
    parts = []
    vt = intel.get("vt")
    if isinstance(vt, dict) and isinstance(vt.get("malicious"), int):
        parts.append(f"VT {vt['malicious']}/{vt.get('total', '?')}"
                     + (f" {_text(vt['label'], 40)}" if vt.get("label") else ""))
    mb = intel.get("mb")
    if isinstance(mb, dict) and mb.get("signature"):
        parts.append(f"MalwareBazaar: {_text(mb['signature'], 30)}")
    return " · ".join(parts) or "–"


def _records_rows(records: dict, links: Links, sessions_to_tty: dict[str, str]) -> list[list[str]]:
    rows = []
    r = records.get("longest_session")
    if r:
        replay = links.replay(sessions_to_tty.get(str(r.get("session", ""))))
        rows.append(["Longest session", f"{_duration(r['duration_ms'])}"
                     + (f" ({_text(r['protocol'], 10)})" if r.get("protocol") else "") + f" · {_ts_day(r.get('ts', ''))}",
                     _join(links.ip(str(r.get("ip", ""))) if r.get("ip") else "", replay)])
    r = records.get("most_commands")
    if r:
        replay = links.replay(sessions_to_tty.get(str(r.get("session", ""))))
        rows.append(["Most commands in one session", f"{r['commands']:,} · {_ts_day(r.get('ts', ''))}",
                     _join(links.ip(str(r.get("ip", ""))) if r.get("ip") else "", replay)])
    r = records.get("longest_password")
    if r:
        rows.append(["Longest password", f"{md_code(str(r.get('password', '')), 60)} ({r['length']:,} characters)",
                     links.ip(str(r["ip"])) if r.get("ip") else "–"])
    r = records.get("most_attempts_ip")
    if r:
        rows.append(["Most login attempts from one IP", f"{r['attempts']:,}", links.ip(r["ip"])])
    r = records.get("most_persistent_ip")
    if r:
        rows.append(["Most persistent IP", f"active on {r['days']} day{'s' if r['days'] != 1 else ''}",
                     links.ip(r["ip"])])
    return rows


def _week_report(year: int, week: int, agg: dict, prev: dict | None, seen: dict, malware: dict[str, dict],
                 links: Links, today: dt.date, history: bool) -> str:
    monday = dt.date.fromisocalendar(year, week, 1)
    sunday = monday + dt.timedelta(days=6)
    name = _name(year, week)
    lines = [f"# Week {name} · {_span(monday, sunday)}", ""]
    last = dt.date.fromisoformat(agg["dates"][-1])
    if monday <= today <= sunday:
        lines += [f"> **In progress.** Covers {_span(monday, last)} so far and updates with every pipeline run.", ""]
    sensor = f"Sensor {md_code(agg['sensor'])} · " if agg["sensor"] else ""
    lines += [f"{sensor}[Live dashboard]({links.site}) · [All weekly reports](README.md)", ""]

    def new_samples(a: dict | None) -> int | None:
        if a is None:
            return None
        return sum(1 for sha in a["downloads"] if seen["sha"].get(sha, "") in a["dates"])

    current_new = new_samples(agg) or 0
    headline = [("Connections", "sessions"), ("Unique IPs", "unique_ips"), ("Login attempts", "login_attempts"),
                ("Successful logins", "login_success"), ("Commands run", "commands")]
    rows = []
    for label, key in headline:
        p = prev["totals"][key] if prev else None
        rows.append([label, f"{agg['totals'][key]:,}", f"{p:,}" if p is not None else "–", _change(agg["totals"][key], p)])
    p_new = new_samples(prev)
    rows.append(["New malware samples", f"{current_new:,}", f"{p_new:,}" if p_new is not None else "–",
                 _change(current_new, p_new)])
    p = prev["totals"]["countries"] if prev else None
    rows.append(["Countries", f"{agg['totals']['countries']:,}", f"{p:,}" if p is not None else "–",
                 _change(agg["totals"]["countries"], p)])
    lines += _table(["", "This week", "Previous week", "Change"], "lrrr", rows) + [""]

    lines += ["## Attack campaigns", "", "Sessions grouped by the commands they ran (heuristic).", ""]
    if agg["campaigns"]:
        rows = []
        for c in agg["campaigns"][:8]:
            new = " **new**" if seen["campaign"].get(c["id"], "") in agg["dates"] else ""
            replay = next((links.replay(sha) for sha in agg["campaign_ttys"].get(c["id"], []) if links.replay(sha)), "")
            rows.append([md_code(str(c["name"]), 60) + new, f"{c['sessions']:,}", f"{len(c['ips']):,}",
                         _ts_day(c["first"]), _join(links.campaign(c["id"]), replay)])
        lines += _table(["Campaign", "Sessions", "IPs", "First seen", "Links"], "lrrll", rows)
    else:
        lines.append(NOTHING)
    lines.append("")

    lines += ["## New malware samples", "",
              "Files fetched into the fake shell for the first time this week. URLs are defanged.", ""]
    fresh = [d for sha, d in agg["downloads"].items() if seen["sha"].get(sha, "") in agg["dates"]]
    fresh.sort(key=lambda d: (-d["count"], d["first"], d["sha256"]))
    if fresh:
        rows = []
        for d in fresh[:15]:
            meta = malware.get(d["sha256"])
            rows.append([links.sample(d["sha256"]), _file_type(meta), _size((meta or {}).get("size")),
                         _detections(meta), md_code(defang(d["url"]), 60) if d["url"] else "–", f"{d['count']:,}"])
        lines += _table(["SHA-256", "Type", "Size", "Detections", "Source", "Seen"], "lllllr", rows)
        if len(fresh) > 15:
            lines += ["", f"_…and {len(fresh) - 15:,} more on the dashboard._"]
    else:
        lines.append(NOTHING)
    lines.append("")

    lines += ["## Where attacks came from", ""]
    total = agg["totals"]["sessions"]
    if agg["countries"]:
        lines += _table(["Country", "Connections", "IPs", "Share"], "lrrr", [
            [_text(country_name(cc)), f"{s:,}", f"{n:,}", f"{s * 100 / total:.1f}%" if total else "–"]
            for cc, (s, n) in agg["countries"][:8]])
        if agg["asns"]:
            lines += [""] + _table(["Network", "Country", "Connections", "IPs"], "llrr", [
                [_text(f"AS{a['asn']} {a['name']}", 60), _text(country_name(a["cc"])), f"{a['sessions']:,}", f"{a['ips']:,}"]
                for a in agg["asns"][:5]])
    else:
        lines.append(NOTHING)
    lines.append("")

    lines += ["## Credentials", ""]
    if agg["credentials"]:
        lines += _table(["Username", "Password", "Attempts"], "llr", [
            [md_code(u, 40), md_code(p, 40), f"{n:,}"] for (u, p), n in agg["credentials"][:10]])
    else:
        lines.append(NOTHING)
    novel = sorted(((p, n) for p, n in agg["passwords"].items() if seen["password"].get(p, "") in agg["dates"]),
                   key=lambda kv: (-kv[1], kv[0]))
    lines += ["", "**Passwords never tried before this week** (among each day's 500 most common)", ""]
    if not history:
        lines.append("_The sensor's first week: every password is new._")
    elif novel:
        lines += _table(["Password", "Attempts"], "lr", [[md_code(p, 50), f"{n:,}"] for p, n in novel[:10]])
    else:
        lines.append(NOTHING)
    lines.append("")

    lines += ["## Records of the week", ""]
    rows = _records_rows(agg["records"], links, agg["sessions_to_tty"])
    lines += _table(["Record", "Value", "Who"], "lll", rows) if rows else [NOTHING]
    lines += ["", "<sub>Written by the pipeline from data/daily/. Source IPs are mostly compromised machines "
              "or rented servers: report abuse, don't retaliate.</sub>", ""]
    return "\n".join(lines)


# ------------------------------------------------------------------ index

def _index(weeks: list[tuple[int, int, dict]], all_time: dict, links: Links, today: dt.date) -> str:
    lines = ["# Weekly reports", "",
             f"Written automatically by the pipeline from the honeypot's daily summaries. "
             f"[Live dashboard]({links.site})", ""]
    rows = []
    for year, week, agg in sorted(weeks, key=lambda w: (w[0], w[1]), reverse=True):
        monday = dt.date.fromisocalendar(year, week, 1)
        name = _name(year, week)
        progress = " _(in progress)_" if monday <= today <= monday + dt.timedelta(days=6) else ""
        t = agg["totals"]
        top = md_code(str(agg["campaigns"][0]["name"]), 40) if agg["campaigns"] else "–"
        rows.append([f"[{name}]({name}.md){progress}", _span(monday, monday + dt.timedelta(days=6)),
                     f"{t['sessions']:,}", f"{t['unique_ips']:,}", f"{t['login_attempts']:,}", f"{t['commands']:,}",
                     f"{agg['new_samples']:,}", top])
    lines += _table(["Week", "Dates", "Connections", "Unique IPs", "Login attempts", "Commands", "New samples",
                     "Top campaign"], "llrrrrrl", rows)
    lines += ["", "## All-time records", ""]
    rows = _records_rows(all_time["records"], links, all_time["sessions_to_tty"])
    if all_time["campaigns"]:
        c = all_time["campaigns"][0]
        rows.append(["Most active campaign", f"{md_code(str(c['name']), 50)} · {c['sessions']:,} sessions",
                     links.campaign(c["id"]) or "–"])
    lines += _table(["Record", "Value", "Who"], "lll", rows) if rows else ["_No data yet._"]
    lines += ["", f"<sub>Data through {_day(dt.date.fromisoformat(all_time['dates'][-1]))}.</sub>", ""]
    return "\n".join(lines)


# ------------------------------------------------------------------ entry point

def write_reports(days: list[dict], malware: dict[str, dict], geo: GeoDB, out_dir: Path, *,
                  site_url: str, now: dt.datetime, replay_ids: set[str] | None = None) -> list[Path]:
    """Write reports/YYYY-Www.md for every ISO week with data plus reports/README.md; return changed files."""
    days = sorted((d for d in days if d.get("date")), key=lambda d: d["date"])
    if not days:
        return []
    links = Links(site_url, replay_ids)
    today = now.astimezone(dt.timezone.utc).date() if now.tzinfo else now.date()
    seen = _first_seen(days)
    by_week: dict[tuple[int, int], list[dict]] = defaultdict(list)
    for day in days:
        by_week[_week_of(day["date"])].append(day)

    files: dict[str, str] = {}
    weeks = []
    for (year, week), week_days in sorted(by_week.items()):
        agg = _aggregate(week_days, geo)
        agg["new_samples"] = sum(1 for sha in agg["downloads"] if seen["sha"].get(sha, "") in agg["dates"])
        prev_monday = dt.date.fromisocalendar(year, week, 1) - dt.timedelta(days=7)
        prev_days = by_week.get(_week_of(prev_monday.isoformat()))
        prev = _aggregate(prev_days, geo) if prev_days else None
        history = days[0]["date"] < agg["dates"][0]
        files[f"{_name(year, week)}.md"] = _week_report(year, week, agg, prev, seen, malware, links, today, history)
        weeks.append((year, week, agg))
    all_time = _aggregate(days, geo)
    files["README.md"] = _index(weeks, all_time, links, today)

    out_dir.mkdir(parents=True, exist_ok=True)
    changed = []
    for name, text in sorted(files.items()):
        path = out_dir / name
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            path.write_text(text, encoding="utf-8")
            changed.append(path)
    return changed
