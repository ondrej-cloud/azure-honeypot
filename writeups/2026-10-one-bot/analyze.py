"""Numbers and charts for the write-up "One bot, 71% of the traffic".

    IGNORE_IPS="$(cat .admin-ips)" python3 writeups/2026-10-one-bot/analyze.py cowrie/2026-10-1[4-7].json.gz

The input is the sensor's raw log blobs (`cowrie/<day>.json.gz` in the storage
account). Addresses in IGNORE_IPS are dropped first, exactly as the pipeline
does, and the charts are written next to this script.
"""
from __future__ import annotations

import collections
import datetime as dt
import gzip
import ipaddress
import json
import os
import statistics
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))

from pipeline.cowrie import parse_networks  # noqa: E402
from pipeline.render import STYLE, compact, nice_ticks  # noqa: E402

# The bot's fingerprint: one Go SSH client, one login, this one command, gone.
CLIENT = "SSH-2.0-Go"
COMMAND = "uname -s -v -n -r -m"
SHIFT_GAP = dt.timedelta(minutes=30)  # a longer pause from the same IP starts a new shift
HOUR = dt.timedelta(hours=1)

# The bot takes categorical slot 2 (orange) next to the slot-1 blue used for
# everything else; the pair is validated for both light and dark surfaces.
BOT_STYLE = ".bot{fill:#eb6834}@media (prefers-color-scheme:dark){.bot{fill:#d95926}}"


def ts(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def load(paths: list[Path], ignored: tuple) -> list[dict]:
    """Cowrie events folded into one dict per session, oldest first."""
    sessions: dict[str, dict] = {}
    for path in paths:
        opener = gzip.open if path.suffix == ".gz" else open
        with opener(path, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if not event.get("session"):
                    continue
                s = sessions.setdefault(event["session"], {"logins": [], "commands": []})
                kind = event.get("eventid")
                if kind == "cowrie.session.connect":
                    s["ip"], s["start"] = event["src_ip"], ts(event["timestamp"])
                elif kind == "cowrie.client.version":
                    s["client"] = event.get("version")
                elif kind in ("cowrie.login.success", "cowrie.login.failed"):
                    s["logins"].append((event.get("username"), event.get("password")))
                elif kind == "cowrie.command.input":
                    s["commands"].append(event.get("input"))
                elif kind == "cowrie.session.closed":
                    s["ms"] = event.get("duration_ms")

    def kept(s: dict) -> bool:
        return "start" in s and not any(ipaddress.ip_address(s["ip"]) in n for n in ignored)

    return sorted(filter(kept, sessions.values()), key=lambda s: s["start"])


def is_bot(s: dict) -> bool:
    return s.get("client") == CLIENT and s["commands"] == [COMMAND]


def shifts(times: list[dt.datetime]) -> list[list[dt.datetime]]:
    """Split one IP's connection times wherever it paused longer than SHIFT_GAP."""
    runs = [[times[0]]]
    for prev, cur in zip(times, times[1:]):
        if cur - prev > SHIFT_GAP:
            runs.append([])
        runs[-1].append(cur)
    return runs


def summary(sessions: list[dict]) -> dict:
    bot = [s for s in sessions if is_bot(s)]
    rest = [s for s in sessions if not is_bot(s)]
    by_ip: dict[str, list[dt.datetime]] = collections.defaultdict(list)
    for s in bot:
        by_ip[s["ip"]].append(s["start"])
    runs = [run for times in by_ip.values() for run in shifts(times)]
    full = [run for run in runs if len(run) == 500]
    gaps = [(b - a).total_seconds() for run in runs for a, b in zip(run, run[1:])]

    pairs = collections.Counter(s["logins"][0] for s in bot if s["logins"])
    owners: dict[tuple, set] = collections.defaultdict(set)
    for s in bot:
        if s["logins"]:
            owners[s["logins"][0]].add(s["ip"])
    tried_elsewhere = {p for s in rest for p in s["logins"]} & set(pairs)

    windows: dict[dt.datetime, set] = collections.defaultdict(set)
    for s in bot:
        windows[s["start"].replace(minute=s["start"].minute // 10 * 10, second=0, microsecond=0)].add(s["ip"])

    return {
        "window": f"{sessions[0]['start']:%Y-%m-%d %H:%M} to {sessions[-1]['start']:%Y-%m-%d %H:%M} UTC",
        "sessions": len(sessions),
        "bot_sessions": len(bot),
        "bot_share": f"{100 * len(bot) / len(sessions):.1f}%",
        "bot_ips": len(by_ip),
        "bot_networks": sorted({str(ipaddress.ip_network(f"{ip}/24", strict=False)) for ip in by_ip}),
        "other_sessions": len(rest),
        "other_ips": len({s["ip"] for s in rest}),
        "shifts": len(runs),
        "shifts_of_exactly_500": len(full),
        "minutes_per_500_median": round(statistics.median((r[-1] - r[0]).total_seconds() / 60 for r in full), 1),
        "seconds_between_logins_median": round(statistics.median(gaps), 1),
        "session_seconds_median": round(statistics.median(s["ms"] / 1000 for s in bot if s.get("ms") is not None), 2),
        "ten_minute_windows_with_one_ip": f"{sum(len(v) == 1 for v in windows.values())} of {len(windows)}",
        "most_ips_at_once": max(len(v) for v in windows.values()),
        "credential_pairs": len(pairs),
        "usernames": len({u for u, _ in pairs}),
        "passwords": len({p for _, p in pairs}),
        "pairs_shared_between_bot_ips": sum(len(ips) > 1 for ips in owners.values()),
        "pairs_also_tried_by_others": len(tried_elsewhere),
        "top_usernames": collections.Counter(u for u, _ in pairs.elements()).most_common(8),
        "top_passwords": collections.Counter(p for _, p in pairs.elements()).most_common(8),
    }


# ------------------------------------------------------------------ charts

def svg(width: int, height: int, title: str, body: list[str]) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="{width}" height="{height}" role="img">'
        f"<title>{title}</title><style>{STYLE}{BOT_STYLE}</style>{''.join(body)}</svg>\n"
    )


def column(x: float, w: float, base: float, h: float, r: float = 4) -> str:
    """Vertical bar, square at the base, rounded at the top."""
    r = min(r, w / 2, h)
    top = base - h
    return (f"M{x:.1f},{base:.1f}V{top + r:.1f}A{r},{r} 0 0 1 {x + r:.1f},{top:.1f}"
            f"H{x + w - r:.1f}A{r},{r} 0 0 1 {x + w:.1f},{top + r:.1f}V{base:.1f}Z")


def time_axis(body: list[str], x, start: dt.datetime, end: dt.datetime, y0: float, y1: float) -> None:
    """Vertical hairlines at midnight and noon UTC, labelled under the plot."""
    t = start.replace(hour=0, minute=0, second=0, microsecond=0)
    while t <= end:
        for hour, label in ((0, f"{t:%b} {t.day}"), (12, "12:00")):
            mark = t + dt.timedelta(hours=hour)
            if start <= mark <= end:
                body.append(f'<line class="grid" x1="{x(mark):.1f}" x2="{x(mark):.1f}" y1="{y0}" y2="{y1}"/>')
                cls = "ink2" if hour == 0 else "muted"
                body.append(f'<text class="{cls}" x="{x(mark):.1f}" y="{y1 + 18}" text-anchor="middle">{label}</text>')
        t += dt.timedelta(days=1)


def hourly_chart(sessions: list[dict]) -> str:
    """Connections per hour, the bot stacked on top of everything else."""
    width, height = 800, 270
    left, right, top, bottom = 44, 16, 40, 30
    start = sessions[0]["start"].replace(minute=0, second=0, microsecond=0)
    end = sessions[-1]["start"].replace(minute=0, second=0, microsecond=0) + HOUR
    hours = int((end - start) / HOUR)
    bot, rest = [0] * hours, [0] * hours
    for s in sessions:
        i = int((s["start"] - start) / HOUR)
        (bot if is_bot(s) else rest)[i] += 1

    plot_w, plot_h = width - left - right, height - top - bottom
    ticks = nice_ticks(max(b + r for b, r in zip(bot, rest)))
    slot = plot_w / hours

    def y(v: float) -> float:
        return top + plot_h - plot_h * v / ticks[-1]

    def x(t: dt.datetime) -> float:
        return left + plot_w * (t - start) / (end - start)

    body = []
    for t in ticks:
        body.append(f'<line class="grid" x1="{left}" x2="{width - right}" y1="{y(t):.1f}" y2="{y(t):.1f}"/>')
        body.append(f'<text class="muted" x="{left - 8}" y="{y(t) + 4:.1f}" text-anchor="end">{compact(t)}</text>')
    time_axis(body, x, start, end, top, top + plot_h)
    body.append(f'<line class="axis" x1="{left}" x2="{width - right}" y1="{y(0):.1f}" y2="{y(0):.1f}"/>')

    for i in range(hours):
        bx, bw, base = left + i * slot + 1, slot - 2, y(0)
        rest_h, bot_h = base - y(rest[i]), base - y(bot[i])
        if rest_h:
            d = column(bx, bw, base, rest_h) if not bot[i] else f"M{bx:.1f},{base:.1f}v{-rest_h:.1f}h{bw:.1f}v{rest_h:.1f}Z"
            body.append(f'<path class="mark" d="{d}"/>')
        if bot_h:
            # 2px of surface between the stacked segments.
            lift = rest_h + 2 if rest_h else 0
            body.append(f'<path class="bot" d="{column(bx, bw, base - lift, bot_h)}"/>')

    legend = (("bot", "The uname bot"), ("mark", "Everything else"))
    lx = left
    for cls, label in legend:
        body.append(f'<rect class="{cls}" x="{lx}" y="10" width="10" height="10" rx="2"/>')
        body.append(f'<text class="ink2" x="{lx + 16}" y="19">{label}</text>')
        lx += 16 + 7.2 * len(label) + 22
    return svg(width, height, "Connections per hour, the uname bot versus everything else", body)


def relay_chart(sessions: list[dict]) -> str:
    """One row per bot IP, one bar per shift: the IPs take turns."""
    by_ip: dict[str, list[dt.datetime]] = collections.defaultdict(list)
    for s in sessions:
        if is_bot(s):
            by_ip[s["ip"]].append(s["start"])
    width, row_h, bar_h = 800, 16, 10
    left, right, top, bottom = 118, 52, 8, 30
    height = top + row_h * len(by_ip) + bottom
    start = sessions[0]["start"].replace(minute=0, second=0, microsecond=0)
    end = sessions[-1]["start"].replace(minute=0, second=0, microsecond=0) + HOUR
    plot_w = width - left - right

    def x(t: dt.datetime) -> float:
        return left + plot_w * (t - start) / (end - start)

    body = []
    time_axis(body, x, start, end, top, height - bottom)
    for row, (ip, times) in enumerate(by_ip.items()):  # insertion order = first seen
        cy = top + row * row_h + row_h / 2
        body.append(f'<text class="ink2 mono" x="{left - 8}" y="{cy + 4:.1f}" text-anchor="end">{ip}</text>')
        for run in shifts(times):
            x0, x1 = x(run[0]), max(x(run[-1]), x(run[0]) + 3)
            body.append(f'<rect class="bot" x="{x0:.1f}" y="{cy - bar_h / 2:.1f}" width="{x1 - x0:.1f}" '
                        f'height="{bar_h}" rx="3"/>')
        body.append(f'<text class="ink" x="{x1 + 6:.1f}" y="{cy + 4:.1f}">{len(times):,}</text>')
    body.append(f'<line class="axis" x1="{left}" x2="{width - right}" y1="{height - bottom}" y2="{height - bottom}"/>')
    return svg(width, height, "When each of the bot's 26 IPs was active", body)


def main(argv: list[str]) -> None:
    if not argv:
        sys.exit(__doc__)
    sessions = load([Path(p) for p in argv], parse_networks(os.environ.get("IGNORE_IPS", "")))
    print(json.dumps(summary(sessions), indent=2, ensure_ascii=False))
    (HERE / "hourly.svg").write_text(hourly_chart(sessions), encoding="utf-8")
    (HERE / "relay.svg").write_text(relay_chart(sessions), encoding="utf-8")


if __name__ == "__main__":
    main(sys.argv[1:])
