"""Static SVG charts and the auto-updated stats section of README.md.

Everything shown here is attacker-controlled text (passwords, commands), so it
is escaped for its destination: XML for SVG, inline code for Markdown.
"""
from __future__ import annotations

import datetime as dt
import json
import math
import re
from pathlib import Path
from xml.sax.saxutils import escape

from .attack import technique_url

COUNTRY_NAMES: dict[str, str] = json.loads(
    (Path(__file__).with_name("countries.json")).read_text(encoding="utf-8"))

START, END = "<!-- STATS:START -->", "<!-- STATS:END -->"

# Reference data-viz palette: slot-1 blue, ink and hairlines, each stepped for
# light and dark. Surface ring colors match GitHub's page backgrounds.
STYLE = """
text{font-family:system-ui,-apple-system,"Segoe UI",Helvetica,Arial,sans-serif;font-size:12px}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:11.5px}
.ink{fill:#0b0b0b}.ink2{fill:#52514e}.muted{fill:#898781}
.grid{stroke:#e1e0d9}.axis{stroke:#c3c2b7}
.mark{fill:#2a78d6}.line{stroke:#2a78d6;fill:none}.area{fill:#2a78d6;fill-opacity:.1}
.ring{stroke:#ffffff}
@media (prefers-color-scheme:dark){
.ink{fill:#f0efec}.ink2{fill:#c3c2b7}.grid{stroke:#2c2c2a}.axis{stroke:#383835}
.mark{fill:#3987e5}.line{stroke:#3987e5}.area{fill:#3987e5}.ring{stroke:#0d1117}}
"""


# ------------------------------------------------------------------ helpers

def printable(value: str) -> str:
    """Replace control and non-XML characters with visible escapes like \\x1b."""
    out = []
    for ch in value:
        o = ord(ch)
        if o < 0x20 or 0x7F <= o < 0xA0 or 0xD800 <= o <= 0xDFFF or o in (0xFFFE, 0xFFFF):
            out.append(f"\\x{o:02x}" if o < 0x100 else f"\\u{o:04x}")
        else:
            out.append(ch)
    return "".join(out)


def truncate(value: str, limit: int) -> str:
    value = printable(value)
    return value if len(value) <= limit else value[: limit - 1] + "…"


def compact(n: float) -> str:
    """1284 -> 1.3K, 12900000 -> 12.9M (for chart labels)."""
    for unit, size in (("B", 1e9), ("M", 1e6), ("K", 1e3)):
        if abs(n) >= size:
            text = f"{n / size:.1f}".rstrip("0").rstrip(".")
            return f"{text}{unit}"
    return f"{int(n)}"


def nice_ticks(maximum: float, count: int = 4) -> list[float]:
    if maximum <= 0:
        return [0, 1]
    raw = maximum / count
    mag = 10 ** math.floor(math.log10(raw))
    step = next(m * mag for m in (1, 2, 2.5, 5, 10) if m * mag >= raw)
    return [i * step for i in range(int(math.ceil(maximum / step)) + 1)]


def country_name(cc: str) -> str:
    return COUNTRY_NAMES.get(cc, "Unknown" if cc == "??" else cc)


def svg(width: int, height: int, title: str, body: list[str]) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="{width}" height="{height}" role="img">'
        f"<title>{escape(title)}</title><style>{STYLE}</style>{''.join(body)}</svg>\n"
    )


def bar_path(x0: float, y: float, x1: float, h: float, r: float = 4) -> str:
    """Horizontal bar, square at the baseline, rounded at the data end."""
    r = min(r, (x1 - x0), h / 2)
    if r <= 0:
        return f"M{x0:.1f},{y:.1f}H{x1:.1f}V{y + h:.1f}H{x0:.1f}Z"
    return (f"M{x0:.1f},{y:.1f}H{x1 - r:.1f}A{r},{r} 0 0 1 {x1:.1f},{y + r:.1f}"
            f"V{y + h - r:.1f}A{r},{r} 0 0 1 {x1 - r:.1f},{y + h:.1f}H{x0:.1f}Z")


# ------------------------------------------------------------------ charts

def area_chart(points: list[tuple[str, int]], title: str) -> str:
    """Daily series as a 2px line over a 10% wash, with the last value labelled."""
    width, height = 800, 240
    left, right, top, bottom = 44, 64, 16, 28
    plot_w, plot_h = width - left - right, height - top - bottom
    values = [v for _, v in points] or [0]
    ticks = nice_ticks(max(values))
    y_max = ticks[-1]

    def x(i: int) -> float:
        return left + (plot_w * i / (len(points) - 1) if len(points) > 1 else plot_w / 2)

    def y(v: float) -> float:
        return top + plot_h - plot_h * v / y_max

    body = []
    for t in ticks:
        body.append(f'<line class="grid" x1="{left}" x2="{width - right}" y1="{y(t):.1f}" y2="{y(t):.1f}"/>')
        body.append(f'<text class="muted" x="{left - 8}" y="{y(t) + 4:.1f}" text-anchor="end">{compact(t)}</text>')
    body.append(f'<line class="axis" x1="{left}" x2="{width - right}" y1="{y(0):.1f}" y2="{y(0):.1f}"/>')

    step = max(1, math.ceil(len(points) / 6))
    for i in range(0, len(points), step):
        day = dt.date.fromisoformat(points[i][0])
        label = f"{day:%b} {day.day}"
        body.append(f'<text class="muted" x="{x(i):.1f}" y="{height - 8}" text-anchor="middle">{label}</text>')

    if points:
        line = " ".join(f"{x(i):.1f},{y(v):.1f}" for i, (_, v) in enumerate(points))
        area = f"M{x(0):.1f},{y(0):.1f} L{line} L{x(len(points) - 1):.1f},{y(0):.1f}Z"
        body.append(f'<path class="area" d="{area}"/>')
        body.append(f'<polyline class="line" points="{line}" stroke-width="2" '
                    f'stroke-linejoin="round" stroke-linecap="round"/>')
        last_x, last_y = x(len(points) - 1), y(values[-1])
        body.append(f'<circle class="mark ring" cx="{last_x:.1f}" cy="{last_y:.1f}" r="4" stroke-width="2"/>')
        body.append(f'<text class="ink" x="{last_x + 10:.1f}" y="{last_y + 4:.1f}" '
                    f'font-weight="600">{compact(values[-1])}</text>')
    return svg(width, height, title, body)


def bar_chart(rows: list[tuple[str, int]], title: str, mono: bool = False) -> str:
    """Horizontal bars with the label on the left and the value at the tip."""
    width, row_h, bar_h = 400, 26, 12
    label_w, value_w = 140, 46
    height = max(1, len(rows)) * row_h + 4
    x0, x_max = label_w + 8, width - value_w
    peak = max((v for _, v in rows), default=0) or 1
    body = [f'<line class="axis" x1="{x0}" x2="{x0}" y1="0" y2="{height}"/>']
    for i, (label, value) in enumerate(rows):
        cy = i * row_h + row_h / 2 + 2
        text = escape(truncate(label, 19 if mono else 22)) or "(empty)"
        cls = "ink2 mono" if mono else "ink2"
        body.append(f'<text class="{cls}" x="{label_w}" y="{cy + 4:.1f}" text-anchor="end">{text}</text>')
        x1 = x0 + max(2.0, (x_max - x0) * value / peak)
        body.append(f'<path class="mark" d="{bar_path(x0, cy - bar_h / 2, x1, bar_h)}"/>')
        body.append(f'<text class="ink" x="{x1 + 6:.1f}" y="{cy + 4:.1f}">{compact(value)}</text>')
    return svg(width, height, title, body)


# ------------------------------------------------------------------ README

def md_code(value: str, limit: int = 70) -> str:
    """Attacker text as a GitHub-safe inline code span inside a table cell."""
    if value == "":
        return "*(empty)*"
    text = truncate(" ".join(value.split()), limit).replace("|", "\\|")
    fence = "`" * (max((len(m) for m in re.findall(r"`+", text)), default=0) + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def readme_block(stats: dict, charts_rel: str) -> str:
    window = stats["windows"].get("all")
    if not window:
        return ("_No data yet: the sensor is warming up. This section refreshes "
                "automatically every 6 hours once attacks start arriving._")
    t = window["totals"]
    updated = stats["generated_at"].replace("T", " ").replace("Z", " UTC")
    sensor = stats["sensor"]
    lines = [
        f"> **{t['sessions']:,}** connections · **{t['unique_ips']:,}** unique IPs · "
        f"**{t['login_attempts']:,}** login attempts · **{t['commands']:,}** commands · "
        f"**{t['countries']}** countries",
        f"> <sub>Since {sensor['first_day']} · updated {updated} · sensor `{sensor['name']}`</sub>",
        "",
        f'<img src="{charts_rel}/activity.svg" alt="Connections per day, last 30 days" width="100%">',
        "",
        "<table><tr>",
        f'<td width="50%"><b>Top countries</b> · connections<br><br>'
        f'<img src="{charts_rel}/countries.svg" alt="Top attacking countries" width="100%"></td>',
        f'<td width="50%"><b>Top passwords tried</b> · attempts<br><br>'
        f'<img src="{charts_rel}/passwords.svg" alt="Most tried passwords" width="100%"></td>',
        "</tr></table>",
        "",
    ]
    if window["commands"]:
        lines += ["| Most common commands | Runs |", "|---|---:|"]
        lines += [f"| {md_code(cmd)} | {n:,} |" for cmd, n in window["commands"][:8]]
        lines.append("")
    if window["techniques"]:
        lines += ["| MITRE ATT&CK technique | Tactic | Sessions |", "|---|---|---:|"]
        for row in sorted(window["techniques"], key=lambda r: -r["sessions"])[:8]:
            lines.append(f"| [{row['id']}]({technique_url(row['id'])}) {row['name']} "
                         f"| {row['tactic']} | {row['sessions']:,} |")
    return "\n".join(lines)


def write_charts(stats: dict, charts_dir: Path) -> None:
    charts_dir.mkdir(parents=True, exist_ok=True)
    if not stats["windows"]:
        return
    month, total = stats["windows"]["30d"], stats["windows"]["all"]
    (charts_dir / "activity.svg").write_text(area_chart(
        [(d["date"], d["sessions"]) for d in month["daily"]], "Connections per day, last 30 days"))
    (charts_dir / "countries.svg").write_text(bar_chart(
        [(country_name(c["cc"]), c["sessions"]) for c in total["countries"][:10]], "Top attacking countries"))
    (charts_dir / "passwords.svg").write_text(bar_chart(
        [(p, n) for p, n in total["passwords"][:10]], "Most tried passwords", mono=True))


def update_readme(readme: Path, block: str) -> bool:
    text = readme.read_text(encoding="utf-8")
    start, end = text.find(START), text.find(END)
    if start < 0 or end < start:
        return False
    new = text[: start + len(START)] + "\n" + block + "\n" + text[end:]
    if new != text:
        readme.write_text(new, encoding="utf-8")
    return True
