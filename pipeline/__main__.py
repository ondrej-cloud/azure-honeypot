"""Honeypot data pipeline.

    python -m pipeline fetch --account <storage-account>   pull new log blobs -> data/daily/
    python -m pipeline ingest cowrie.json.2026-10-12 ...   summarize local Cowrie logs
    python -m pipeline build                               data/daily/ -> stats.json, charts, README
    python -m pipeline demo                                synthetic data -> docs/data/stats.demo.json
"""
from __future__ import annotations

import argparse
import gzip
import io
import json
import os
import re
import sys
from pathlib import Path
from typing import Iterable

from . import demo, fetch, geo, render, stats
from .cowrie import parse_networks, summarize

ROOT = Path(__file__).resolve().parent.parent
DAILY = ROOT / "data" / "daily"
STATE = ROOT / "data" / "state.json"
CACHE = ROOT / ".cache"
DATE_IN_NAME = re.compile(r"(\d{4}-\d{2}-\d{2})")


def _ignored_networks() -> tuple:
    """The operator's own addresses (IGNORE_IPS), kept out of everything published."""
    try:
        return parse_networks(os.environ.get("IGNORE_IPS", ""))
    except ValueError as e:
        sys.exit(str(e))


def _lines(path: Path) -> Iterable[bytes]:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rb") as f:
        yield from f


def _write_day(daily_dir: Path, summary: dict) -> None:
    daily_dir.mkdir(parents=True, exist_ok=True)
    out = daily_dir / f"{summary['date']}.json"
    out.write_text(json.dumps(summary, separators=(",", ":"), ensure_ascii=False) + "\n", encoding="utf-8")
    t = summary["totals"]
    print(f"{summary['date']}: {t['sessions']:,} sessions, {summary['unique_ips']:,} IPs, "
          f"{t['login_attempts']:,} logins, {t['commands']:,} commands")


def cmd_ingest(args: argparse.Namespace) -> None:
    ignore = _ignored_networks()
    for path in map(Path, args.files):
        m = DATE_IN_NAME.search(path.name)
        if not (m or args.date):
            sys.exit(f"{path}: no YYYY-MM-DD in the file name, pass --date")
        _write_day(args.data, summarize(_lines(path), args.date or m.group(1), ignore))


def cmd_fetch(args: argparse.Namespace) -> None:
    ignore = _ignored_networks()
    state = json.loads(STATE.read_text()) if STATE.exists() else {}
    container = fetch.BlobContainer(args.account, args.container, fetch.access_token())
    for blob in container.list("cowrie/"):
        m = re.fullmatch(r"cowrie/(\d{4}-\d{2}-\d{2})\.json\.gz", blob["name"])
        if not m or state.get(blob["name"]) == blob["etag"]:
            continue
        raw = io.BytesIO(container.download(blob["name"]))
        with gzip.GzipFile(fileobj=raw) as lines:
            _write_day(args.data, summarize(lines, m.group(1), ignore))
        state[blob["name"]] = blob["etag"]
        STATE.write_text(json.dumps(state, indent=1, sort_keys=True) + "\n")


def _build(daily_dir: Path, stats_path: Path, charts_dir: Path, readme: Path | None, demo_mode: bool) -> dict:
    data = stats.build(stats.load_days(daily_dir), geo.load(CACHE), demo=demo_mode)
    stats_path.parent.mkdir(parents=True, exist_ok=True)
    stats_path.write_text(json.dumps(data, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
    render.write_charts(data, charts_dir)
    if readme is not None and not render.update_readme(
            readme, render.readme_block(data, charts_dir.relative_to(ROOT).as_posix())):
        print(f"warning: no {render.START} marker in {readme}", file=sys.stderr)
    print(f"wrote {stats_path.relative_to(ROOT)} ({stats_path.stat().st_size / 1024:.0f} KiB)")
    return data


def cmd_build(args: argparse.Namespace) -> None:
    _build(args.data, ROOT / "docs" / "data" / "stats.json", ROOT / "docs" / "charts",
           ROOT / "README.md", demo_mode=False)


def cmd_demo(args: argparse.Namespace) -> None:
    work = ROOT / "build" / "demo"
    for old in (work / "daily").glob("*.json"):
        old.unlink()
    for path in demo.generate(work / "raw", days=args.days, seed=args.seed):
        _write_day(work / "daily", summarize(_lines(path), DATE_IN_NAME.search(path.name).group(1)))
    _build(work / "daily", ROOT / "docs" / "data" / "stats.demo.json", work / "charts", None, demo_mode=True)
    print("preview: make serve, then open http://localhost:8000/?demo")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m pipeline", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("fetch", help="download new log blobs from Azure Storage")
    p.add_argument("--account", required=True)
    p.add_argument("--container", default="logs")
    p.add_argument("--data", type=Path, default=DAILY)
    p.set_defaults(func=cmd_fetch)

    p = sub.add_parser("ingest", help="summarize local Cowrie JSON logs")
    p.add_argument("files", nargs="+")
    p.add_argument("--date", help="UTC day the file covers (default: from the file name)")
    p.add_argument("--data", type=Path, default=DAILY)
    p.set_defaults(func=cmd_ingest)

    p = sub.add_parser("build", help="build stats.json, README charts and the README stats block")
    p.add_argument("--data", type=Path, default=DAILY)
    p.set_defaults(func=cmd_build)

    p = sub.add_parser("demo", help="build a dashboard preview from synthetic logs")
    p.add_argument("--days", type=int, default=45)
    p.add_argument("--seed", type=int, default=7)
    p.set_defaults(func=cmd_demo)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
