"""Honeypot data pipeline.

    python -m pipeline fetch --account <storage-account>   pull new blobs -> data/daily/, data/malware/, replays
    python -m pipeline ingest cowrie.json.2026-10-12 ...   summarize local Cowrie logs
    python -m pipeline intel                               look samples up on VirusTotal / MalwareBazaar (optional keys)
    python -m pipeline build                               data/ -> stats.json, profiles.json, charts, README
    python -m pipeline report                              data/ -> reports/YYYY-Www.md
    python -m pipeline demo                                synthetic data -> docs/data/demo/
"""
from __future__ import annotations

import argparse
import datetime as dt
import gzip
import importlib
import importlib.util
import io
import json
import os
import re
import sys
from pathlib import Path
from typing import Iterable

from . import demo, fetch, geo, render, replays, stats
from .cowrie import SCHEMA, parse_networks, summarize

ROOT = Path(__file__).resolve().parent.parent
DAILY = ROOT / "data" / "daily"
STATE = ROOT / "data" / "state.json"
MALWARE = ROOT / "data" / "malware"
DOCS_DATA = ROOT / "docs" / "data"
REPLAYS = DOCS_DATA / "replays"
DEMO_DATA = DOCS_DATA / "demo"
REPORTS = ROOT / "reports"
CACHE = ROOT / ".cache"
DATE_IN_NAME = re.compile(r"(\d{4}-\d{2}-\d{2})")
MAX_META_BYTES = 256 * 1024
DEFAULT_SITE = "https://ondrej-cloud.github.io/azure-honeypot/"


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


def _write_json(path: Path, data: object, compact: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = (json.dumps(data, separators=(",", ":"), ensure_ascii=False) if compact
            else json.dumps(data, indent=1, sort_keys=True, ensure_ascii=False) + "\n")
    path.write_text(text, encoding="utf-8")


def _write_day(daily_dir: Path, summary: dict) -> None:
    daily_dir.mkdir(parents=True, exist_ok=True)
    out = daily_dir / f"{summary['date']}.json"
    out.write_text(json.dumps(summary, separators=(",", ":"), ensure_ascii=False) + "\n", encoding="utf-8")
    t = summary["totals"]
    print(f"{summary['date']}: {t['sessions']:,} sessions, {summary['unique_ips']:,} IPs, "
          f"{t['login_attempts']:,} logins, {t['commands']:,} commands")


def _schema_of(path: Path) -> int:
    try:
        return int(json.loads(path.read_text(encoding="utf-8")).get("schema", 0))
    except (OSError, ValueError, AttributeError):
        return 0


def cmd_ingest(args: argparse.Namespace) -> None:
    ignore = _ignored_networks()
    for path in map(Path, args.files):
        m = DATE_IN_NAME.search(path.name)
        if not (m or args.date):
            sys.exit(f"{path}: no YYYY-MM-DD in the file name, pass --date")
        _write_day(args.data, summarize(_lines(path), args.date or m.group(1), ignore))


def fetch_all(container, *, daily_dir: Path, state_path: Path, malware_dir: Path, replay_dir: Path,
              ignore: tuple = ()) -> None:
    """Pull every new or changed blob. `container` behaves like fetch.BlobContainer."""
    state = json.loads(state_path.read_text()) if state_path.exists() else {}

    def save() -> None:
        _write_json(state_path, state, compact=False)

    for blob in container.list("cowrie/"):
        m = re.fullmatch(r"cowrie/(\d{4}-\d{2}-\d{2})\.json\.gz", blob["name"])
        if not m:
            continue
        # A day summarized by an older pipeline version is redone even if its blob is unchanged.
        if state.get(blob["name"]) == blob["etag"] and _schema_of(daily_dir / f"{m.group(1)}.json") >= SCHEMA:
            continue
        raw = io.BytesIO(container.download(blob["name"]))
        with gzip.GzipFile(fileobj=raw) as lines:
            _write_day(daily_dir, summarize(lines, m.group(1), ignore))
        state[blob["name"]] = blob["etag"]
        save()

    added = 0
    for blob in container.list("malware/"):
        m = re.fullmatch(r"malware/([0-9a-f]{64})\.json", blob["name"])
        if not m or state.get(blob["name"]) == blob["etag"] or blob.get("size", 0) > MAX_META_BYTES:
            continue
        try:
            meta = json.loads(container.download(blob["name"]))
        except ValueError:
            continue
        if not isinstance(meta, dict):
            continue
        meta["sha256"] = m.group(1)
        target = malware_dir / f"{m.group(1)}.json"
        if target.exists():
            # The sensor never knows the lookups intel.py made; keep them.
            try:
                old = json.loads(target.read_text(encoding="utf-8"))
            except ValueError:
                old = {}
            if isinstance(old, dict) and old.get("intel") and not meta.get("intel"):
                meta["intel"] = old["intel"]
        _write_json(target, meta, compact=False)
        state[blob["name"]] = blob["etag"]
        added += 1
        save()
    if added:
        print(f"malware: {added} new or updated sample(s)")

    replays.sync(stats.load_days(daily_dir), lambda sha: container.get("tty/" + sha), replay_dir)


def cmd_fetch(args: argparse.Namespace) -> None:
    ignore = _ignored_networks()
    container = fetch.BlobContainer(args.account, args.container, fetch.access_token())
    fetch_all(container, daily_dir=args.data, state_path=STATE, malware_dir=MALWARE, replay_dir=REPLAYS,
              ignore=ignore)


def publish(days: list[dict], malware: dict[str, dict], out_dir: Path, *, replay_dir: Path, geo_db: geo.GeoDB,
            charts_dir: Path, readme: Path | None, demo_mode: bool, now: dt.datetime | None = None) -> dict:
    """stats.json + profiles.json into out_dir, unreferenced replays pruned, charts and README refreshed."""
    now = now or dt.datetime.now(dt.timezone.utc)
    keep = replays.existing(replay_dir) & {c["id"] for c in replays.select(days)}
    replays.prune(replay_dir, keep)
    data = stats.build(days, geo_db, now=now, demo=demo_mode, malware=malware, replay_ids=keep)
    profiles = stats.build_profiles(days, geo_db, replay_ids=keep, now=now)
    _write_json(out_dir / "stats.json", data)
    _write_json(out_dir / "profiles.json", profiles)
    render.write_charts(data, charts_dir)
    if readme is not None and not render.update_readme(
            readme, render.readme_block(data, charts_dir.relative_to(ROOT).as_posix())):
        print(f"warning: no {render.START} marker in {readme}", file=sys.stderr)
    for name in ("stats.json", "profiles.json"):
        path = out_dir / name
        shown = path.relative_to(ROOT) if ROOT in path.parents else path
        print(f"wrote {shown} ({path.stat().st_size / 1024:.0f} KiB)")
    print(f"replays: {len(keep)} file(s)")
    return data


def cmd_build(args: argparse.Namespace) -> None:
    publish(stats.load_days(args.data), stats.load_malware(MALWARE), DOCS_DATA, replay_dir=REPLAYS,
            geo_db=geo.load(CACHE), charts_dir=ROOT / "docs" / "charts", readme=ROOT / "README.md",
            demo_mode=False)


def cmd_demo(args: argparse.Namespace) -> None:
    work = ROOT / "build" / "demo"
    for old in (work / "daily").glob("*.json"):
        old.unlink()
    raw = work / "raw"
    for path in demo.generate(raw, days=args.days, seed=args.seed):
        _write_day(work / "daily", summarize(_lines(path), DATE_IN_NAME.search(path.name).group(1)))
    days = stats.load_days(work / "daily")
    replays.sync(days, replays.local_fetcher(raw / "tty"), DEMO_DATA / "replays", log=lambda _msg: None)
    publish(days, stats.load_malware(raw / "malware"), DEMO_DATA, replay_dir=DEMO_DATA / "replays",
            geo_db=geo.load(CACHE), charts_dir=work / "charts", readme=None, demo_mode=True)
    print("preview: make serve, then open http://localhost:8000/?demo")


def _module(name: str):
    """Optional pipeline modules are imported only when their command runs."""
    if importlib.util.find_spec(f"pipeline.{name}") is None:
        sys.exit(f"pipeline/{name}.py is missing, so `{name}` is not available")
    return importlib.import_module(f"pipeline.{name}")


def site_url() -> str:
    """Dashboard URL for links in reports: SITE_URL, else derived from the GitHub repository."""
    if os.environ.get("SITE_URL"):
        return os.environ["SITE_URL"].rstrip("/") + "/"
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if re.fullmatch(r"[A-Za-z0-9-]+/[A-Za-z0-9._-]+", repo):
        owner, name = repo.split("/")
        return f"https://{owner.lower()}.github.io/{name}/"
    return DEFAULT_SITE


def cmd_report(args: argparse.Namespace) -> None:
    report = _module("report")
    changed = report.write_reports(stats.load_days(args.data), stats.load_malware(MALWARE), geo.load(CACHE),
                                   args.out, site_url=site_url(), now=dt.datetime.now(dt.timezone.utc),
                                   replay_ids=replays.existing(REPLAYS))
    print(f"reports: {len(changed)} file(s) updated")


def cmd_intel(args: argparse.Namespace) -> None:
    intel = _module("intel")
    vt_key, mb_key = intel.keys_from_env()
    if not (vt_key or mb_key):
        print("intel: no VIRUSTOTAL_API_KEY or MALWAREBAZAAR_AUTH_KEY set, skipping")
        return
    if not MALWARE.is_dir():
        print("intel: no malware metadata yet")
        return
    updated = intel.enrich(MALWARE, vt_key=vt_key, mb_key=mb_key, max_vt=args.max_vt)
    print(f"intel: updated {updated} sample(s)")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m pipeline", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("fetch", help="download new blobs from Azure Storage")
    p.add_argument("--account", required=True)
    p.add_argument("--container", default="logs")
    p.add_argument("--data", type=Path, default=DAILY)
    p.set_defaults(func=cmd_fetch)

    p = sub.add_parser("ingest", help="summarize local Cowrie JSON logs")
    p.add_argument("files", nargs="+")
    p.add_argument("--date", help="UTC day the file covers (default: from the file name)")
    p.add_argument("--data", type=Path, default=DAILY)
    p.set_defaults(func=cmd_ingest)

    p = sub.add_parser("intel", help="look captured samples up on VirusTotal / MalwareBazaar")
    # The free VirusTotal API allows 4 lookups a minute and 500 a day; 16 per run (every 6 h) stays far below.
    p.add_argument("--max-vt", type=int, default=16, help="VirusTotal lookups per run (default: 16)")
    p.set_defaults(func=cmd_intel)

    p = sub.add_parser("build", help="build stats.json, profiles.json, README charts and the README stats block")
    p.add_argument("--data", type=Path, default=DAILY)
    p.set_defaults(func=cmd_build)

    p = sub.add_parser("report", help="write the weekly Markdown reports")
    p.add_argument("--data", type=Path, default=DAILY)
    p.add_argument("--out", type=Path, default=REPORTS)
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("demo", help="build a dashboard preview from synthetic logs")
    p.add_argument("--days", type=int, default=45)
    p.add_argument("--seed", type=int, default=7)
    p.set_defaults(func=cmd_demo)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
