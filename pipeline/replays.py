"""Choose which recorded sessions the dashboard can replay, and keep those files in sync.

Daily summaries list replay candidates. From the last 30 days this keeps the
best session per campaign (most commands, then the latest), plus the sessions
behind each window's records, and turns their raw recordings into
docs/data/replays/<id>.json. Files nothing points at any more are deleted, so
the published set stays small.
"""
from __future__ import annotations

import datetime as dt
import json
import re
from pathlib import Path
from typing import Callable, Optional

from . import tty
from .stats import merge_records, window_ranges

MAX_FILES = 60
RECENT_DAYS = 30
SHA256 = re.compile(r"^[0-9a-f]{64}$")
REPLAY_ID = re.compile(r"^[0-9a-f]{16}$")


def select(days: list[dict], max_files: int = MAX_FILES) -> list[dict]:
    """Candidates to publish, record holders first; each gains an "id"."""
    if not days:
        return []
    by_session: dict[str, dict] = {}
    for day in days:
        for c in day.get("replays", []):
            if SHA256.match(str(c.get("sha", ""))):
                by_session.setdefault(c["session"], c)

    chosen: list[dict] = []
    seen: set[str] = set()

    def take(candidate: dict | None) -> None:
        # Deduplicated by id, the published file name, not just by full hash.
        if candidate and candidate["sha"][:16] not in seen and len(chosen) < max_files:
            seen.add(candidate["sha"][:16])
            chosen.append({**candidate, "id": candidate["sha"][:16]})

    for _key, _label, start, end in window_ranges(days):
        window = [d for d in days if start.isoformat() <= d["date"] <= end.isoformat()]
        records = merge_records(window)
        for key in ("longest_session", "most_commands"):
            if records[key]:
                take(by_session.get(records[key]["session"]))

    cutoff = (dt.date.fromisoformat(days[-1]["date"]) - dt.timedelta(days=RECENT_DAYS - 1)).isoformat()
    best: dict[str, dict] = {}
    weight: dict[str, int] = {}
    for day in days:
        if day["date"] < cutoff:
            continue
        for cid, camp in day.get("campaigns", {}).items():
            weight[cid] = weight.get(cid, 0) + camp.get("sessions", 0)
        for c in day.get("replays", []):
            cid = c.get("campaign")
            if cid and SHA256.match(str(c.get("sha", ""))):
                if cid not in best or (c["commands"], c["ts"]) > (best[cid]["commands"], best[cid]["ts"]):
                    best[cid] = c
    for cid in sorted(best, key=lambda cid: (-weight.get(cid, 0), cid)):
        take(best[cid])
    return chosen


def existing(out_dir: Path) -> set[str]:
    return {p.stem for p in out_dir.glob("*.json") if REPLAY_ID.match(p.stem)} if out_dir.is_dir() else set()


def sync(days: list[dict], fetch: Callable[[str], Optional[bytes]], out_dir: Path,
         log: Optional[Callable[[str], None]] = None) -> list[str]:
    """Write the missing selected replays; fetch(sha) returns the raw recording or None."""
    log = log or print
    have = existing(out_dir)
    written = []
    for candidate in select(days):
        if candidate["id"] in have:
            continue
        data = fetch(candidate["sha"])
        if data is None:
            log(f"replay {candidate['id']}: recording not available yet")
            continue
        out_dir.mkdir(parents=True, exist_ok=True)
        replay = tty.to_replay(data, candidate)
        (out_dir / f"{candidate['id']}.json").write_text(
            json.dumps(replay, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
        written.append(candidate["id"])
    if written:
        log(f"wrote {len(written)} replay(s)")
    return written


def prune(out_dir: Path, keep: set[str]) -> int:
    """Delete replay files outside `keep`; returns how many went."""
    removed = 0
    for rid in existing(out_dir) - keep:
        (out_dir / f"{rid}.json").unlink()
        removed += 1
    return removed


def local_fetcher(tty_dir: Path) -> Callable[[str], Optional[bytes]]:
    """fetch() for recordings in a local directory (demo data, tests)."""
    def fetch(sha: str) -> Optional[bytes]:
        path = tty_dir / sha
        return path.read_bytes() if SHA256.match(sha) and path.is_file() else None
    return fetch
