"""Look up captured samples on VirusTotal and MalwareBazaar (optional, free API keys).

Only the hash leaves the pipeline, never the file. Both services rate-limit free keys hard
(VirusTotal: 4 requests a minute, 500 a day), so each run checks a few samples, newest and most
interesting first, and remembers when each source was asked so nothing is looked up twice in a
row. Errors keep whatever was known before; the keys are never printed or stored.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable

VT_URL = "https://www.virustotal.com/api/v3/files/"
MB_URL = "https://mb-api.abuse.ch/api/v1/"
VT_SPACING = 15              # seconds between VirusTotal requests (free tier: 4 per minute)
RECHECK_FOUND = dt.timedelta(days=30)
RECHECK_MISSING = dt.timedelta(days=7)
NAME = re.compile(r"^([0-9a-f]{64})\.json$")
# Echo leftovers and empty files are not worth a lookup.
KIND_RANK = {"elf": 0, "script": 1, "archive": 2, "data": 3, "html": 4, "text": 5}
MIN_SIZE = 16


class StopSource(Exception):
    """Rate limit or rejected key: ask this source nothing more in this run."""


class LookupFailed(Exception):
    """A single lookup failed; keep the previous answer and move on."""


def _clean(value: object, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    text = "".join(ch for ch in " ".join(value.split()) if ch.isprintable())[:limit]
    return text or None


def _fetch(req: urllib.request.Request) -> tuple[int, dict | None]:
    """(HTTP status, parsed JSON body); 404 -> (404, None). Rate limits and failures raise."""
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        if err.code == 404:
            return 404, None
        if err.code == 429:
            raise StopSource(f"HTTP {err.code}") from None
        if err.code in (401, 403):
            raise StopSource(f"HTTP {err.code}, check the API key") from None
        raise LookupFailed(f"HTTP {err.code}") from None
    except (urllib.error.URLError, OSError, ValueError) as err:
        raise LookupFailed(type(err).__name__) from None


def virustotal(sha: str, key: str) -> dict | None:
    req = urllib.request.Request(VT_URL + sha, headers={"x-apikey": key, "Accept": "application/json",
                                                        "User-Agent": "azure-honeypot-pipeline"})
    status, body = _fetch(req)
    if status == 404 or not body:
        return None
    attrs = (body.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    counts = [v for v in stats.values() if isinstance(v, int)]
    label = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")
    return {"malicious": int(stats.get("malicious", 0) or 0), "total": sum(counts), "label": _clean(label, 100)}


def malwarebazaar(sha: str, key: str) -> dict | None:
    data = urllib.parse.urlencode({"query": "get_info", "hash": sha}).encode()
    req = urllib.request.Request(MB_URL, data=data, method="POST", headers={
        "Auth-Key": key, "Accept": "application/json", "User-Agent": "azure-honeypot-pipeline"})
    _, body = _fetch(req)
    status = (body or {}).get("query_status")
    if status in ("hash_not_found", "no_results"):
        return None
    if status != "ok" or not body.get("data"):
        if "auth" in str(status):
            raise StopSource(f"status {_clean(status, 40)}, check the API key")
        raise LookupFailed(f"status {_clean(status, 40)}")
    item = body["data"][0] if isinstance(body["data"], list) else {}
    tags = [t for t in (_clean(t, 40) for t in (item.get("tags") or [])[:10]) if t]
    return {"signature": _clean(item.get("signature"), 100), "tags": tags}


def _stamp(t: dt.datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(stamp: object) -> dt.datetime | None:
    try:
        return dt.datetime.strptime(str(stamp), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


def _due(intel: dict, source: str, now: dt.datetime) -> bool:
    checked = _parse((intel.get("sources") or {}).get(source))
    if checked is None:
        return True
    return now - checked >= (RECHECK_FOUND if intel.get(source) else RECHECK_MISSING)


def _write(path: Path, meta: dict) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(meta, indent=1, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(path)


def enrich(malware_dir: Path, *, vt_key: str | None, mb_key: str | None,
           now: dt.datetime | None = None, max_vt: int = 4, max_mb: int = 30,
           sleep: Callable[[float], None] = time.sleep) -> int:
    """Fill the "intel" field of data/malware/*.json; returns how many files changed."""
    now = now or dt.datetime.now(dt.timezone.utc)
    budget = {"vt": max_vt if vt_key else 0, "mb": max_mb if mb_key else 0}
    lookups: dict[str, Callable[[str], dict | None]] = {
        "vt": lambda sha: virustotal(sha, vt_key or ""), "mb": lambda sha: malwarebazaar(sha, mb_key or "")}
    if not any(budget.values()) or not malware_dir.is_dir():
        return 0

    samples = []
    for path in sorted(malware_dir.glob("*.json")):
        m = NAME.match(path.name)
        try:
            meta = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            print(f"intel: skipping unreadable {path.name}", file=sys.stderr)
            continue
        if not m or meta.get("sha256") != m.group(1):
            continue
        size = meta.get("size") if isinstance(meta.get("size"), int) else 0
        if meta.get("kind") not in KIND_RANK or size < MIN_SIZE:
            continue
        samples.append((path, meta))
    # Never-checked samples first, then executables before scripts before the rest, newest first.
    samples.sort(key=lambda s: str(s[1].get("first_seen", "")), reverse=True)
    samples.sort(key=lambda s: (bool((s[1].get("intel") or {}).get("sources")), KIND_RANK[s[1]["kind"]]))

    changed = 0
    last_vt = None
    for path, meta in samples:
        if not any(budget.values()):
            break
        sha = meta["sha256"]
        intel = dict(meta.get("intel") or {"vt": None, "mb": None})
        intel.setdefault("vt", None)
        intel.setdefault("mb", None)
        sources = dict(intel.get("sources") or {})
        updated = False
        for source in ("vt", "mb"):
            if budget[source] <= 0 or not _due({**intel, "sources": sources}, source, now):
                continue
            if source == "vt" and last_vt is not None:
                sleep(VT_SPACING)
            budget[source] -= 1
            try:
                result = lookups[source](sha)
            except StopSource as err:
                budget[source] = 0
                print(f"intel: {source} stopped for this run ({err})", file=sys.stderr)
                continue
            except LookupFailed as err:
                print(f"intel: {source} lookup of {sha[:12]} failed ({err}), keeping what we had", file=sys.stderr)
                continue
            finally:
                if source == "vt":
                    last_vt = True
            intel[source] = result
            sources[source] = _stamp(now)
            updated = True
        if updated:
            intel["sources"] = sources
            intel["checked_at"] = _stamp(now)
            meta["intel"] = intel
            _write(path, meta)
            changed += 1
    return changed


def keys_from_env() -> tuple[str | None, str | None]:
    return os.environ.get("VIRUSTOTAL_API_KEY") or None, os.environ.get("MALWAREBAZAAR_AUTH_KEY") or None
