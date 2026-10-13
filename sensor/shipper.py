#!/usr/bin/env python3
"""Ship Cowrie's JSON logs from the honeypot VM to Azure Blob Storage.

Runs hourly from a systemd timer. It authenticates with the VM's managed
identity through the Azure Instance Metadata Service, so no key, SAS token or
password is ever stored on the box. Each UTC day becomes one gzipped blob,
cowrie/YYYY-MM-DD.json.gz, re-uploaded while that day's log keeps growing.
Local files are pruned only once they are safely uploaded.

Standard library only: it runs on the stock python3 of Ubuntu 24.04.
"""
from __future__ import annotations

import datetime as dt
import gzip
import json
import os
import re
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

VOLUME = Path(os.environ.get("COWRIE_VAR", "/var/lib/docker/volumes/cowrie-var/_data"))
LOG_DIR = VOLUME / "log" / "cowrie"
STATE_DIR = Path(os.environ.get("STATE_DIRECTORY", "/var/lib/honeypot-shipper"))
ACCOUNT = os.environ.get("STORAGE_ACCOUNT", "")
CONTAINER = os.environ.get("STORAGE_CONTAINER", "logs")
KEEP_LOG_DAYS = int(os.environ.get("KEEP_LOG_DAYS", "14"))
KEEP_ARTIFACT_DAYS = int(os.environ.get("KEEP_ARTIFACT_DAYS", "30"))
# Write blobs into this local directory instead of Azure (for testing).
DRY_RUN_DIR = os.environ.get("SHIPPER_DRY_RUN_DIR")

IMDS_TOKEN_URL = (
    "http://169.254.169.254/metadata/identity/oauth2/token"
    "?api-version=2018-02-01&resource=https%3A%2F%2Fstorage.azure.com%2F"
)
ROTATED = re.compile(r"^cowrie\.json\.(\d{4})[-_](\d{1,2})[-_](\d{1,2})$")


def log(msg: str) -> None:
    print(msg, flush=True)


def log_files() -> list[tuple[Path, dt.date]]:
    """Every Cowrie JSON log on disk with the UTC day its events belong to."""
    files = []
    for path in sorted(LOG_DIR.glob("cowrie.json*")):
        if path.name == "cowrie.json":
            # The live file is rotated on the first write of a new day, so it
            # always holds events from the day it was last written to.
            mtime = dt.datetime.fromtimestamp(path.stat().st_mtime, dt.timezone.utc)
            files.append((path, mtime.date()))
        elif m := ROTATED.match(path.name):
            files.append((path, dt.date(*map(int, m.groups()))))
    return files


def imds_token() -> str:
    req = urllib.request.Request(IMDS_TOKEN_URL, headers={"Metadata": "true"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.load(resp)["access_token"]


def put_blob(name: str, path: Path, token: str) -> None:
    if DRY_RUN_DIR:
        target = Path(DRY_RUN_DIR) / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        return
    url = f"https://{ACCOUNT}.blob.core.windows.net/{CONTAINER}/{name}"
    size = path.stat().st_size
    for attempt in range(1, 4):
        try:
            with path.open("rb") as body:
                req = urllib.request.Request(url, data=body, method="PUT", headers={
                    "Authorization": f"Bearer {token}",
                    "x-ms-version": "2023-11-03",
                    "x-ms-blob-type": "BlockBlob",
                    "x-ms-blob-content-type": "application/gzip",
                    "Content-Length": str(size),
                })
                with urllib.request.urlopen(req, timeout=120):
                    return
        except urllib.error.HTTPError as err:
            if err.code < 500 or attempt == 3:
                raise RuntimeError(f"upload of {name} failed: HTTP {err.code} {err.read()[:300]!r}") from err
        except urllib.error.URLError:
            if attempt == 3:
                raise
        time.sleep(5 * attempt)


def load_state() -> dict:
    try:
        return json.loads((STATE_DIR / "state.json").read_text())
    except (FileNotFoundError, ValueError):
        return {}


def save_state(state: dict) -> None:
    tmp = STATE_DIR / "state.json.tmp"
    tmp.write_text(json.dumps(state, indent=1, sort_keys=True))
    tmp.replace(STATE_DIR / "state.json")


def ship(state: dict) -> None:
    token = None
    for path, day in log_files():
        stat = path.stat()
        fingerprint = [stat.st_size, stat.st_mtime_ns]
        if state.get(path.name) == fingerprint:
            continue
        blob = f"cowrie/{day.isoformat()}.json.gz"
        with tempfile.NamedTemporaryFile(dir=STATE_DIR, suffix=".gz", delete=False) as tmp:
            tmp_path = Path(tmp.name)
            # Stream-compress so a large day never has to fit in the VM's 1 GiB of RAM.
            with path.open("rb") as src, gzip.GzipFile(fileobj=tmp, mode="wb", mtime=0) as gz:
                shutil.copyfileobj(src, gz, 1 << 20)
        try:
            token = token or ("" if DRY_RUN_DIR else imds_token())
            put_blob(blob, tmp_path, token)
        finally:
            tmp_path.unlink(missing_ok=True)
        state[path.name] = fingerprint
        save_state(state)
        log(f"uploaded {path.name} -> {blob} ({stat.st_size:,} bytes raw)")


def prune(state: dict) -> None:
    today = dt.datetime.now(dt.timezone.utc).date()
    for path, day in log_files():
        uploaded = state.get(path.name, [None])[0] == path.stat().st_size
        if path.name != "cowrie.json" and uploaded and (today - day).days > KEEP_LOG_DAYS:
            path.unlink()
            state.pop(path.name, None)
            log(f"pruned {path.name}")
    # Session recordings and captured malware are kept on the VM only, for a while.
    cutoff = time.time() - KEEP_ARTIFACT_DAYS * 86400
    for sub in ("lib/cowrie/tty", "lib/cowrie/downloads"):
        for path in (VOLUME / sub).glob("*"):
            if path.is_file() and not path.name.startswith(".") and path.stat().st_mtime < cutoff:
                path.unlink()
    save_state(state)


def main() -> int:
    if not ACCOUNT and not DRY_RUN_DIR:
        log("STORAGE_ACCOUNT is not set")
        return 2
    if not LOG_DIR.is_dir():
        log(f"no Cowrie logs yet in {LOG_DIR}")
        return 0
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    state = load_state()
    ship(state)
    prune(state)
    return 0


if __name__ == "__main__":
    sys.exit(main())
