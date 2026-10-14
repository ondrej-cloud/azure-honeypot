#!/usr/bin/env python3
"""Ship Cowrie's logs, session recordings and malware metadata to Azure Blob Storage.

Runs hourly from a systemd timer. It authenticates with the VM's managed
identity through the Azure Instance Metadata Service, so no key, SAS token or
password is ever stored on the box. It uploads:

  cowrie/YYYY-MM-DD.json.gz   each UTC day's JSON log, re-uploaded while it grows
  tty/<sha256>                each finished session recording, once
  malware/<sha256>.json       header metadata of each captured file, once

Captured files are only parsed (ELF headers, script text), never executed, and
never leave the VM. Local logs are pruned only once they are safely uploaded.

Standard library only: it runs on the stock python3 of Ubuntu 24.04.
"""
from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import json
import os
import re
import shutil
import struct
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, Union

VOLUME = Path(os.environ.get("COWRIE_VAR", "/var/lib/docker/volumes/cowrie-var/_data"))
LOG_DIR = VOLUME / "log" / "cowrie"
TTY_DIR = VOLUME / "lib" / "cowrie" / "tty"
DOWNLOAD_DIR = VOLUME / "lib" / "cowrie" / "downloads"
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
# Cowrie renames recordings and downloads to their SHA-256 once they are complete;
# anything else in those directories is still being written.
FINISHED_NAME = re.compile(r"^[0-9a-f]{64}$")
SETTLE_SECONDS = 60

Source = Union[Path, bytes]


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
        else:
            m = ROTATED.match(path.name)
            if m:
                files.append((path, dt.date(*map(int, m.groups()))))
    return files


def finished_files(directory: Path) -> list[Path]:
    """Complete, settled recordings or downloads (SHA-256 names, untouched for a minute)."""
    if not directory.is_dir():
        return []
    cutoff = time.time() - SETTLE_SECONDS
    return [p for p in sorted(directory.iterdir())
            if FINISHED_NAME.match(p.name) and p.is_file() and p.stat().st_mtime <= cutoff]


def imds_token() -> str:
    req = urllib.request.Request(IMDS_TOKEN_URL, headers={"Metadata": "true"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.load(resp)["access_token"]


class Auth:
    """Fetches the managed-identity token on first use and reuses it for the run."""

    def __init__(self) -> None:
        self._token = ""

    def token(self) -> str:
        if not self._token and not DRY_RUN_DIR:
            self._token = imds_token()
        return self._token


def put_blob(name: str, source: Source, token: str, content_type: str) -> None:
    if DRY_RUN_DIR:
        target = Path(DRY_RUN_DIR) / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(source, bytes):
            target.write_bytes(source)
        else:
            shutil.copyfile(source, target)
        return
    url = f"https://{ACCOUNT}.blob.core.windows.net/{CONTAINER}/{name}"
    size = len(source) if isinstance(source, bytes) else source.stat().st_size
    for attempt in range(1, 4):
        try:
            body = source if isinstance(source, bytes) else source.open("rb")
            try:
                req = urllib.request.Request(url, data=body, method="PUT", headers={
                    "Authorization": f"Bearer {token}",
                    "x-ms-version": "2023-11-03",
                    "x-ms-blob-type": "BlockBlob",
                    "x-ms-blob-content-type": content_type,
                    "Content-Length": str(size),
                })
                with urllib.request.urlopen(req, timeout=120):
                    return
            finally:
                if not isinstance(body, bytes):
                    body.close()
        except urllib.error.HTTPError as err:
            if err.code < 500 or attempt == 3:
                raise RuntimeError(f"upload of {name} failed: HTTP {err.code} {err.read()[:300]!r}") from err
        except urllib.error.URLError:
            if attempt == 3:
                raise
        time.sleep(5 * attempt)


def load_state() -> dict:
    try:
        state = json.loads((STATE_DIR / "state.json").read_text())
    except (FileNotFoundError, ValueError):
        return {}
    return state if isinstance(state, dict) else {}


def save_state(state: dict) -> None:
    tmp = STATE_DIR / "state.json.tmp"
    tmp.write_text(json.dumps(state, indent=1, sort_keys=True))
    tmp.replace(STATE_DIR / "state.json")


def shipped(state: dict, key: str) -> set[str]:
    return set(state.get(key) or [])


def mark_shipped(state: dict, key: str, name: str) -> None:
    state[key] = sorted(shipped(state, key) | {name})
    save_state(state)


# ------------------------------------------------------------------ malware metadata

MAX_READ = 32 << 20        # never pull more of a sample than this into memory
HINT_WINDOW = 1 << 20      # keyword hints come from the first 1 MiB

ELF_MACHINES = {
    2: "SPARC", 3: "x86", 4: "m68k", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64", 22: "S390", 40: "ARM",
    42: "SuperH", 43: "SPARC64", 62: "x86-64", 93: "ARC", 183: "AArch64", 195: "ARCv2", 243: "RISC-V",
    258: "LoongArch",
}
ELF_TYPES = {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
PT_INTERP, SHT_SYMTAB = 3, 2

ARCHIVE_MAGIC = (b"\x1f\x8b", b"PK\x03\x04", b"BZh", b"\xfd7zXZ\x00", b"7z\xbc\xaf\x27\x1c", b"Rar!")
HINTS = {
    b"busybox": "busybox", b"mirai": "mirai", b"gafgyt": "gafgyt", b"bashlite": "bashlite",
    # Mozi by its binary names: a bare "mozi" also matches the Mozilla user agents in HTTP-flood bots.
    b"tsunami": "tsunami", b"kaiten": "kaiten", b"mozi.m": "mozi", b"mozi.a": "mozi", b"hajime": "hajime",
    b"xmrig": "xmrig",
    b"stratum+tcp": "stratum", b"monero": "monero", b"redtail": "redtail", b"mdrfckr": "mdrfckr",
    b"authorized_keys": "ssh-keys", b"crontab": "crontab", b"chattr": "chattr", b"iptables": "iptables",
    b"/dev/watchdog": "watchdog",
}
SCRIPT_WORDS = re.compile(rb"\b(?:wget|curl|tftp|ftpget|chmod|busybox|cd /tmp|/bin/sh|bash)\b")
URL = re.compile(r"(?i)\b(?:https?|ftp|tftp)://[^\s'\"<>;|&()`]+")
ARCH = re.compile(
    r"arm(?:v?[4-7]l?|64)?|aarch64|mips(?:el|64)?|mpsl|x86(?:_64)?|x64|i[3-6]86|amd64|ppc(?:64|440)?|"
    r"powerpc|m68k|m68000|sh4|spc|sparc(?:64)?|arc|riscv64|loongarch64")
TOKEN_SPLIT = re.compile(r"[\s;|&'\"`()<>]+")


def _utc(timestamp: float) -> str:
    return dt.datetime.fromtimestamp(timestamp, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_text(head: bytes) -> bool:
    try:
        head.decode("utf-8")
    except UnicodeDecodeError as err:
        if err.start < len(head) - 3:   # invalid in the middle, not just a character cut off at the end
            return False
    controls = sum(b < 32 and b not in b"\t\n\r\f\x1b" for b in head)
    return controls <= 0.02 * len(head)


def _kind(data: bytes) -> str:
    if not data:
        return "empty"
    if data.startswith(b"\x7fELF"):
        return "elf"
    if data.startswith(ARCHIVE_MAGIC) or data[257:262] == b"ustar":
        return "archive"
    head = data[:4096]
    if not _is_text(head):
        return "data"
    lower = head.lstrip().lower()
    if lower.startswith((b"<!doctype html", b"<html")) or b"<html" in lower or b"<body" in lower:
        return "html"
    if data.startswith(b"#!") or SCRIPT_WORDS.search(head):
        return "script"
    return "text"


def parse_elf(data: bytes) -> dict | None:
    """Header facts of an ELF file; None when the identification bytes make no sense."""
    if len(data) < 20 or data[4] not in (1, 2) or data[5] not in (1, 2):
        return None
    bits = 32 if data[4] == 1 else 64
    end = "<" if data[5] == 1 else ">"
    header = end + ("HHIIIIIHHHHHH" if bits == 32 else "HHIQQQIHHHHHH")
    try:
        (e_type, machine, _version, _entry, phoff, shoff, _flags, _ehsize,
         phentsize, phnum, shentsize, shnum, _shstrndx) = struct.unpack_from(header, data, 16)
    except struct.error:
        return {"bits": bits, "endian": "little" if end == "<" else "big", "machine": None,
                "machine_id": None, "type": None, "static": None, "stripped": None, "interp": None}

    interp = None
    phdr = end + ("IIIIIIII" if bits == 32 else "IIQQQQQQ")
    if phentsize >= struct.calcsize(phdr):
        for i in range(min(phnum, 512)):
            try:
                fields = struct.unpack_from(phdr, data, phoff + i * phentsize)
            except struct.error:
                break
            if fields[0] == PT_INTERP:
                offset, size = (fields[1], fields[4]) if bits == 32 else (fields[2], fields[5])
                interp = data[offset:offset + min(size, 256)].split(b"\x00")[0].decode("ascii", "replace")
                break

    stripped = None
    if shoff and shnum and shentsize >= 8 and shoff + shnum * shentsize <= len(data):
        stripped = True
        for i in range(min(shnum, 4096)):
            (sh_type,) = struct.unpack_from(end + "I", data, shoff + i * shentsize + 4)
            if sh_type == SHT_SYMTAB:
                stripped = False
                break

    return {
        "bits": bits,
        "endian": "little" if end == "<" else "big",
        "machine": ELF_MACHINES.get(machine, f"machine {machine}"),
        "machine_id": machine,
        "type": ELF_TYPES.get(e_type, str(e_type)),
        "static": interp is None,
        "stripped": stripped,
        "interp": interp[:200] if interp is not None else None,
    }


def parse_script(data: bytes) -> dict:
    text = data.decode("utf-8", "replace")
    first = text.split("\n", 1)[0]
    urls = list(dict.fromkeys(u[:300] for u in URL.findall(text)))[:50]
    archs = []
    for token in TOKEN_SPLIT.split(text):
        name = token.rstrip("/").rsplit("/", 1)[-1].lower()
        for part in [name] + re.split(r"[.\-]", name):
            if part and ARCH.fullmatch(part) and part not in archs:
                archs.append(part)
                break
    return {
        "shebang": first.strip()[:100] if first.startswith("#!") else None,
        "lines": text.count("\n") + (1 if text and not text.endswith("\n") else 0),
        "urls": urls,
        "archs": archs[:20],
    }


def analyze(path: Path) -> dict:
    """Metadata of one captured file, from its bytes only."""
    stat = path.stat()
    with path.open("rb") as f:
        data = f.read(MAX_READ)
    kind = _kind(data)
    lower = data[:HINT_WINDOW].lower()
    return {
        "v": 1,
        "sha256": sha256_file(path),
        "size": stat.st_size,
        "first_seen": _utc(stat.st_mtime),
        "kind": kind,
        "magic": data[:16].hex(),
        "elf": parse_elf(data) if kind == "elf" else None,
        "packer": "UPX" if b"UPX!" in data else None,
        "script": parse_script(data) if kind == "script" else None,
        "hints": sorted({tag for needle, tag in HINTS.items() if needle in lower}),
        "intel": None,
    }


# ------------------------------------------------------------------ shipping steps

def ship_logs(state: dict, auth: Auth) -> int:
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
            put_blob(blob, tmp_path, auth.token(), "application/gzip")
        finally:
            tmp_path.unlink(missing_ok=True)
        state[path.name] = fingerprint
        save_state(state)
        log(f"uploaded {path.name} -> {blob} ({stat.st_size:,} bytes raw)")
    return 0


def ship_recordings(state: dict, auth: Auth) -> int:
    failures = 0
    done = shipped(state, "tty")
    for path in finished_files(TTY_DIR):
        if path.name in done:
            continue
        try:
            put_blob(f"tty/{path.name}", path, auth.token(), "application/octet-stream")
        except Exception as err:  # one bad upload must not hold back the others
            failures += 1
            log(f"recording {path.name}: {err}")
            continue
        mark_shipped(state, "tty", path.name)
        log(f"uploaded recording {path.name[:16]} ({path.stat().st_size:,} bytes)")
    return failures


def ship_malware(state: dict, auth: Auth) -> int:
    failures = 0
    done = shipped(state, "malware")
    for path in finished_files(DOWNLOAD_DIR):
        if path.name in done:
            continue
        try:
            meta = analyze(path)
            body = json.dumps(meta, separators=(",", ":")).encode()
            put_blob(f"malware/{meta['sha256']}.json", body, auth.token(), "application/json")
        except Exception as err:  # a malformed sample must not hold back the others
            failures += 1
            log(f"sample {path.name}: {err}")
            continue
        mark_shipped(state, "malware", path.name)
        log(f"uploaded metadata of {path.name[:16]} ({meta['kind']}, {meta['size']:,} bytes)")
    return failures


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
    for directory in (TTY_DIR, DOWNLOAD_DIR):
        for path in directory.glob("*"):
            if path.is_file() and not path.name.startswith(".") and path.stat().st_mtime < cutoff:
                path.unlink()
    # Forget shipped artifacts that are gone from disk, so the state does not grow forever.
    for key, directory in (("tty", TTY_DIR), ("malware", DOWNLOAD_DIR)):
        if key in state:
            state[key] = sorted(name for name in shipped(state, key) if (directory / name).is_file())
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
    auth = Auth()
    failures = 0
    steps: list[Callable[[dict, Auth], int]] = [ship_logs, ship_recordings, ship_malware]
    for step in steps:
        try:
            failures += step(state, auth)
        except Exception as err:  # logs first, but each step runs even if another fails
            failures += 1
            log(f"{step.__name__} failed: {err}")
    prune(state)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
