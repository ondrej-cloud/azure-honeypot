"""IPv4 -> (country, ASN, AS name) using the public-domain iptoasn.com dataset."""
from __future__ import annotations

import bisect
import gzip
import socket
import struct
import sys
import time
import urllib.request
from functools import lru_cache
from pathlib import Path

DATASET_URL = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"
UNKNOWN = ("??", 0, "Unknown")


def _ip_to_int(ip: str) -> int | None:
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except (OSError, struct.error):
        return None


class GeoDB:
    """Sorted IP ranges with a binary-search lookup. Empty if no dataset is available."""

    def __init__(self, path: Path | None = None) -> None:
        self._starts: list[int] = []
        self._ends: list[int] = []
        self._rows: list[tuple[str, int, str]] = []
        if path is not None and path.exists():
            self._load(path)
        self.lookup = lru_cache(maxsize=None)(self._lookup)

    def __len__(self) -> int:
        return len(self._starts)

    def _load(self, path: Path) -> None:
        names: dict[str, str] = {}
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 5 or parts[2] == "0":   # AS 0 = not routed
                    continue
                start, end = _ip_to_int(parts[0]), _ip_to_int(parts[1])
                if start is None or end is None:
                    continue
                cc = parts[3] if len(parts[3]) == 2 else "??"
                name = names.setdefault(parts[4], parts[4])
                self._starts.append(start)
                self._ends.append(end)
                self._rows.append((cc, int(parts[2]), name))
        if any(a > b for a, b in zip(self._starts, self._starts[1:])):
            order = sorted(range(len(self._starts)), key=self._starts.__getitem__)
            self._starts = [self._starts[i] for i in order]
            self._ends = [self._ends[i] for i in order]
            self._rows = [self._rows[i] for i in order]

    def _lookup(self, ip: str) -> tuple[str, int, str]:
        n = _ip_to_int(ip)
        if n is None:
            return UNKNOWN
        i = bisect.bisect_right(self._starts, n) - 1
        if i >= 0 and n <= self._ends[i]:
            return self._rows[i]
        return UNKNOWN


def load(cache_dir: Path, max_age_days: float = 7) -> GeoDB:
    """Load the dataset from cache_dir, downloading it when missing or stale."""
    path = cache_dir / "ip2asn-v4.tsv.gz"
    stale = not path.exists() or time.time() - path.stat().st_mtime > max_age_days * 86400
    if stale:
        cache_dir.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".part")
        try:
            req = urllib.request.Request(DATASET_URL, headers={"User-Agent": "azure-honeypot-pipeline"})
            with urllib.request.urlopen(req, timeout=60) as resp, tmp.open("wb") as out:
                while chunk := resp.read(1 << 20):
                    out.write(chunk)
            tmp.replace(path)
        except OSError as err:
            tmp.unlink(missing_ok=True)
            print(f"warning: could not download {DATASET_URL}: {err}", file=sys.stderr)
    return GeoDB(path if path.exists() else None)
