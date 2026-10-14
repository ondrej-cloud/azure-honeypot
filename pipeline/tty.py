"""Cowrie TTY recordings -> replay files the dashboard's terminal player plays back.

A recording (cowrie.core.ttylog) is a series of records with a 24-byte header
"<iLiiLL" = op, tty, length, direction, seconds, microseconds; OP_WRITE records
carry `length` bytes of data. Direction 2 is what the attacker saw (including
the echo of what they typed), 3 is an SSH exec command, 1 is raw input, which
the echo already shows.

The output is attacker-controlled terminal data, so it is cleaned before it is
published: control characters other than the few the player understands are
dropped, binary dumps are summarized, URLs are defanged across chunk
boundaries and the size is capped.
"""
from __future__ import annotations

import codecs
import datetime as dt
import re
import struct
from typing import Iterable

OP_OPEN, OP_CLOSE, OP_WRITE = 1, 2, 3
DIR_INPUT, DIR_OUTPUT, DIR_INTERACT = 1, 2, 3
HEADER = struct.Struct("<iLiiLL")

MERGE_GAP = 0.005          # seconds; output chunks closer than this become one frame
MAX_TEXT = 64 * 1024       # characters of output kept per replay
MAX_FRAMES = 5000
BINARY_RUN = 16            # this many non-printable characters read as a binary dump
BINARY_GAP = 4             # printable runs shorter than this don't end a binary dump
TRUNCATED = "\r\n[recording truncated]\r\n"
KEEP_CONTROLS = {"\n", "\r", "\b", "\t", "\x1b"}

_STRING_INTRO = "]P^_X"
_STRING_END = re.compile(r"\x07|\x1b\\")
MAX_STRING_SEQ = 512
_URL = re.compile(r"\b((?:https?|s?ftp|tftp)://)([^\s/'\"<>()\\]+)", re.IGNORECASE)


def parse(data: bytes) -> tuple[float | None, list[tuple[float, int, bytes]]]:
    """(start time, [(time, direction, data)]) for a recording; a cut-off tail is ignored."""
    start, writes, off = None, [], 0
    while off + HEADER.size <= len(data):
        op, _tty, length, direction, sec, usec = HEADER.unpack_from(data, off)
        off += HEADER.size
        t = sec + usec / 1e6
        if start is None:
            start = t
        if op == OP_WRITE:
            if length < 0 or off + length > len(data):
                break
            writes.append((t, direction, data[off:off + length]))
            off += length
    return start, writes


def encode(records: Iterable[tuple[int, int, float, bytes]]) -> bytes:
    """Inverse of parse, for tests and demo data: [(op, direction, time, data)]."""
    out = bytearray()
    for op, direction, t, payload in records:
        sec = int(t)
        out += HEADER.pack(op, 0, len(payload) if op == OP_WRITE else 0, direction, sec, int(round((t - sec) * 1e6)))
        if op == OP_WRITE:
            out += payload
    return bytes(out)


def _printable(ch: str) -> bool:
    o = ord(ch)
    return not (o < 0x20 or 0x7F <= o < 0xA0 or ch == "�") or ch in KEEP_CONTROLS


def _clean(text: str, owners: list[int]) -> tuple[list[str], list[int]]:
    """Drop stray control characters and replace binary dumps with a marker.

    `owners[i]` is the chunk index of text[i]; the result keeps that mapping
    (a marker belongs to the chunk where its dump started)."""
    out: list[str] = []
    out_owner: list[int] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "\x1b" and i + 1 < n and text[i + 1] in _STRING_INTRO:
            # OSC/DCS/APC/PM/SOS strings (window titles and the like) are dropped whole.
            m = _STRING_END.search(text, i + 2, min(n, i + 2 + MAX_STRING_SEQ))
            i = m.end() if m else i + 2
            continue
        if _printable(ch):
            out.append(ch)
            out_owner.append(owners[i])
            i += 1
            continue
        # A run of non-printables, absorbing short printable islands inside it.
        start, j, bad, last_bad = i, i, 0, i
        while j < n:
            if _printable(text[j]):
                k = j
                while k < n and _printable(text[k]) and k - j < BINARY_GAP:
                    k += 1
                if k - j >= BINARY_GAP or k == n:
                    break
                j = k
            else:
                bad += 1
                last_bad = j
                j += 1
        end = last_bad + 1
        if bad >= BINARY_RUN:
            marker = f"[binary output, {end - start} bytes]"
            out.extend(marker)
            out_owner.extend([owners[start]] * len(marker))
        else:
            for p in range(start, end):
                if _printable(text[p]):
                    out.append(text[p])
                    out_owner.append(owners[p])
        i = end
    return out, out_owner


def _defang(chars: list[str]) -> list[str]:
    """Defang URLs found in the joined text by rewriting single characters, so
    chunk boundaries (a URL typed character by character) don't matter."""
    text = "".join(chars)
    for m in _URL.finditer(text):
        s0, s1 = m.span(1)
        for p in range(s0, s1 - 3):                # the scheme, without "://"
            if chars[p] in "tT":
                chars[p] = "x" if chars[p] == "t" else "X"
        h0, h1 = m.span(2)
        for p in range(h0, h1):
            if chars[p] == ".":
                chars[p] = "[.]"
    return chars


def to_replay(data: bytes, meta: dict) -> dict:
    """Replay JSON for one recording; meta is a daily `replays` candidate."""
    start, writes = parse(data)
    chunks: list[tuple[float, str]] = []
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    for t, direction, payload in writes:
        if direction == DIR_OUTPUT:
            chunks.append((t, decoder.decode(payload)))
        elif direction == DIR_INTERACT:
            command = codecs.decode(payload, "utf-8", "replace").replace("\x00", "")
            chunks.append((t, "$ " + " ".join(command.split("\n")) + "\r\n"))
    tail = decoder.decode(b"", final=True)
    if tail and chunks:
        chunks[-1] = (chunks[-1][0], chunks[-1][1] + tail)

    joined = "".join(text for _t, text in chunks)
    owners: list[int] = []
    for index, (_t, text) in enumerate(chunks):
        owners.extend([index] * len(text))
    chars, owner_of = _clean(joined, owners)
    chars = _defang(chars)

    per_chunk: dict[int, list[str]] = {}
    for ch, owner in zip(chars, owner_of):
        per_chunk.setdefault(owner, []).append(ch)

    t0 = start if start is not None else (chunks[0][0] if chunks else 0.0)
    frames: list[list] = []
    used, truncated, last_t, prev_raw = 0, False, 0.0, None
    for index, (t, _text) in enumerate(chunks):
        text = "".join(per_chunk.get(index, ()))
        if not text:
            continue
        room = MAX_TEXT - used
        merge = bool(frames) and prev_raw is not None and t - prev_raw <= MERGE_GAP
        if room <= 0 or (not merge and len(frames) >= MAX_FRAMES):
            truncated = True
            break
        if merge:
            frames[-1][1] += text[:room]
        else:
            last_t = max(last_t, round(t - t0, 3))
            frames.append([last_t, text[:room]])
        used += min(len(text), room)
        prev_raw = t
        if len(text) > room:
            truncated = True
            break
    if truncated:
        frames.append([last_t, TRUNCATED])

    duration = (meta.get("duration_ms") or 0) / 1000 or (frames[-1][0] if frames else 0.0)
    if start is not None:
        begun = dt.datetime.fromtimestamp(t0, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    else:
        ts = str(meta.get("ts", ""))
        begun = ts[:19] + "Z" if len(ts) >= 19 else ""
    sha = str(meta.get("sha", ""))
    return {
        "v": 1,
        "id": sha[:16],
        "session": meta.get("session", ""),
        "ip": meta.get("ip", ""),
        "protocol": meta.get("protocol", ""),
        "start": begun,
        "duration": round(duration, 1),
        "campaign": meta.get("campaign"),
        "truncated": truncated,
        "frames": frames,
    }
