"""Group sessions that ran commands into campaigns.

Bots replay the same script over and over, so a session's command sequence is
a good fingerprint of the tool behind it. A few families leave a recognisable
marker and get a name; everything else is clustered by its normalized command
sequence. Like the ATT&CK mapping this is a heuristic: it groups what looks the
same, it does not attribute anything to an actor.
"""
from __future__ import annotations

import hashlib
import re
from typing import Sequence

# Known families, first match wins. Each marker is something the family's own
# scripts type verbatim, not a generic command every bot uses.
_FAMILIES: list[tuple[re.Pattern[str], str, str]] = [
    # SSH key with the comment "mdrfckr", planted by the Outlaw (Dota) group.
    (re.compile(r"mdrfckr"), "outlaw-mdrfckr", "Outlaw botnet (mdrfckr SSH key)"),
    (re.compile(r"\bredtail\b", re.IGNORECASE), "redtail", "RedTail cryptominer"),
    (re.compile(r"xmrig|stratum\+(?:tcp|ssl)://", re.IGNORECASE), "xmrig-miner", "XMRig cryptominer dropper"),
]
# Mirai and its forks run `/bin/busybox <TAG>` and expect "<TAG>: applet not
# found" to prove they reached a real BusyBox shell. The tag is the bot's name
# and is upper case, unlike real applets.
_BUSYBOX_TAG = re.compile(r"(?:^|[\s;&|])(?:/bin/)?busybox\s+([A-Z][A-Z0-9_]{2,19})(?=$|[\s;&|])")

TRIVIAL = {"", "sh", "shell", "enable", "system", "linuxshell", "ping; sh"}
NAME_LIMIT = 48


def _clean(text: str, limit: int = NAME_LIMIT) -> str:
    """Single-line, printable, bounded: safe to use as a display name."""
    text = "".join(ch if ch.isprintable() else "?" for ch in " ".join(text.split()))
    return text if len(text) <= limit else text[: limit - 1] + "…"


def normalize(commands: Sequence[str]) -> list[str]:
    """Strip, collapse whitespace, digits -> 0, drop consecutive duplicates."""
    out: list[str] = []
    for command in commands:
        norm = re.sub(r"\d+", "0", " ".join(command.split()))
        if not out or out[-1] != norm:
            out.append(norm)
    return out


def classify(commands: Sequence[str]) -> tuple[str, str, bool]:
    """(campaign id, display name, known family?) for one session's commands."""
    for pattern, cid, name in _FAMILIES:
        if any(pattern.search(c) for c in commands):
            return cid, name, True
    for command in commands:
        m = _BUSYBOX_TAG.search(command)
        if m:
            tag = m.group(1)
            return "mirai-" + tag.lower().replace("_", "-"), f"Mirai-style loader ({tag})", True

    norm = normalize(commands)
    cid = "c-" + hashlib.sha1("\n".join(norm).encode("utf-8", "replace")).hexdigest()[:8]
    collapsed = [" ".join(c.split()) for c in commands]
    first = next((c for c in collapsed if c not in TRIVIAL), None)
    label = first if first is not None else "; ".join(c for c in normalize(collapsed) if c) or "(empty)"
    return cid, "Cluster: " + _clean(label), False
