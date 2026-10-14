import datetime as dt
import gzip
import re
import tempfile
import unittest
from pathlib import Path

from pipeline.geo import GeoDB
from pipeline.report import write_reports

SITE = "https://ondrej-cloud.github.io/azure-honeypot/"
NOW = dt.datetime(2026, 10, 14, 12, 0, tzinfo=dt.timezone.utc)   # Wednesday of 2026-W42
SHA_A = "a" * 64
SHA_B = "b" * 64
TTY = "c" * 64
HOSTILE = "<script>alert(1)</script>|`x``\nnext"


def summary(date, ips=None, passwords=(), credentials=(), campaigns=None, downloads=(), records=None,
            replays=(), schema=2):
    ips = ips or {"203.0.113.7": [5, 4, 1, 3]}
    day = {
        "schema": schema, "date": date, "sensor": "azure-test",
        "totals": {"sessions": sum(c[0] for c in ips.values()), "login_attempts": sum(c[1] for c in ips.values()),
                   "login_success": sum(c[2] for c in ips.values()), "commands": sum(c[3] for c in ips.values()),
                   "interactive_sessions": 1, "downloads": len(downloads), "malformed_lines": 0},
        "unique_ips": len(ips), "hourly": [0] * 24, "protocols": {"ssh": 1},
        "ips": ips, "usernames": [], "passwords": [list(p) for p in passwords],
        "credentials": [list(c) for c in credentials], "commands": [], "clients": [], "hassh": [],
        "techniques": {}, "downloads": [dict(d) for d in downloads],
    }
    if schema >= 2:
        day.update({"campaigns": campaigns or {}, "replays": list(replays), "records": records or {},
                    "profiles": {}, "failed_downloads": []})
    return day


def geodb(tmp: Path) -> GeoDB:
    path = tmp / "ip2asn.tsv.gz"
    with gzip.open(path, "wt") as f:
        f.write("203.0.113.0\t203.0.113.255\t64500\tPK\tEXAMPLE-NET <b>bold</b>\n")
        f.write("198.51.100.0\t198.51.100.255\t64501\tUS\tTEST-NET\n")
    return GeoDB(path)


def outside_code(text: str) -> str:
    """Markdown with inline code spans removed, i.e. what GitHub would interpret as markup."""
    return re.sub(r"(`+).*?\1", "", text)


class ReportTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.geo = geodb(self.dir)
        self.out = self.dir / "reports"
        self.days = [
            summary("2026-10-11", passwords=[("123456", 9), ("old-secret", 2)],
                    credentials=[("root", "123456", 9)],
                    campaigns={"mirai-hisilicon": {"name": "Mirai-style loader (HISILICON)", "known": True,
                                                   "sessions": 4, "ips": {"203.0.113.7": 4},
                                                   "first": "2026-10-11T03:00:00Z", "last": "2026-10-11T04:00:00Z"}}),
            summary("2026-10-12", ips={"203.0.113.7": [8, 6, 2, 5], "198.51.100.9": [2, 2, 0, 0]},
                    passwords=[("old-secret", 3), (HOSTILE, 1), ("fresh", 4)],
                    credentials=[("root", HOSTILE, 1), ("admin", "fresh", 4)],
                    campaigns={
                        "mirai-hisilicon": {"name": "Mirai-style loader (HISILICON)", "known": True, "sessions": 6,
                                            "ips": {"203.0.113.7": 6}, "first": "2026-10-12T01:00:00Z",
                                            "last": "2026-10-12T09:00:00Z"},
                        "c-1234abcd": {"name": "Cluster: " + HOSTILE, "known": False, "sessions": 2,
                                       "ips": {"198.51.100.9": 2}, "first": "2026-10-12T05:00:00Z",
                                       "last": "2026-10-12T05:30:00Z"}},
                    downloads=[{"sha256": SHA_A, "url": "http://203.0.113.5/bins.sh", "count": 3,
                                "first": "2026-10-12T05:00:00Z", "last": "2026-10-12T06:00:00Z",
                                "ips": ["203.0.113.7"], "campaigns": ["mirai-hisilicon"]},
                               {"sha256": "not-a-hash](javascript:alert(1))", "url": HOSTILE, "count": 1,
                                "first": "2026-10-12T07:00:00Z", "last": "2026-10-12T07:00:00Z"}],
                    records={"longest_session": {"duration_ms": 754000, "session": "s1", "ip": "203.0.113.7",
                                                 "protocol": "telnet", "ts": "2026-10-12T05:00:00Z"},
                             "most_commands": {"commands": 41, "session": "s2", "ip": "198.51.100.9",
                                               "ts": "2026-10-12T06:00:00Z"},
                             "longest_password": {"length": len(HOSTILE), "password": HOSTILE, "ip": "198.51.100.9",
                                                  "ts": "2026-10-12T07:00:00Z"},
                             "most_attempts_ip": {"attempts": 6, "ip": "203.0.113.7"}},
                    replays=[{"sha": TTY, "session": "s1", "ip": "203.0.113.7", "protocol": "telnet",
                              "ts": "2026-10-12T05:00:00Z", "duration_ms": 754000, "size": 900, "commands": 9,
                              "campaign": "mirai-hisilicon"}]),
            summary("2026-10-13", schema=1, passwords=[("fresh", 1)]),
        ]
        self.malware = {SHA_A: {"v": 1, "sha256": SHA_A, "size": 2048, "kind": "elf",
                                "elf": {"bits": 32, "endian": "little", "machine": "ARM", "static": True},
                                "packer": "UPX",
                                "intel": {"checked_at": "2026-10-12T08:00:00Z",
                                          "vt": {"malicious": 41, "total": 66, "label": "trojan.mirai/gafgyt"},
                                          "mb": {"signature": "Mirai", "tags": ["elf"]}}}}

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, **kw):
        kw.setdefault("replay_ids", {TTY[:16]})
        return write_reports(self.days, self.malware, self.geo, self.out, site_url=SITE, now=NOW, **kw)

    def read(self, name):
        return (self.out / name).read_text(encoding="utf-8")

    def test_one_file_per_iso_week_and_an_index(self):
        changed = self.write()
        self.assertEqual(sorted(p.name for p in changed), ["2026-W41.md", "2026-W42.md", "README.md"])
        w41, w42 = self.read("2026-W41.md"), self.read("2026-W42.md")
        self.assertTrue(w42.startswith("# Week 2026-W42 · Oct 12 – Oct 18, 2026\n"))
        self.assertIn("**In progress.** Covers Oct 12 – Oct 13, 2026 so far", w42)
        self.assertNotIn("In progress", w41)
        index = self.read("README.md")
        self.assertLess(index.index("[2026-W42](2026-W42.md) _(in progress)_"), index.index("[2026-W41](2026-W41.md)"))

    def test_headline_compares_with_previous_week(self):
        self.write()
        w42 = self.read("2026-W42.md")
        # W41: 5 sessions; W42: 10 + 5 (schema-1 day) = 15 -> +200%
        self.assertIn("| Connections | 15 | 5 | +200% |", w42)
        self.assertIn("| New malware samples | 2 | 0 | new |", w42)
        self.assertIn("| Connections | 5 | – | – |", self.read("2026-W41.md"))

    def test_campaigns_samples_and_links(self):
        self.write()
        w42 = self.read("2026-W42.md")
        self.assertIn(f"[Dashboard]({SITE}#all&campaign=mirai-hisilicon) · [Replay]({SITE}#all&replay={TTY[:16]})", w42)
        self.assertIn("`Cluster:", w42)
        self.assertRegex(w42, r"`Cluster:[^\n]*` \*\*new\*\*")
        self.assertNotRegex(w42, r"HISILICON\)` \*\*new\*\*")      # first seen the week before
        self.assertIn(f"[`{SHA_A[:12]}…`](https://www.virustotal.com/gui/file/{SHA_A})", w42)
        self.assertIn("ARM 32-bit LE, static, UPX packed", w42)
        self.assertIn("VT 41/66 trojan.mirai/gafgyt · MalwareBazaar: Mirai", w42)
        self.assertIn("2.0 KB", w42)
        self.assertIn("`hxxp://203[.]0[.]113[.]5/bins.sh`", w42)
        self.assertNotIn("http://203.0.113.5", w42)
        self.assertIn(f"[203.0.113.7]({SITE}#all&ip=203.0.113.7)", w42)

    def test_replays_are_linked_only_when_published(self):
        self.write(replay_ids=set())
        self.assertNotIn("#all&replay=", self.read("2026-W42.md"))

    def test_hostile_strings_cannot_become_markup(self):
        self.write()
        for name in ("2026-W41.md", "2026-W42.md", "README.md"):
            text = self.read(name)
            markup = outside_code(text)
            self.assertNotIn("<script", markup, name)
            self.assertNotIn("<b>", markup, name)
            self.assertNotIn("javascript:", markup, name)
            for line in text.splitlines():
                if line.startswith("|"):
                    # an injected newline or unescaped pipe would break the table row
                    cells = re.split(r"(?<!\\)\|", outside_code(line))
                    self.assertTrue(line.endswith("|"), line)
                    self.assertGreaterEqual(len(cells), 3, line)
        self.assertIn("EXAMPLE-NET \\<b\\>bold\\</b\\>", self.read("2026-W42.md"))

    def test_new_passwords_ignore_earlier_weeks(self):
        self.write()
        w42 = self.read("2026-W42.md")
        section = w42[w42.index("never tried before"):w42.index("## Records")]
        self.assertIn("`fresh`", section)
        self.assertNotIn("old-secret", section)
        self.assertNotIn("123456", section)

    def test_first_week_has_no_new_password_list(self):
        self.write()
        self.assertIn("_The sensor's first week: every password is new._", self.read("2026-W41.md"))

    def test_records(self):
        self.write()
        w42 = self.read("2026-W42.md")
        self.assertIn(f"| Longest session | 12 min 34 s (telnet) · Oct 12 | [203.0.113.7]({SITE}#all&ip=203.0.113.7)"
                      f" · [Replay]({SITE}#all&replay={TTY[:16]}) |", w42)
        self.assertIn("| Most commands in one session | 41 · Oct 12 |", w42)
        self.assertIn(f"({len(HOSTILE)} characters) | [198.51.100.9]", w42)
        self.assertIn("| Most login attempts from one IP | 10 |", w42)    # 6 + 4 (schema-1 day)
        self.assertIn("| Most persistent IP | active on 2 days |", w42)
        index = self.read("README.md")
        self.assertIn("## All-time records", index)
        self.assertIn("| Most active campaign | `Mirai-style loader (HISILICON)` · 10 sessions |", index)

    def test_second_run_changes_nothing(self):
        self.write()
        before = {p.name: p.read_text() for p in self.out.iterdir()}
        self.assertEqual(self.write(), [])
        self.assertEqual({p.name: p.read_text() for p in self.out.iterdir()}, before)

    def test_schema_1_only(self):
        days = [summary("2026-09-28", schema=1, passwords=[("toor", 3)], credentials=[("root", "toor", 3)])]
        write_reports(days, {}, GeoDB(), self.out, site_url=SITE, now=NOW)
        text = self.read("2026-W40.md")
        self.assertTrue(text.startswith("# Week 2026-W40 · Sep 28 – Oct 4, 2026\n"))
        self.assertIn("## Attack campaigns\n\nSessions grouped by the commands they ran (heuristic).\n\n"
                      "_Nothing recorded this week._", text)
        self.assertIn("| Longest password | `toor` (4 characters) | – |", text)
        self.assertIn("Unknown", text)   # no geo data

    def test_week_spanning_new_year(self):
        days = [summary("2026-12-31"), summary("2027-01-01"), summary("2027-01-04")]
        write_reports(days, {}, GeoDB(), self.out, site_url=SITE, now=NOW)
        self.assertTrue(self.read("2026-W53.md").startswith("# Week 2026-W53 · Dec 28, 2026 – Jan 3, 2027\n"))
        self.assertIn("| Connections | 10 |", self.read("2026-W53.md"))
        self.assertIn("| Connections | 5 | 10 | −50% |", self.read("2027-W01.md"))

    def test_nothing_to_do_without_days(self):
        self.assertEqual(write_reports([], {}, GeoDB(), self.out, site_url=SITE, now=NOW), [])
        self.assertFalse(self.out.exists())


if __name__ == "__main__":
    unittest.main()
