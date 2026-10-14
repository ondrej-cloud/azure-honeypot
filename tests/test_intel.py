import contextlib
import datetime as dt
import io
import json
import tempfile
import unittest
import urllib.error
import urllib.parse
from pathlib import Path
from unittest import mock

from pipeline import intel

NOW = dt.datetime(2026, 10, 14, 12, 0, tzinfo=dt.timezone.utc)
VT_KEY = "vt-secret-key-123"
MB_KEY = "mb-secret-key-456"


def sha(n: int) -> str:
    return f"{n:064x}"


class FakeResponse:
    def __init__(self, body: dict, status: int = 200):
        self.status = status
        self.body = json.dumps(body).encode()

    def read(self):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def http_error(url: str, code: int):
    return urllib.error.HTTPError(url, code, "error", {}, None)


class FakeAPIs:
    """Stands in for urllib.request.urlopen; answers per hash and records every request."""

    def __init__(self, vt=None, mb=None):
        self.vt = vt or {}     # sha -> body dict | int (HTTP error code) | Exception
        self.mb = mb or {}
        self.requests = []

    def __call__(self, req, timeout=None):
        url = req.full_url
        self.requests.append(req)
        if url.startswith(intel.VT_URL):
            self.assert_header(req, "X-apikey", VT_KEY)
            answer = self.vt.get(url[len(intel.VT_URL):], 404)
        else:
            self.assert_header(req, "Auth-key", MB_KEY)
            form = urllib.parse.parse_qs(req.data.decode())
            assert form["query"] == ["get_info"], form
            answer = self.mb.get(form["hash"][0], {"query_status": "hash_not_found"})
        if isinstance(answer, Exception):
            raise answer
        if isinstance(answer, int):
            raise http_error(url, answer)
        return FakeResponse(answer)

    @staticmethod
    def assert_header(req, name, value):
        assert req.get_header(name) == value, (name, req.header_items())

    def count(self, prefix):
        return sum(1 for r in self.requests if r.full_url.startswith(prefix))


def vt_found(malicious=41, label="trojan.mirai/gafgyt"):
    return {"data": {"attributes": {
        "last_analysis_stats": {"malicious": malicious, "suspicious": 2, "undetected": 20, "harmless": 0,
                                "timeout": 3},
        "popular_threat_classification": {"suggested_threat_label": label}}}}


def mb_found(signature="Mirai"):
    return {"query_status": "ok", "data": [{"signature": signature, "tags": ["elf", "mirai"]}]}


class IntelTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def sample(self, n, kind="elf", size=4096, first_seen="2026-10-14T07:00:00Z", intel_value=None):
        meta = {"v": 1, "sha256": sha(n), "size": size, "kind": kind, "first_seen": first_seen, "intel": intel_value}
        (self.dir / f"{sha(n)}.json").write_text(json.dumps(meta))
        return meta

    def load(self, n):
        return json.loads((self.dir / f"{sha(n)}.json").read_text())

    def run_enrich(self, apis, now=NOW, **kw):
        kw.setdefault("vt_key", VT_KEY)
        kw.setdefault("mb_key", MB_KEY)
        sleeps = []
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("urllib.request.urlopen", apis), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            changed = intel.enrich(self.dir, now=now, sleep=sleeps.append, **kw)
        return changed, sleeps, out.getvalue() + err.getvalue()

    def test_found_on_both(self):
        self.sample(1)
        changed, _, _ = self.run_enrich(FakeAPIs(vt={sha(1): vt_found()}, mb={sha(1): mb_found()}))
        self.assertEqual(changed, 1)
        got = self.load(1)["intel"]
        self.assertEqual(got["vt"], {"malicious": 41, "total": 66, "label": "trojan.mirai/gafgyt"})
        self.assertEqual(got["mb"], {"signature": "Mirai", "tags": ["elf", "mirai"]})
        self.assertEqual(got["checked_at"], "2026-10-14T12:00:00Z")

    def test_not_found_is_null_and_rechecked_after_a_week(self):
        self.sample(1)
        apis = FakeAPIs()
        self.assertEqual(self.run_enrich(apis)[0], 1)
        self.assertEqual((self.load(1)["intel"]["vt"], self.load(1)["intel"]["mb"]), (None, None))
        self.assertEqual(self.run_enrich(apis, now=NOW + dt.timedelta(days=6))[0], 0)
        self.assertEqual(len(apis.requests), 2)
        self.assertEqual(self.run_enrich(apis, now=NOW + dt.timedelta(days=7))[0], 1)
        self.assertEqual(len(apis.requests), 4)

    def test_found_is_rechecked_after_a_month(self):
        self.sample(1)
        apis = FakeAPIs(vt={sha(1): vt_found()}, mb={sha(1): mb_found()})
        self.run_enrich(apis)
        self.assertEqual(self.run_enrich(apis, now=NOW + dt.timedelta(days=29))[0], 0)
        self.assertEqual(len(apis.requests), 2)
        apis.vt[sha(1)] = vt_found(malicious=50)
        self.assertEqual(self.run_enrich(apis, now=NOW + dt.timedelta(days=30))[0], 1)
        self.assertEqual(self.load(1)["intel"]["vt"]["malicious"], 50)

    def test_errors_keep_previous_intel(self):
        old = {"checked_at": "2026-09-01T00:00:00Z", "sources": {"vt": "2026-09-01T00:00:00Z", "mb": "2026-09-01T00:00:00Z"},
               "vt": {"malicious": 3, "total": 60, "label": None}, "mb": None}
        self.sample(1, intel_value=old)
        apis = FakeAPIs(vt={sha(1): urllib.error.URLError("boom")}, mb={sha(1): 500})
        changed, _, output = self.run_enrich(apis)
        self.assertEqual(changed, 0)
        self.assertEqual(self.load(1)["intel"], old)
        self.assertIn("failed", output)

    def test_one_source_failing_does_not_block_the_other(self):
        self.sample(1)
        changed, _, _ = self.run_enrich(FakeAPIs(vt={sha(1): 502}, mb={sha(1): mb_found()}))
        self.assertEqual(changed, 1)
        got = self.load(1)["intel"]
        self.assertEqual(got["mb"]["signature"], "Mirai")
        self.assertNotIn("vt", got["sources"])   # VirusTotal stays due for the next run

    def test_budget_and_spacing(self):
        for n in range(1, 6):
            self.sample(n, first_seen=f"2026-10-1{n}T00:00:00Z")
        apis = FakeAPIs()
        changed, sleeps, _ = self.run_enrich(apis, max_vt=2, max_mb=3)
        self.assertEqual((apis.count(intel.VT_URL), apis.count(intel.MB_URL)), (2, 3))
        self.assertEqual(changed, 3)
        self.assertEqual(sleeps, [intel.VT_SPACING])            # between the two VT requests only
        checked = [n for n in range(1, 6) if self.load(n)["intel"]]
        self.assertEqual(checked, [3, 4, 5])                    # newest first

    def test_rate_limit_stops_that_source(self):
        for n in range(1, 4):
            self.sample(n)
        apis = FakeAPIs(vt={sha(n): 429 for n in range(1, 4)})
        _, _, output = self.run_enrich(apis)
        self.assertEqual(apis.count(intel.VT_URL), 1)
        self.assertEqual(apis.count(intel.MB_URL), 3)
        self.assertIn("vt stopped for this run (HTTP 429)", output)

    def test_bad_key_stops_that_source(self):
        self.sample(1)
        self.sample(2)
        apis = FakeAPIs(mb={sha(1): {"query_status": "unknown_auth_key"}, sha(2): {"query_status": "unknown_auth_key"}})
        _, _, output = self.run_enrich(apis, vt_key=None)
        self.assertEqual(apis.count(intel.MB_URL), 1)
        self.assertIn("check the API key", output)

    def test_priorities_and_skips(self):
        self.sample(1, kind="text", first_seen="2026-10-14T09:00:00Z")
        self.sample(2, kind="elf", first_seen="2026-10-01T00:00:00Z")
        self.sample(3, kind="empty", size=0)
        self.sample(4, kind="elf", size=8)
        self.sample(5, kind="script", intel_value={"checked_at": "2026-01-01T00:00:00Z",
                                                  "sources": {"vt": "2026-01-01T00:00:00Z"}, "vt": None, "mb": None})
        apis = FakeAPIs()
        self.run_enrich(apis, mb_key=None, max_vt=2)
        looked_up = [r.full_url[len(intel.VT_URL):] for r in apis.requests]
        self.assertEqual(looked_up, [sha(2), sha(1)])   # unchecked first, ELF before text; tiny/empty skipped

    def test_no_keys_is_a_no_op(self):
        self.sample(1)
        apis = FakeAPIs()
        self.assertEqual(self.run_enrich(apis, vt_key=None, mb_key=None)[0], 0)
        self.assertEqual(apis.requests, [])
        self.assertIsNone(self.load(1)["intel"])

    def test_keys_never_leak(self):
        self.sample(1)
        self.sample(2)
        apis = FakeAPIs(vt={sha(1): vt_found(), sha(2): 401}, mb={sha(1): urllib.error.URLError(VT_KEY)})
        _, _, output = self.run_enrich(apis)
        files = "".join(p.read_text() for p in self.dir.iterdir())
        for key in (VT_KEY, MB_KEY):
            self.assertNotIn(key, output)
            self.assertNotIn(key, files)

    def test_hostile_api_strings_are_bounded(self):
        self.sample(1)
        self.run_enrich(FakeAPIs(vt={sha(1): vt_found(label="x\n" * 500)},
                                 mb={sha(1): mb_found(signature="<b>\x1b[31m" + "y" * 500)}))
        got = self.load(1)["intel"]
        self.assertLessEqual(len(got["vt"]["label"]), 100)
        self.assertNotIn("\n", got["vt"]["label"])
        self.assertNotIn("\x1b", got["mb"]["signature"])
        self.assertLessEqual(len(got["mb"]["signature"]), 100)

    def test_stable_formatting_and_ignored_files(self):
        self.sample(1)
        (self.dir / "notes.json").write_text("{}")
        (self.dir / f"{sha(9)}.json").write_text("not json")
        apis = FakeAPIs()
        self.run_enrich(apis)
        text = (self.dir / f"{sha(1)}.json").read_text()
        self.assertEqual(text, json.dumps(json.loads(text), indent=1, sort_keys=True, ensure_ascii=False) + "\n")
        self.assertEqual((self.dir / "notes.json").read_text(), "{}")
        self.assertEqual(len(apis.requests), 2)


if __name__ == "__main__":
    unittest.main()
