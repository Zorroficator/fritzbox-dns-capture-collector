import json
import re
import tempfile
import unittest
from pathlib import Path

import helpers as h
import ftrap_dns
from test_store_and_loop import LoopTests

ROOT = Path(__file__).resolve().parent.parent
DOC = (ROOT / "docs" / "dns_contract.md").read_text(encoding="utf-8")
FREE_MAPS = {"statuses"}      # dictionaries with data-dependent keys


def doc_json(heading):
    """First ```json block after the '## <heading>' line."""
    start = DOC.index(f"## `{heading}`")
    m = re.search(r"```json\n(.*?)```", DOC[start:], re.S)
    return json.loads(m.group(1))


def shape(value, key=""):
    if isinstance(value, dict):
        if key in FREE_MAPS:
            return "map"
        return {k: shape(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [shape(value[0], key)] if value else []
    return "scalar"


def diff(a, b, path=""):
    """List differences; an empty list on either side matches anything."""
    if isinstance(a, list) and isinstance(b, list):
        if not a or not b:
            return []
        return diff(a[0], b[0], path + "[]")
    if isinstance(a, dict) and isinstance(b, dict):
        out = []
        for k in sorted(set(a) | set(b)):
            if k not in a:
                out.append(f"{path}.{k}: missing in docs")
            elif k not in b:
                out.append(f"{path}.{k}: missing in output")
            else:
                out += diff(a[k], b[k], f"{path}.{k}")
        return out
    return [] if a == b else [f"{path}: {a!r} != {b!r}"]


class ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.TemporaryDirectory()
        loop = LoopTests()
        app = loop.make_app(cls.tmpdir.name, loop.build_stream(250))
        orig = app._session

        def once():
            orig()
            app.stop_event.set()
        app._session = once
        app.run()
        out = Path(cls.tmpdir.name) / "out"
        cls.live = json.loads((out / "dns_live.json").read_text())
        cls.top = json.loads((out / "dns_top.json").read_text())

    @classmethod
    def tearDownClass(cls):
        cls.tmpdir.cleanup()

    def test_live_max_documented(self):
        self.assertEqual(ftrap_dns.LIVE_MAX, 200)
        self.assertIn("never has more than 200", DOC)
        for word in ("`demo`", "`exported_at`", '"(other)"', "untrusted"):
            self.assertIn(word, DOC)

    def test_live_shape_matches_docs(self):
        self.assertEqual(diff(shape(doc_json("dns_live.json")), shape(self.live)), [])

    def test_top_shape_matches_docs(self):
        doc = doc_json("dns_top.json")
        doc["periods"]["7d"] = doc["periods"]["30d"] = doc["periods"]["today"]
        self.assertEqual(diff(shape(doc), shape(self.top)), [])

    def test_event_and_health_fields_documented(self):
        for key in list(self.live["events"][0]) + list(self.live["health"]):
            self.assertIn(f"`{key}`", DOC, key)

    def test_all_error_codes_documented(self):
        src = (ROOT / "capture.py").read_text(encoding="utf-8")
        codes = set(re.findall(r'code = "([a-z_]+)"', src))
        codes |= set(re.findall(r'CaptureError\([^\n]*?, "([a-z_]+)"\)', src))
        main_src = (ROOT / "ftrap_dns.py").read_text(encoding="utf-8")
        codes |= set(re.findall(r'CaptureError\([^\n]*?, \\?"([a-z_]+)\\?"\)', main_src))
        codes |= {"credentials_error", "internal_error"}
        codes.discard("aborted")      # an intended stop is never reported as an error
        self.assertTrue({"auth_failed", "capture_busy", "tls_error"} <= codes)
        for code in codes:
            self.assertIn(f"`{code}`", DOC, code)


if __name__ == "__main__":
    unittest.main()
