import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import helpers  # noqa: F401
import config

PIN = "ab" * 32


class ConfigTests(unittest.TestCase):
    def load(self, text):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "c.toml"
            p.write_text(text)
            return config.load_config(p)

    def test_defaults(self):
        c = config.load_config()
        self.assertEqual(c["box_url"], "http://fritz.box")
        self.assertEqual(c["interface"], "1-lan")
        self.assertEqual(c["limits"]["client_per_min"], 1200)
        self.assertEqual(c["retention"]["events_hours"], 24)
        self.assertEqual(c["timezone"], "")
        self.assertTrue(c["db_path"].endswith("ftrap/ftrap_dns.db"))

    def test_xdg(self):
        with mock.patch.dict(os.environ, {"XDG_DATA_HOME": "/tmp/xd", "XDG_CONFIG_HOME": "/tmp/xc"}):
            c = config.load_config()
        self.assertEqual(c["db_path"], "/tmp/xd/ftrap/ftrap_dns.db")
        self.assertEqual(c["credentials_file"], "/tmp/xc/ftrap/capture_credentials")

    def test_override_and_sections_merge(self):
        c = self.load('interface = "2-wan"\n[limits]\nclient_per_min = 5\n')
        self.assertEqual(c["interface"], "2-wan")
        self.assertEqual(c["limits"]["client_per_min"], 5)
        self.assertEqual(c["limits"]["domains_per_day"], 20000)

    def test_https_needs_pin_or_ca(self):
        with self.assertRaises(ValueError):
            self.load('box_url = "https://fritz.box"\n')
        c = self.load(f'box_url = "https://fritz.box"\npin_sha256 = "{PIN}"\n')
        self.assertEqual(c["pin_sha256"], PIN)
        self.load('box_url = "https://fritz.box"\nca_file = "/tmp/box.pem"\n')

    def test_bad_values(self):
        for text in ('box_url = "ftp://x"\n', 'timezone = "Nowhere/Land"\n',
                     f'pin_sha256 = "zz"\n'):
            with self.assertRaises(ValueError):
                self.load(text)

    def test_timezone(self):
        self.assertIsNone(config.resolve_timezone(""))
        self.assertEqual(str(config.resolve_timezone("UTC")), "UTC")

    def test_private_helpers(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "sub" / "f.json"
            config.write_private(p, '{"a": 1}')
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(p.parent.stat().st_mode), 0o700)   # newly created
            fd = config.open_private(Path(d) / "log")
            os.close(fd)
            self.assertEqual(stat.S_IMODE((Path(d) / "log").stat().st_mode), 0o600)

    def test_open_private_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "target"
            target.write_text("keep")
            os.chmod(target, 0o644)
            link = Path(d) / "log"
            link.symlink_to(target)
            with self.assertRaises(OSError):
                config.open_private(link)
            self.assertEqual(target.read_text(), "keep")
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)

    def test_legacy_md5_default_and_type(self):
        self.assertIs(config.load_config()["allow_legacy_md5"], False)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "c.toml"
            p.write_text("allow_legacy_md5 = true\n")
            self.assertIs(config.load_config(p)["allow_legacy_md5"], True)
            p.write_text('allow_legacy_md5 = "yes"\n')
            with self.assertRaises(ValueError):
                config.load_config(p)

    def test_existing_dir_untouched_with_warning(self):
        with tempfile.TemporaryDirectory() as d:
            existing = Path(d) / "web"
            existing.mkdir()
            os.chmod(existing, 0o755)
            with self.assertLogs("ftrap_dns", "WARNING") as lg:
                config.ensure_private_dir(existing)
                config.ensure_private_dir(existing)      # warned only once
            self.assertEqual(len(lg.output), 1)
            self.assertEqual(stat.S_IMODE(existing.stat().st_mode), 0o755)
            config.write_private(existing / "f.json", "{}")
            self.assertEqual(stat.S_IMODE(existing.stat().st_mode), 0o755)

    def test_existing_dir_within_mode_no_warning(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "ok"
            p.mkdir()
            os.chmod(p, 0o750)
            with self.assertNoLogs("ftrap_dns", "WARNING"):
                config.ensure_private_dir(p, 0o750)

    def test_new_dir_gets_mode_despite_umask(self):
        old = os.umask(0o077)
        try:
            with tempfile.TemporaryDirectory() as d:
                p = config.ensure_private_dir(Path(d) / "a" / "b", 0o750)
                self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o750)
        finally:
            os.umask(old)

    def test_every_new_path_component_gets_mode(self):
        old = os.umask(0o022)
        try:
            with tempfile.TemporaryDirectory() as d:
                base = Path(d) / "keep"
                base.mkdir()
                os.chmod(base, 0o755)
                with self.assertLogs("ftrap_dns", "WARNING"):
                    config.ensure_private_dir(base)
                p = config.ensure_private_dir(base / "a" / "b" / "c", 0o750)
                for part in (base / "a", base / "a" / "b", p):
                    self.assertEqual(stat.S_IMODE(part.stat().st_mode), 0o750)
                self.assertEqual(stat.S_IMODE(base.stat().st_mode), 0o755)   # existing: untouched
        finally:
            os.umask(old)

    def test_file_mode_applies_despite_umask(self):
        old = os.umask(0o077)
        try:
            with tempfile.TemporaryDirectory() as d:
                p = Path(d) / "f.json"
                config.write_private(p, "{}", file_mode=0o640)
                self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o640)
        finally:
            os.umask(old)

    def test_output_modes(self):
        c = self.load('[output]\ndir_mode = 0o750\nfile_mode = "0640"\n')
        self.assertEqual((c["output"]["dir_mode"], c["output"]["file_mode"]), (0o750, 0o640))
        c = config.load_config()
        self.assertEqual((c["output"]["dir_mode"], c["output"]["file_mode"]), (0o700, 0o600))

    def test_invalid_modes(self):
        for text in ('[output]\nfile_mode = 0o755\n', '[output]\nfile_mode = "0644x"\n',
                     '[output]\ndir_mode = 0o1777\n', '[output]\nfile_mode = true\n',
                     '[output]\nfile_mode = 0o400\n', '[output]\ndir_mode = 0o070\n'):
            with self.assertRaises(ValueError, msg=text):
                self.load(text)

    def test_limit_defaults(self):
        c = config.load_config()
        self.assertEqual((c["limits"]["events_per_min"], c["limits"]["clients_per_day"]), (6000, 500))


if __name__ == "__main__":
    unittest.main()
