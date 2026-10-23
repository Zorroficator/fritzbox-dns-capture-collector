import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import helpers as h
import check_login
import credentials as cr
import fritz_auth
import ftrap_dns

PW_ENV = {cr.ENV_USER: "capture", cr.ENV_PASSWORD: "pw"}


class MainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfgfile = Path(self.tmp.name) / "c.toml"
        self.cred = Path(self.tmp.name) / "cred"
        self.cfgfile.write_text(
            f'credentials_file = "{self.cred}"\nout_dir = "{self.tmp.name}/out"\n'
            f'db_path = "{self.tmp.name}/x.db"\ntimezone = "UTC"\n')

    def run_main(self, argv, env=None):
        with mock.patch.dict(os.environ, env or {}, clear=False), \
                mock.patch.object(ftrap_dns.App, "run") as run, \
                mock.patch("signal.signal"), \
                mock.patch.object(ftrap_dns, "_setup_logging"), \
                mock.patch.object(ftrap_dns, "log") as self.log:
            for k in (cr.ENV_USER, cr.ENV_PASSWORD):
                if k not in (env or {}):
                    os.environ.pop(k, None)
            rc = ftrap_dns.main(["--config", str(self.cfgfile)] + argv)
        return rc, run

    def test_missing_credentials_exit_2(self):
        rc, run = self.run_main([])
        self.assertEqual(rc, 2)
        self.log.error.assert_called()
        run.assert_not_called()

    def test_insecure_file_exit_2_and_override(self):
        self.cred.write_text("capture\npw\n")
        os.chmod(self.cred, 0o644)
        rc, run = self.run_main([])
        self.assertEqual(rc, 2)
        rc, run = self.run_main(["--allow-insecure-credentials"])
        self.assertEqual(rc, 0)
        run.assert_called_once()

    def test_env_credentials_start(self):
        rc, run = self.run_main([], env=PW_ENV)
        self.assertEqual(rc, 0)
        run.assert_called_once()

    def test_password_stdin(self):
        with mock.patch("sys.stdin", io.StringIO("pw\n")):
            rc, run = self.run_main(["--password-stdin"], env={cr.ENV_USER: "capture"})
        self.assertEqual(rc, 0)

    def test_bad_config_exit_2(self):
        self.cfgfile.write_text('box_url = "https://fritz.box"\n')   # https without pin
        rc, run = self.run_main([], env=PW_ENV)
        self.assertEqual(rc, 2)
        run.assert_not_called()

    def test_output_dirs_private(self):
        self.run_main([], env=PW_ENV)
        mode = os.stat(Path(self.tmp.name) / "out").st_mode & 0o777
        self.assertEqual(mode, 0o700)

    def test_existing_output_dir_not_changed(self):
        out = Path(self.tmp.name) / "out"
        out.mkdir()
        os.chmod(out, 0o755)
        with self.assertLogs("ftrap_dns", "WARNING") as lg:
            self.run_main([], env=PW_ENV)
        self.assertEqual(os.stat(out).st_mode & 0o777, 0o755)
        self.assertTrue(any("leaving it unchanged" in m for m in lg.output))

    def test_http_warning_once_at_start(self):
        self.run_main([], env=PW_ENV)
        msgs = [c.args[0] for c in self.log.warning.call_args_list]
        self.assertTrue(any("plain http" in m for m in msgs))

    def test_no_http_warning_for_https(self):
        self.cfgfile.write_text(self.cfgfile.read_text() + 'box_url = "https://fritz.box"\npin_sha256 = "%s"\n' % ("ab" * 32))
        self.run_main([], env=PW_ENV)
        msgs = [c.args[0] for c in self.log.warning.call_args_list]
        self.assertFalse(any("plain http" in m for m in msgs))


class CheckLoginTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfgfile = Path(self.tmp.name) / "c.toml"
        self.cfgfile.write_text('box_url = "http://192.0.2.1"\n')

    def run_check(self, side_effect=None, sid="0123456789abcdef"):
        out = io.StringIO()
        fake = mock.Mock()
        if side_effect:
            fake.get_sid.side_effect = side_effect
        else:
            fake.get_sid.return_value = sid
        with mock.patch.dict(os.environ, PW_ENV), \
                mock.patch.object(fritz_auth, "FritzAuth", return_value=fake), \
                mock.patch.object(check_login, "logout") as lo, \
                contextlib.redirect_stdout(out):
            rc = check_login.main(["--config", str(self.cfgfile)])
        return rc, out.getvalue(), lo

    def test_ok_logs_out(self):
        rc, out, lo = self.run_check()
        self.assertEqual(rc, 0)
        self.assertIn("Login ok", out)
        lo.assert_called_once()

    def test_rejected(self):
        rc, out, lo = self.run_check(fritz_auth.LoginRejected("x"))
        self.assertEqual(rc, 1)
        self.assertIn("rejected", out)
        lo.assert_not_called()

    def test_http_warning(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.run_check()
        self.assertIn("plain http", err.getvalue())

    def test_pin_error(self):
        rc, out, _ = self.run_check(fritz_auth.AuthError("x"))
        self.assertEqual(rc, 1)
        try:
            raise fritz_auth.CertPinError("pin")
        except OSError as inner:
            err = fritz_auth.AuthError("failed")
            err.__cause__ = inner
        rc, out, _ = self.run_check(err)
        self.assertEqual(rc, 1)
        self.assertIn("TLS certificate", out)

    def test_missing_credentials(self):
        out = io.StringIO()
        env = {k: v for k, v in os.environ.items() if k not in (cr.ENV_USER, cr.ENV_PASSWORD)}
        self.cfgfile.write_text(f'credentials_file = "{self.tmp.name}/none"\n')
        with mock.patch.dict(os.environ, env, clear=True), contextlib.redirect_stdout(out):
            rc = check_login.main(["--config", str(self.cfgfile)])
        self.assertEqual(rc, 1)
        self.assertNotIn("pw", out.getvalue().replace("password", ""))


if __name__ == "__main__":
    unittest.main()
