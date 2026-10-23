import io
import os
import tempfile
import unittest
from pathlib import Path

import helpers  # noqa: F401
import credentials as cr


class CredentialsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "creds"
        self.cfg = {"credentials_file": str(self.path), "user": ""}

    def write(self, text, mode=0o600):
        self.path.write_text(text)
        os.chmod(self.path, mode)

    def test_env_first(self):
        self.write("fileuser\nfilepw\n")
        env = {cr.ENV_USER: "envuser", cr.ENV_PASSWORD: "envpw"}
        self.assertEqual(cr.load_credentials(self.cfg, environ=env), ("envuser", "envpw"))

    def test_partial_env_falls_back_to_file(self):
        self.write("fileuser\nfilepw\n")
        env = {cr.ENV_USER: "envuser"}
        self.assertEqual(cr.load_credentials(self.cfg, environ=env), ("fileuser", "filepw"))

    def test_file_two_lines(self):
        self.write("capture\nsecret pw\n")
        self.assertEqual(cr.load_credentials(self.cfg, environ={}), ("capture", "secret pw"))

    def test_file_keyed(self):
        self.write("username: capture\npassword: a:b\n")
        self.assertEqual(cr.load_credentials(self.cfg, environ={}), ("capture", "a:b"))

    def test_file_incomplete(self):
        self.write("onlyuser\n")
        with self.assertRaises(cr.CredentialsError):
            cr.load_credentials(self.cfg, environ={})

    def test_file_missing(self):
        with self.assertRaises(cr.CredentialsError):
            cr.load_credentials(self.cfg, environ={})

    def test_permissions_refused(self):
        self.write("capture\nsecret\n", mode=0o644)
        with self.assertRaises(cr.CredentialsError) as cm:
            cr.load_credentials(self.cfg, environ={})
        self.assertNotIn("secret", str(cm.exception))
        self.assertIn("chmod 600", str(cm.exception))

    def test_permissions_override_warns(self):
        self.write("capture\nsecret\n", mode=0o640)
        warnings = []
        got = cr.load_credentials(self.cfg, allow_insecure=True, environ={}, warn=warnings.append)
        self.assertEqual(got, ("capture", "secret"))
        self.assertEqual(len(warnings), 1)
        self.assertNotIn("secret", warnings[0])

    def test_stdin_password(self):
        self.assertEqual(cr.read_password_stdin(io.StringIO("pw\nrest")), "pw")
        with self.assertRaises(cr.CredentialsError):
            cr.read_password_stdin(io.StringIO("\n"))

    def test_stdin_with_env_user_ignores_file(self):
        got = cr.load_credentials(self.cfg, stdin_password="pw", environ={cr.ENV_USER: "u"})
        self.assertEqual(got, ("u", "pw"))

    def test_stdin_with_config_user(self):
        self.cfg["user"] = "cfguser"
        self.assertEqual(cr.load_credentials(self.cfg, stdin_password="pw", environ={}),
                         ("cfguser", "pw"))

    def test_stdin_without_user(self):
        with self.assertRaises(cr.CredentialsError):
            cr.load_credentials(self.cfg, stdin_password="pw", environ={})


if __name__ == "__main__":
    unittest.main()
