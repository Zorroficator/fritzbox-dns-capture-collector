import hashlib
import http.client
import unittest
from unittest import mock

import helpers  # noqa: F401
import fritz_auth

DER = b"synthetic-der-certificate"
PIN = hashlib.sha256(DER).hexdigest()
OTHER_PIN = hashlib.sha256(b"other").hexdigest()
NULL = "0000000000000000"
GOOD = "0123456789abcdef"


class FakeSock:
    def __init__(self, der):
        self._der, self.closed = der, False

    def getpeercert(self, binary_form=False):
        return self._der

    def close(self):
        self.closed = True


def fake_connect(der):
    def connect(self):
        self.sock = FakeSock(der)
    return connect


class PinTests(unittest.TestCase):
    def conn(self, pin):
        return fritz_auth.PinnedHTTPSConnection("fritz.box", 443, timeout=1, pin=pin)

    def test_pin_match(self):
        with mock.patch.object(http.client.HTTPSConnection, "connect", fake_connect(DER)):
            c = self.conn(PIN)
            c.connect()
            self.assertIsNotNone(c.sock)

    def test_pin_mismatch(self):
        with mock.patch.object(http.client.HTTPSConnection, "connect", fake_connect(DER)):
            c = self.conn(OTHER_PIN)
            with self.assertRaises(fritz_auth.CertPinError) as cm:
                c.connect()
            self.assertIsInstance(cm.exception, OSError)
            self.assertNotIn(PIN, str(cm.exception))
            self.assertIsNone(c.sock)

    def test_no_certificate_is_mismatch(self):
        with mock.patch.object(http.client.HTTPSConnection, "connect", fake_connect(None)):
            with self.assertRaises(fritz_auth.CertPinError):
                self.conn(PIN).connect()

    def test_pin_format_accepts_colons_and_case(self):
        colon = ":".join(PIN[i:i + 2] for i in range(0, 64, 2)).upper()
        self.assertEqual(fritz_auth.normalize_pin(colon), PIN)
        for bad in ("", "abc", "zz" * 32, PIN[:-1]):
            with self.assertRaises(ValueError):
                fritz_auth.normalize_pin(bad)


class TransportTests(unittest.TestCase):
    def test_https_without_pin_or_ca_refused(self):
        with self.assertRaises(ValueError):
            fritz_auth.make_conn_factory("https://fritz.box")
        with self.assertRaises(ValueError):
            fritz_auth.FritzAuth("https://fritz.box", "u", "p")
        with self.assertRaises(ValueError):
            fritz_auth.check_transport("https", "", "")

    def test_http_needs_neither(self):
        conn = fritz_auth.make_conn_factory("http://fritz.box")(3)
        self.assertIsInstance(conn, http.client.HTTPConnection)
        self.assertEqual((conn.host, conn.port), ("fritz.box", 80))
        fritz_auth.FritzAuth("http://fritz.box", "u", "p")

    def test_https_with_pin_gives_pinned_connection(self):
        conn = fritz_auth.make_conn_factory("https://192.0.2.1:8443", pin_sha256=PIN)(3)
        self.assertIsInstance(conn, fritz_auth.PinnedHTTPSConnection)
        self.assertEqual((conn.host, conn.port), ("192.0.2.1", 8443))

    def test_bad_scheme_and_url(self):
        for url in ("ftp://fritz.box", "fritz.box", "http://"):
            with self.assertRaises(ValueError):
                fritz_auth.make_conn_factory(url)

    def test_https_pin_only_uses_pinned_handler(self):
        auth = fritz_auth.FritzAuth("https://fritz.box", "u", "p", pin_sha256=PIN)
        names = [type(h).__name__ for h in auth.opener.handlers]
        self.assertIn("_PinnedHTTPSHandler", names)


class FakeOpener:
    """Stands in for the urllib opener: returns canned login XML."""

    def __init__(self, final_sid):
        self.final_sid = final_sid
        self.calls = 0

    def open(self, req, timeout=None):
        self.calls += 1
        sid = NULL
        if self.calls == 2:
            sid = self.final_sid
        body = f"<SessionInfo><SID>{sid}</SID><Challenge>1234abcd</Challenge></SessionInfo>".encode()
        resp = mock.MagicMock()
        resp.__enter__.return_value = resp
        resp.read.return_value = body
        return resp


class OpenerTests(unittest.TestCase):
    def test_environment_proxy_is_never_used(self):
        import urllib.request
        with mock.patch.dict("os.environ", {"http_proxy": "http://203.0.113.1:3128"}):
            opener = fritz_auth.build_box_opener()
        # an empty ProxyHandler registers no *_open methods, but replaces the default one
        self.assertFalse(any(isinstance(x, urllib.request.ProxyHandler) and x.proxies
                             for x in opener.handlers))
        self.assertNotIn("http", [m for m in opener.handle_open if opener.handle_open[m]
                                  and any(isinstance(x, urllib.request.ProxyHandler)
                                          for x in opener.handle_open[m])])

    def test_no_ensure_sid(self):
        self.assertFalse(hasattr(fritz_auth.FritzAuth, "ensure_sid"))


class LoginTests(unittest.TestCase):
    def auth(self, final_sid):
        a = fritz_auth.FritzAuth("http://fritz.box", "u", "p", allow_legacy_md5=True)
        a._opener = FakeOpener(final_sid)
        return a

    def test_rejected(self):
        with self.assertRaises(fritz_auth.LoginRejected) as cm:
            self.auth(NULL).get_sid()
        self.assertIsInstance(cm.exception, fritz_auth.AuthError)

    def test_ok(self):
        self.assertEqual(self.auth(GOOD).get_sid(), GOOD)

    def test_unreachable_is_plain_autherror(self):
        a = fritz_auth.FritzAuth("http://fritz.box", "u", "p")
        a._opener = mock.Mock(open=mock.Mock(side_effect=OSError("boom")))
        with self.assertRaises(fritz_auth.AuthError) as cm:
            a.get_sid()
        self.assertNotIsInstance(cm.exception, fritz_auth.LoginRejected)


def challenge_opener(challenge):
    op = mock.Mock()
    body = f"<SessionInfo><SID>{NULL}</SID><Challenge>{challenge}</Challenge></SessionInfo>".encode()
    resp = mock.MagicMock()
    resp.__enter__.return_value = resp
    resp.read.return_value = body
    op.open.return_value = resp
    return op


class ChallengeTests(unittest.TestCase):
    def test_md5_refused_by_default(self):
        a = fritz_auth.FritzAuth("http://fritz.box", "u", "p")
        a._opener = challenge_opener("1234abcd")
        with self.assertRaises(fritz_auth.AuthError) as cm:
            a.get_sid()
        self.assertIn("legacy MD5", str(cm.exception))
        self.assertEqual(a._opener.open.call_count, 1)      # no login request was sent

    def test_md5_accepted_with_switch(self):
        a = fritz_auth.FritzAuth("http://fritz.box", "u", "p", allow_legacy_md5=True)
        a._opener = FakeOpener(GOOD)
        self.assertEqual(a.get_sid(), GOOD)

    def test_pbkdf2_iterations_validated(self):
        for it in (0, 10_000_001, 2 ** 40):
            a = fritz_auth.FritzAuth("http://fritz.box", "u", "p")
            a._opener = challenge_opener(f"2${it}$aabb$1$ccdd")
            with self.assertRaises(fritz_auth.AuthError) as cm:
                a.get_sid()
            self.assertNotIn("aabb", str(cm.exception))
            self.assertEqual(a._opener.open.call_count, 1)
        a = fritz_auth.FritzAuth("http://fritz.box", "u", "p")
        a._opener = challenge_opener("2$1$aabb$-5$ccdd")
        with self.assertRaises(fritz_auth.AuthError):
            a.get_sid()


if __name__ == "__main__":
    unittest.main()
