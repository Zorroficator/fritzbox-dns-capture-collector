import ssl
import unittest
from unittest import mock

import helpers  # noqa: F401
import capture
import fritz_auth

BOX = "http://fritz.box"
BOXS = "https://fritz.box"


class A:
    def get_sid(self):
        return "0123456789abcdef"


class FakeConn:
    def __init__(self, exc=None):
        self.sock = mock.MagicMock()
        self.exc = exc

    def request(self, *a, **k):
        if self.exc:
            raise self.exc

    def getresponse(self):
        return mock.Mock(status=200)

    def close(self):
        pass


class QueryTests(unittest.TestCase):
    def test_query_percent20_no_plus(self):
        c = capture.Capture("http://192.0.2.1", "1-lan", A())
        c.login()
        q = c.start_query()
        self.assertIn("%20", q)
        self.assertNotIn("+", q)
        self.assertIn("filter=udp%20port%2053%20or%20tcp%20port%2053", q)
        self.assertIn("capture=Start", q)
        self.assertIn("ifaceorminor=1-lan", q)
        self.assertIn("capture=Stop", c.stop_query())

    def test_headers(self):
        c = capture.Capture(BOX + "/", auth=A())
        hd = c._headers()
        self.assertEqual(hd["Referer"], "http://fritz.box/")
        self.assertTrue(hd["User-Agent"].startswith("Mozilla/5.0"))


class LoginTests(unittest.TestCase):
    def test_login_error_hides_details(self):
        class Bad:
            def get_sid(self):
                raise RuntimeError("password=xyz")
        with self.assertRaises(capture.CaptureError) as cm:
            capture.Capture(BOX, auth=Bad()).login()
        self.assertNotIn("xyz", str(cm.exception))
        self.assertNotIsInstance(cm.exception, capture.LoginError)

    def test_login_rejected_is_login_error(self):
        class Bad:
            def get_sid(self):
                raise fritz_auth.LoginRejected("sid=SECRET")
        with self.assertRaises(capture.LoginError) as cm:
            capture.Capture(BOX, auth=Bad()).login()
        self.assertNotIn("SECRET", str(cm.exception))

    def test_other_auth_errors_are_not_login_error(self):
        class Bad:
            def get_sid(self):
                raise fritz_auth.AuthError("FRITZ!Box not reachable: URLError")
        with self.assertRaises(capture.CaptureError) as cm:
            capture.Capture(BOX, auth=Bad()).login()
        self.assertNotIsInstance(cm.exception, capture.LoginError)

    def test_same_text_in_plain_autherror_is_not_login_error(self):
        # classification is by type, never by message text
        class Bad:
            def get_sid(self):
                raise fritz_auth.AuthError("Login failed - check user name and password")
        with self.assertRaises(capture.CaptureError) as cm:
            capture.Capture(BOX, auth=Bad()).login()
        self.assertNotIsInstance(cm.exception, capture.LoginError)

    def test_pin_error_chained_in_autherror(self):
        try:
            try:
                raise fritz_auth.CertPinError("pin")
            except OSError as exc:
                raise fritz_auth.AuthError("login request failed") from exc
        except fritz_auth.AuthError as err:
            e = err

        class Bad:
            def get_sid(self):
                raise e
        c = capture.Capture(BOXS, auth=Bad(), conn_factory=lambda t: None)
        with self.assertRaises(capture.CaptureError) as cm:
            c.login()
        self.assertEqual(str(cm.exception), capture.TLS_MSG)
        self.assertNotIsInstance(cm.exception, capture.LoginError)

    def test_ssl_error_is_not_login_error(self):
        class Bad:
            def get_sid(self):
                raise ssl.SSLError("x")
        with self.assertRaises(capture.CaptureError) as cm:
            capture.Capture(BOXS, auth=Bad(), conn_factory=lambda t: None).login()
        self.assertNotIsInstance(cm.exception, capture.LoginError)
        self.assertEqual(str(cm.exception), capture.TLS_MSG)

    def test_has_ssl_error_cycle_safe(self):
        a, b = RuntimeError("a"), RuntimeError("b")
        a.__cause__, b.__cause__ = b, a
        self.assertFalse(capture._has_ssl_error(a))

    def test_block_time(self):
        class C:
            def request(self, *a, **k):
                pass

            def getresponse(self):
                return mock.Mock(read=lambda n: b"<SessionInfo><SID>000</SID><BlockTime>42</BlockTime></SessionInfo>")

            def close(self):
                pass
        self.assertEqual(capture.Capture(BOX, conn_factory=lambda t: C()).block_time(), 42)

        def boom(t):
            raise OSError("x")
        self.assertEqual(capture.Capture(BOX, conn_factory=boom).block_time(), 0)


class TransportTests(unittest.TestCase):
    def test_https_without_factory_refused(self):
        with self.assertRaises(ValueError):
            capture.Capture(BOXS, auth=A())

    def test_https_uses_factory_and_https_referer(self):
        conns = []

        def fac(timeout):
            conns.append((FakeConn(), timeout))
            return conns[-1][0]
        c = capture.Capture(BOXS, auth=A(), conn_factory=fac)
        c.open()
        self.assertEqual(conns[0][1], 30)
        conns[0][0].sock.settimeout.assert_called_with(150)
        self.assertTrue(c._headers()["Referer"].startswith("https://"))

    def test_pin_mismatch_message(self):
        for exc in (ssl.SSLError("x-secret"), fritz_auth.CertPinError("fp=abc")):
            c = capture.Capture(BOXS, auth=A(), conn_factory=lambda t, e=exc: FakeConn(e))
            with self.assertRaises(capture.CaptureError) as cm:
                c.open()
            self.assertEqual(str(cm.exception), capture.TLS_MSG)

    def test_get_page_and_open_pin_error(self):
        def make(timeout):
            raise fritz_auth.CertPinError("pin")
        c = capture.Capture(BOXS, conn_factory=make)
        c._sid = "x"
        with self.assertRaises(capture.CaptureError) as cm:
            c.get_page("/p")
        self.assertEqual(str(cm.exception), capture.TLS_MSG)
        with self.assertRaises(capture.CaptureError) as cm:
            c.open()
        self.assertEqual(str(cm.exception), capture.TLS_MSG)

    def test_errno_in_message(self):
        c = capture.Capture(BOX, auth=A(), conn_factory=lambda t: FakeConn(OSError(65, "No route 192.0.2.7")))
        with self.assertRaises(capture.CaptureError) as cm:
            c.open()
        self.assertIn("OSError errno 65", str(cm.exception))
        self.assertNotIn("192.0.2.7", str(cm.exception))

    def test_abort_between_login_and_connect(self):
        c = capture.Capture(BOX, auth=A(), conn_factory=lambda t: self.fail("connected"))
        c.abort()
        with self.assertRaises(capture.CaptureError):
            c.open()

    def test_non_200_status(self):
        class C(FakeConn):
            def getresponse(self):
                return mock.Mock(status=403)
        c = capture.Capture(BOX, auth=A(), conn_factory=lambda t: C())
        with self.assertRaises(capture.CaptureError) as cm:
            c.open()
        self.assertIn("HTTP 403", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
