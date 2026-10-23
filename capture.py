"""Packet capture on the FRITZ!Box via /cgi-bin/capture_notimeout.

This is an undocumented AVM endpoint; behavior may change with firmware updates.

Privacy: the SID and URLs are never logged or copied into error messages.
"""
import http.client
import logging
import re
import socket
import ssl
import urllib.parse

import fritz_auth
import pcap

USER_AGENT = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")
log = logging.getLogger("ftrap_dns")
CGI = "/cgi-bin/capture_notimeout"
FILTER = "udp port 53 or tcp port 53"


TLS_MSG = "TLS certificate check failed (fingerprint or CA mismatch)"


class CaptureError(Exception):
    """Capture failure. ``code`` is a short stable identifier (see docs/dns_contract.md)."""
    code = "capture_failed"

    def __init__(self, message="", code=None):
        super().__init__(message)
        if code:
            self.code = code


class LoginError(CaptureError):
    """Credentials rejected (not: box unreachable, pin mismatch)."""
    code = "auth_failed"


LOGIN_MSG = "Login rejected (check user name and password)"


def describe_exc(exc) -> str:
    """Type + errno (no addresses/texts), e.g. 'OSError errno 65'."""
    num = getattr(exc, "errno", None) if isinstance(exc, OSError) else None
    return f"{type(exc).__name__} errno {num}" if num else type(exc).__name__


def set_keepalive(sock) -> None:
    """SO_KEEPALIVE + TCP keepalive idle time of 30 s; errors are ignored."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        opt = getattr(socket, "TCP_KEEPALIVE", None) or getattr(socket, "TCP_KEEPIDLE", 0x10)
        sock.setsockopt(socket.IPPROTO_TCP, opt, 30)
    except (OSError, AttributeError):
        pass


def _has_ssl_error(exc) -> bool:
    """True if the cause chain contains an SSLError or CertPinError (pin mismatch)."""
    e, seen = exc, set()
    while e is not None and id(e) not in seen and len(seen) < 10:
        seen.add(id(e))
        if isinstance(e, (ssl.SSLError, fritz_auth.CertPinError)):
            return True
        e = e.__cause__ or e.__context__ or getattr(e, "reason", None)
    return False


def build_query(params: dict) -> str:
    # %20 instead of '+': with '+' the box delivers no stream
    return urllib.parse.urlencode(params, quote_via=urllib.parse.quote)


class Capture:
    def __init__(self, box_url, iface="1-lan", auth=None, idle_timeout=150, snaplen=1600,
                 conn_factory=None, connect_timeout=30):
        self.box_url = box_url.rstrip("/")
        self.scheme = urllib.parse.urlsplit(self.box_url).scheme.lower()
        self.connect_timeout = connect_timeout
        # conn_factory(timeout) -> connected or connectable HTTP(S) connection. For https it
        # MUST verify the certificate (see fritz_auth.make_conn_factory); there is no silent
        # fallback to http.
        if conn_factory is None:
            if self.scheme != "http":
                raise ValueError("https needs a verifying connection factory "
                                 "(fritz_auth.make_conn_factory)")
            conn_factory = fritz_auth.make_conn_factory(self.box_url)
        self._factory = conn_factory
        self.iface = iface
        self.auth = auth
        self.idle_timeout = idle_timeout
        self.snaplen = snaplen
        self.status = None
        self.first_bytes = b""
        self._sid = None
        self._conn = None
        self._resp = None
        self._started = False
        self._sock = None
        self._aborted = False

    def _headers(self):
        return {"User-Agent": USER_AGENT, "Referer": self.box_url + "/"}

    def login(self) -> str:
        if self._sid is None:
            try:
                self._sid = self.auth.get_sid()
            except Exception as exc:
                if isinstance(exc, fritz_auth.LoginRejected):
                    raise LoginError(LOGIN_MSG) from None
                if _has_ssl_error(exc):
                    raise CaptureError(TLS_MSG, "tls_error") from None
                raise CaptureError("Login to the FRITZ!Box failed", "login_failed") from None
        return self._sid

    def block_time(self) -> int:
        """Remaining login block time (s) reported by the box, without credentials. Any error -> 0."""
        conn = None
        try:
            conn = self._factory(5)
            conn.request("GET", "/login_sid.lua?version=2", headers=self._headers())
            body = conn.getresponse().read(65536).decode("utf-8", "replace")
            m = re.search(r"<BlockTime>\s*(\d{1,6})\s*</BlockTime>", body)
            return int(m.group(1)) if m else 0
        except Exception:
            return 0
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    def start_query(self) -> str:
        return build_query({"sid": self._sid, "capture": "Start", "snaplen": self.snaplen,
                            "filter": FILTER, "ifaceorminor": self.iface})

    def stop_query(self) -> str:
        return build_query({"sid": self._sid, "capture": "Stop", "ifaceorminor": self.iface})

    def get_page(self, path: str, timeout=10) -> str:
        """Fetch a page with the SID (e.g. /html/capture.html)."""
        self.login()
        conn = None
        try:
            conn = self._factory(timeout)
            conn.request("GET", path + "?" + build_query({"sid": self._sid}), headers=self._headers())
            r = conn.getresponse()
            return r.read(1 << 20).decode("utf-8", "replace")
        except (OSError, ValueError, http.client.HTTPException) as exc:
            if _has_ssl_error(exc):
                raise CaptureError(TLS_MSG, "tls_error") from None
            raise CaptureError("page not retrievable", "page_error") from None
        finally:
            if conn is not None:
                conn.close()

    def open(self) -> None:
        self.login()
        if self._aborted:
            raise CaptureError("capture aborted", "aborted")
        # Short timeout for connect/getresponse, then the idle timeout for the blocking
        # reads (no poll timeout: a socket timeout poisons SocketIO, later reads raise
        # OSError). Keep the socket beforehand: conn.sock is often None after getresponse().
        try:
            self._conn = self._factory(self.connect_timeout)
            if self._conn.sock is None:
                self._conn.connect()
            self._sock = self._conn.sock
            set_keepalive(self._sock)
            self._conn.request("GET", CGI + "?" + self.start_query(), headers=self._headers())
            self._started = True
            self._resp = self._conn.getresponse()
            self._sock.settimeout(self.idle_timeout)
        except (OSError, ValueError, http.client.HTTPException) as exc:
            if self._aborted:
                raise CaptureError("capture aborted", "aborted") from None
            if _has_ssl_error(exc):
                raise CaptureError(TLS_MSG, "tls_error") from None
            raise CaptureError(f"capture start failed ({describe_exc(exc)})", "connect_failed") from None
        self.status = self._resp.status
        if self.status != 200:
            raise CaptureError(f"capture start: HTTP {self.status}", "http_error")

    def abort(self) -> None:
        """Thread-safe: ends reading (normal end, not an error)."""
        self._aborted = True
        sock = self._sock
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def chunks(self):
        """Generator of byte chunks. Ends at EOF or abort(); raises on idle time
        > idle_timeout, a non-pcap stream or an empty stream."""
        if self._resp is None:
            raise CaptureError("capture not opened")
        head = b""
        while True:
            try:
                data = self._resp.read1(65536)
            except (OSError, http.client.HTTPException) as exc:
                if self._aborted or isinstance(exc, http.client.IncompleteRead):
                    return
                if isinstance(exc, (socket.timeout, TimeoutError)):
                    raise CaptureError("idle timeout in capture stream", "idle_timeout") from None
                raise CaptureError(f"read error in capture stream ({describe_exc(exc)})", "read_error") from None
            if not data:
                if self._aborted:
                    return
                if not head:
                    raise CaptureError("Empty stream - probably another capture is running", "capture_busy")
                if not self.first_bytes:
                    self.first_bytes = head[:16]
                    raise CaptureError("Stream ended before the pcap header", "stream_truncated")
                return
            if not self.first_bytes:
                head += data
                if len(head) < 16 and not (len(head) >= 4 and not pcap.is_magic(head)):
                    continue
                self.first_bytes = head[:16]
                if not pcap.is_magic(head[:4]):
                    raise CaptureError("Not a pcap stream (probably a login or error page)", "not_pcap")
                data = head
            yield data

    def stop(self) -> None:
        """Idempotent: send Stop (3 s), close the connection, log out."""
        started, self._started = self._started, False
        if self._conn is not None:
            try:
                self._conn.close()
            except OSError:
                pass
            self._conn = self._resp = self._sock = None
        sid = self._sid
        if sid is None:
            return
        if started:
            try:
                c = self._factory(3)
                try:
                    c.request("GET", CGI + "?" + self.stop_query(), headers=self._headers())
                    c.getresponse().read(65536)
                finally:
                    c.close()
                log.info("capture: Stop sent")
            except (OSError, ValueError, http.client.HTTPException):
                log.warning("capture: Stop failed")
        try:
            c = self._factory(3)
            try:
                body = build_query({"logout": 1, "sid": sid})
                h = dict(self._headers())
                h["Content-Type"] = "application/x-www-form-urlencoded"
                c.request("POST", "/login_sid.lua", body=body, headers=h)
                c.getresponse().read(65536)
            finally:
                c.close()
            log.info("capture: logout done")
        except (OSError, ValueError, http.client.HTTPException):
            log.warning("capture: logout failed")
        self._sid = None
