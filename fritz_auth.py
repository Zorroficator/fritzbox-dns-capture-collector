"""SID login and connection helpers for the FRITZ!Box web interface (stdlib only).

Implements the challenge/response login of ``login_sid.lua``:
PBKDF2-HMAC-SHA256 ("2$..." challenge, FRITZ!OS >= 7.24). The weaker MD5
login of older firmware is only used with ``allow_legacy_md5=True``, because
over plain http an attacker in the network could otherwise force it by
sending a challenge without "2$". The password is never logged.

Transport security: plain ``http://`` is allowed (LAN); ``https://`` is only
accepted together with a certificate pin (``pin_sha256``) and/or a trusted
certificate file (``ca_file``). There is no silent fallback to http and
certificate verification cannot be switched off without a pin.
"""
from __future__ import annotations

import functools
import hashlib
import hmac
import http.client
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

_SID_NULL = "0000000000000000"
_MAX_LOGIN_BYTES = 65536
_MAX_PBKDF2_ITER = 10_000_000   # a hostile challenge must not pin the CPU for minutes


class AuthError(Exception):
    """Raised when logging in to the FRITZ!Box finally fails."""


class LoginRejected(AuthError):
    """The box answered, but rejected the user name / password."""


class CertPinError(OSError):
    """The certificate presented by the box does not match the configured pin."""


def normalize_pin(pin: str) -> str:
    """Return the SHA-256 pin as 64 lowercase hex digits (colons/spaces allowed)."""
    clean = re.sub(r"[\s:]", "", str(pin or "")).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", clean):
        raise ValueError("pin_sha256 must be 64 hex digits (SHA-256 of the DER certificate)")
    return clean


def check_transport(scheme: str, pin_sha256: str | None, ca_file: str | None) -> str:
    """Validate the scheme/pin/ca_file combination; return the normalized pin ('' if none)."""
    if scheme not in ("http", "https"):
        raise ValueError("box_url must start with http:// or https://")
    pin = normalize_pin(pin_sha256) if pin_sha256 else ""
    if scheme == "https" and not pin and not ca_file:
        raise ValueError("https needs pin_sha256 and/or ca_file (no unverified connections)")
    return pin


def _split_url(box_url: str) -> tuple[str, str, int | None]:
    parts = urllib.parse.urlsplit(box_url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("box_url must look like http://fritz.box or https://host")
    try:
        port = parts.port
    except ValueError:
        raise ValueError("box_url has an invalid port") from None
    return parts.scheme, parts.hostname, port


def make_ssl_context(pin: str, ca_file: str | None) -> ssl.SSLContext:
    """TLS context: verified against ``ca_file`` if given, else pin-only (no CA check)."""
    if ca_file:
        return ssl.create_default_context(cafile=ca_file)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False       # the pin is the trust anchor (self-signed box certificate)
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that checks the SHA-256 of the DER certificate after the handshake."""

    def __init__(self, *args, pin: str = "", **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._pin = pin

    def connect(self) -> None:
        super().connect()
        if not self._pin:
            return
        der = self.sock.getpeercert(binary_form=True) if self.sock is not None else None
        digest = hashlib.sha256(der).hexdigest() if der else ""
        if not hmac.compare_digest(digest, self._pin):
            try:
                self.sock.close()
            finally:
                self.sock = None
            raise CertPinError("certificate fingerprint mismatch")


def make_conn_factory(box_url: str, pin_sha256: str | None = None, ca_file: str | None = None):
    """Return ``factory(timeout) -> http.client connection`` for raw streaming requests."""
    scheme, host, port = _split_url(box_url)
    pin = check_transport(scheme, pin_sha256, ca_file)
    if scheme == "http":
        return lambda timeout: http.client.HTTPConnection(host, port or 80, timeout=timeout)
    ctx = make_ssl_context(pin, ca_file)
    return lambda timeout: PinnedHTTPSConnection(host, port or 443, timeout=timeout,
                                                 context=ctx, pin=pin)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, context: ssl.SSLContext, pin: str) -> None:
        super().__init__(context=context)
        self._ctx, self._pin = context, pin

    def https_open(self, req):
        return self.do_open(
            functools.partial(PinnedHTTPSConnection, context=self._ctx, pin=self._pin), req)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect so credentials/SID never reach another host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def build_box_opener(ca_file: str | None = None, pin_sha256: str | None = None,
                     extra_handlers: tuple = ()) -> urllib.request.OpenerDirector:
    """Opener for all requests to the box: no redirects, TLS never unverified.

    ``ca_file`` (optional) is a PEM certificate to trust for https, ``pin_sha256``
    (optional) pins the SHA-256 of the box's DER certificate. https requests
    without either are refused by ``FritzAuth``.
    """
    pin = normalize_pin(pin_sha256) if pin_sha256 else ""
    # never route box requests through an environment proxy (credentials, SID, LAN host)
    handlers: list = [urllib.request.ProxyHandler({}), _NoRedirect()]
    if pin or ca_file:
        handlers.append(_PinnedHTTPSHandler(make_ssl_context(pin, ca_file), pin))
    handlers.extend(extra_handlers)
    return urllib.request.build_opener(*handlers)


class FritzAuth:
    """Manages the SID lifecycle for one FRITZ!Box."""

    def __init__(self, box_url: str, username: str, password: str,
                 timeout: float = 10.0, ca_file: str | None = None,
                 pin_sha256: str | None = None, allow_legacy_md5: bool = False) -> None:
        scheme, _host, _port = _split_url(box_url)
        check_transport(scheme, pin_sha256, ca_file)
        self._base = box_url.rstrip("/")
        self._username = username
        self._password = password
        self._timeout = timeout
        self._allow_md5 = allow_legacy_md5
        self._opener = build_box_opener(ca_file, pin_sha256)
        self._sid = _SID_NULL

    def get_sid(self) -> str:
        """Force a fresh login and return the new SID."""
        sid = self._fetch_sid()
        self._sid = sid
        return sid

    @property
    def opener(self) -> urllib.request.OpenerDirector:
        return self._opener

    def _read_xml(self, req) -> ET.Element:
        with self._opener.open(req, timeout=self._timeout) as resp:
            return ET.fromstring(resp.read(_MAX_LOGIN_BYTES))

    def _fetch_sid(self) -> str:
        try:
            root = self._read_xml(f"{self._base}/login_sid.lua?version=2")
        except (urllib.error.URLError, OSError, ET.ParseError) as exc:
            raise AuthError(f"FRITZ!Box not reachable: {type(exc).__name__}") from exc

        sid_el = root.find("SID")
        if sid_el is None or not sid_el.text:
            raise AuthError("Invalid login response: <SID> missing")
        if sid_el.text != _SID_NULL:
            return sid_el.text  # session already active

        challenge_el = root.find("Challenge")
        if challenge_el is None or not challenge_el.text:
            raise AuthError("Invalid login response: <Challenge> missing")
        challenge = challenge_el.text

        if challenge.startswith("2$"):
            parts = challenge.split("$")
            if len(parts) < 5:
                raise AuthError("Malformed PBKDF2 challenge")
            try:
                iter1, salt1 = int(parts[1]), bytes.fromhex(parts[2])
                iter2, salt2 = int(parts[3]), bytes.fromhex(parts[4])
            except ValueError as exc:
                raise AuthError("Malformed PBKDF2 challenge") from exc
            if not (1 <= iter1 <= _MAX_PBKDF2_ITER and 1 <= iter2 <= _MAX_PBKDF2_ITER):
                raise AuthError("PBKDF2 challenge has an implausible iteration count")
            hash1 = hashlib.pbkdf2_hmac("sha256", self._password.encode(), salt1, iter1)
            hash2 = hashlib.pbkdf2_hmac("sha256", hash1, salt2, iter2)
            response = f"{parts[4]}${hash2.hex()}"
        else:
            if not self._allow_md5:
                raise AuthError("legacy MD5 challenge refused (set allow_legacy_md5 = true "
                                "to accept it from firmware older than FRITZ!OS 7.24)")
            raw = f"{challenge}-{self._password}".encode("utf-16le")
            response = f"{challenge}-{hashlib.md5(raw).hexdigest()}"  # legacy firmware

        data = urllib.parse.urlencode(
            {"username": self._username, "response": response}).encode()
        try:
            root = self._read_xml(
                urllib.request.Request(f"{self._base}/login_sid.lua", data=data))
        except (urllib.error.URLError, OSError, ET.ParseError) as exc:
            raise AuthError(f"Login request failed: {type(exc).__name__}") from exc

        sid_el = root.find("SID")
        if sid_el is None or not sid_el.text:
            raise AuthError("Invalid login response: <SID> missing")
        if sid_el.text == _SID_NULL:
            raise LoginRejected("Login failed - check user name and password")
        return sid_el.text
