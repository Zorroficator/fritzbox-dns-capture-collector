"""Device names: optional TR-064 host list of the box plus a user-defined alias table.

Privacy: names, IPs and MACs are never logged.
"""
from __future__ import annotations

import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

import fritz_auth

_SERVICE = "urn:dslforum-org:service:Hosts:1"
_CONTROL = "/upnp/control/hosts"
_MAX_BYTES = 8 * 1024 * 1024
_SOAP = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
    's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
    '<s:Body><u:X_AVM-DE_GetHostListPath xmlns:u="' + _SERVICE + '"/></s:Body></s:Envelope>'
)


class HostMap:
    def __init__(self, aliases=None):
        self.aliases = {str(k).strip().lower(): v for k, v in (aliases or {}).items() if v}
        self.by_ip = {}
        self.by_mac = {}
        self.nat_macs = set()
        self.errors = 0
        self.loaded = False

    def update(self, hosts) -> None:
        by_ip, mac_names = {}, {}
        for h in hosts:
            ip, mac, name = h.get("ip", ""), (h.get("mac") or "").lower(), h.get("hostname", "")
            if ip and ":" not in ip and name:
                by_ip[ip] = name
            if mac and ip and ":" not in ip and name:
                mac_names.setdefault(mac, set()).add(name)
        by_mac, nat = {}, set()
        for mac, names in mac_names.items():
            if len(names) > 1:          # repeater with MAC NAT: do not map the MAC
                nat.add(mac)
            else:
                by_mac[mac] = next(iter(names))
        for h in hosts:                  # hosts without IPv4: MAC + name only
            mac, name = (h.get("mac") or "").lower(), h.get("hostname", "")
            if mac and name and mac not in nat and mac not in by_mac and mac not in mac_names:
                by_mac[mac] = name
        self.by_ip, self.by_mac, self.nat_macs = by_ip, by_mac, nat
        self.loaded = True

    def name_for(self, ip, mac) -> str:
        """Alias (IP, then MAC) > host list (IP, then MAC) > raw IP/MAC."""
        m = (mac or "").lower()
        if ip and ip.lower() in self.aliases:
            return self.aliases[ip.lower()]
        if m and m not in self.nat_macs and m in self.aliases:
            return self.aliases[m]
        if ip and ":" not in ip and ip in self.by_ip:
            return self.by_ip[ip]
        if m and m not in self.nat_macs and m in self.by_mac:
            return self.by_mac[m]
        return ip or mac or "?"

    def refresh(self, fetch) -> bool:
        """fetch() -> host list. On failure keep the old mapping and count the error."""
        try:
            self.update(fetch())
            return True
        except Exception:
            self.errors += 1
            return False


def parse_hostlist(xml_bytes: bytes) -> list:
    """Parse the box's host list XML -> [{"ip", "mac", "hostname"}, ...]."""
    root = ET.fromstring(xml_bytes)
    out = []
    for item in root.iter("Item"):
        out.append({"ip": (item.findtext("IPAddress") or "").strip(),
                    "mac": (item.findtext("MACAddress") or "").strip(),
                    "hostname": (item.findtext("HostName") or "").strip()})
    return out


def parse_hostlist_path(soap_bytes: bytes) -> str:
    root = ET.fromstring(soap_bytes)
    for el in root.iter():
        if el.tag.endswith("NewX_AVM-DE_HostListPath") and el.text and el.text.startswith("/"):
            return el.text.strip()
    raise ValueError("no host list path in TR-064 answer")


def make_fetch(cfg: dict, get_credentials):
    """Return ``fetch() -> host list`` using TR-064 with the capture user.

    ``get_credentials()`` -> (user, password). TR-064 listens on port 49000 (http)
    or 49443 (https); https uses the same pin / CA file as the capture.
    """
    parts = urllib.parse.urlsplit(cfg["box_url"])
    scheme = parts.scheme
    host = f"[{parts.hostname}]" if ":" in (parts.hostname or "") else parts.hostname
    base = f"{scheme}://{host}:{49443 if scheme == 'https' else 49000}"
    pin, ca_file = cfg.get("pin_sha256") or None, cfg.get("ca_file") or None
    timeout = float(cfg["timeout_seconds"])
    fritz_auth.check_transport(scheme, pin, ca_file)

    def fetch():
        user, password = get_credentials()
        mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        mgr.add_password(None, base, user, password)
        opener = fritz_auth.build_box_opener(
            ca_file, pin, (urllib.request.HTTPDigestAuthHandler(mgr),))
        req = urllib.request.Request(
            base + _CONTROL, data=_SOAP.encode("utf-8"),
            headers={"Content-Type": 'text/xml; charset="utf-8"',
                     "SoapAction": _SERVICE + "#X_AVM-DE_GetHostListPath"})
        with opener.open(req, timeout=timeout) as resp:
            path = parse_hostlist_path(resp.read(65536))
        with opener.open(base + path, timeout=timeout) as resp:
            return parse_hostlist(resp.read(_MAX_BYTES))
    return fetch
