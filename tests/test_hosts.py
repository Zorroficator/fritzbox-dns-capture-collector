import unittest
from unittest import mock

import helpers  # noqa: F401
import fritz_auth
import hosts
from hosts import HostMap

SOAP = (b'<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
        b'<s:Body><u:X_AVM-DE_GetHostListPathResponse xmlns:u="urn:dslforum-org:service:Hosts:1">'
        b'<NewX_AVM-DE_HostListPath>/hosts/hostlist.xml</NewX_AVM-DE_HostListPath>'
        b'</u:X_AVM-DE_GetHostListPathResponse></s:Body></s:Envelope>')
LIST = (b'<?xml version="1.0"?><List><Item><IPAddress>192.0.2.5</IPAddress>'
        b'<MACAddress>02:00:00:00:00:01</MACAddress><HostName>laptop</HostName></Item>'
        b'<Item><IPAddress></IPAddress><MACAddress>02:00:00:00:00:02</MACAddress>'
        b'<HostName>phone</HostName></Item></List>')


class AliasTests(unittest.TestCase):
    def test_alias_wins_over_host_list(self):
        m = HostMap({"02:00:00:00:00:01": "Living room TV", "192.0.2.9": "Printer"})
        m.update([{"ip": "192.0.2.5", "mac": "02:00:00:00:00:01", "hostname": "laptop"}])
        self.assertEqual(m.name_for("192.0.2.5", "02:00:00:00:00:01"), "Living room TV")
        self.assertEqual(m.name_for("fe80::1", "02:00:00:00:00:01"), "Living room TV")
        self.assertEqual(m.name_for("192.0.2.9", ""), "Printer")

    def test_alias_case_insensitive_and_fallback(self):
        m = HostMap({"AA:BB:CC:00:00:01": "Tablet"})
        self.assertEqual(m.name_for("192.0.2.77", "aa:bb:cc:00:00:01"), "Tablet")
        self.assertEqual(m.name_for("192.0.2.77", "aa:bb:cc:00:00:02"), "192.0.2.77")
        self.assertEqual(m.name_for("", "aa:bb:cc:00:00:02"), "aa:bb:cc:00:00:02")
        self.assertEqual(m.name_for("", ""), "?")

    def test_mac_alias_ignored_for_nat_mac(self):
        m = HostMap({"02:00:00:00:00:09": "Repeater"})
        m.update([{"ip": "192.0.2.7", "mac": "02:00:00:00:00:09", "hostname": "a"},
                  {"ip": "192.0.2.8", "mac": "02:00:00:00:00:09", "hostname": "b"}])
        self.assertEqual(m.name_for("192.0.2.7", "02:00:00:00:00:09"), "a")


class ParseTests(unittest.TestCase):
    def test_parse_path_and_list(self):
        self.assertEqual(hosts.parse_hostlist_path(SOAP), "/hosts/hostlist.xml")
        got = hosts.parse_hostlist(LIST)
        self.assertEqual(got[0], {"ip": "192.0.2.5", "mac": "02:00:00:00:00:01", "hostname": "laptop"})
        self.assertEqual(got[1]["ip"], "")

    def test_path_must_be_absolute(self):
        bad = SOAP.replace(b">/hosts/", b">http://evil.example/")
        with self.assertRaises(ValueError):
            hosts.parse_hostlist_path(bad)


class FetchTests(unittest.TestCase):
    def cfg(self, **kw):
        base = {"box_url": "http://fritz.box", "pin_sha256": "", "ca_file": "", "timeout_seconds": 5}
        base.update(kw)
        return base

    def test_fetch_two_step(self):
        calls = []

        class Resp:
            def __init__(self, body):
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n=-1):
                return self.body

        class Opener:
            def open(self, req, timeout=None):
                url = req.full_url if hasattr(req, "full_url") else req
                calls.append(url)
                return Resp(SOAP if url.endswith("/upnp/control/hosts") else LIST)

        with mock.patch.object(fritz_auth, "build_box_opener", return_value=Opener()):
            fetch = hosts.make_fetch(self.cfg(), lambda: ("u", "p"))
            got = fetch()
        self.assertEqual(calls, ["http://fritz.box:49000/upnp/control/hosts",
                                 "http://fritz.box:49000/hosts/hostlist.xml"])
        self.assertEqual(got[0]["hostname"], "laptop")

    def test_https_port_and_refusal_without_pin(self):
        with self.assertRaises(ValueError):
            hosts.make_fetch(self.cfg(box_url="https://fritz.box"), lambda: ("u", "p"))
        hosts.make_fetch(self.cfg(box_url="https://fritz.box", pin_sha256="ab" * 32),
                         lambda: ("u", "p"))

    def test_ipv6_host_in_brackets(self):
        calls = []

        class Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n=-1):
                return SOAP

        class Opener:
            def open(self, req, timeout=None):
                calls.append(req.full_url if hasattr(req, "full_url") else req)
                raise OSError("stop")

        with mock.patch.object(fritz_auth, "build_box_opener", return_value=Opener()):
            fetch = hosts.make_fetch(self.cfg(box_url="http://[2001:db8::1]"), lambda: ("u", "p"))
            with self.assertRaises(OSError):
                fetch()
        self.assertEqual(calls, ["http://[2001:db8::1]:49000/upnp/control/hosts"])

    def test_refresh_counts_errors(self):
        m = HostMap()

        def bad():
            raise OSError("down")
        self.assertFalse(m.refresh(bad))
        self.assertEqual(m.errors, 1)


if __name__ == "__main__":
    unittest.main()
