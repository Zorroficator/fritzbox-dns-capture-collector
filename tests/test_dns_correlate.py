import unittest

import helpers as h
from correlate import Correlator
from dnsparse import DnsError, parse_message
from netparse import Packet

C, S = "192.168.1.5", "192.168.1.1"


def pk(src, dst, sp, dp, payload):
    return Packet(src, dst, sp, dp, "aa:bb", "cc:dd", "udp", payload)


def feed(corr, ts, payload, query=True, port=40000):
    msg = parse_message(payload)
    p = pk(C, S, port, 53, payload) if query else pk(S, C, 53, port, payload)
    return corr.feed(ts, p, msg)


def a(ip):
    return h.rr(1, bytes(int(x) for x in ip.split(".")))


class DnsTests(unittest.TestCase):
    def test_compression_and_name(self):
        m = parse_message(h.dns_response(7, "WWW.Example.ORG", 1, answers=[a("1.2.3.4")]))
        self.assertEqual(m.qname, "www.example.org")
        self.assertEqual(m.addrs, ["1.2.3.4"])
        self.assertEqual(m.qr, 1)

    def test_compression_loop(self):
        hdr = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        with self.assertRaises(DnsError):
            parse_message(hdr + b"\xc0\x0c" + b"\x00\x01\x00\x01")  # pointer to itself
        with self.assertRaises(DnsError):
            parse_message(hdr + b"\xc0\x20" + b"\x00\x01\x00\x01")  # forward pointer

    def test_truncated(self):
        with self.assertRaises(DnsError):
            parse_message(b"\x00\x01")

    def test_blocked_cname_chain(self):
        cn = h.rr(5, h.name_bytes("sink.local"))
        resp = h.dns_response(1, "ads.example", 1, answers=[cn, h.rr(1, b"\x00\x00\x00\x00", name=h.name_bytes("sink.local"))])
        c = Correlator()
        feed(c, 1.0, h.dns_query(1, "ads.example"))
        ev = feed(c, 1.01, resp, query=False)
        self.assertEqual(ev[0]["status"], "blocked")
        self.assertAlmostEqual(ev[0]["latency_ms"], 10.0, places=0)
        self.assertEqual(ev[0]["client_mac"], "aa:bb")

    def test_blocked_aaaa(self):
        c = Correlator()
        feed(c, 1.0, h.dns_query(2, "ads.example", 28))
        ev = feed(c, 1.1, h.dns_response(2, "ads.example", 28, answers=[h.rr(28, bytes(16))]), query=False)
        self.assertEqual((ev[0]["status"], ev[0]["qtype"]), ("blocked", "AAAA"))

    def test_blocked_box_nodata_https(self):
        c = Correlator()
        feed(c, 1.0, h.dns_query(6, "ads.example", 65))
        ev = feed(c, 1.1, h.dns_response(6, "ads.example", 65), query=False)  # NOERROR, 0/0
        self.assertEqual((ev[0]["status"], ev[0]["reply"]), ("blocked", "blocked"))

    def test_truncated_nodata_not_blocked(self):
        c = Correlator()
        feed(c, 1.0, h.dns_query(8, "tc.example", 65))
        resp = bytearray(h.dns_response(8, "tc.example", 65))
        resp[2] |= 0x02  # TC-Bit
        ev = feed(c, 1.1, bytes(resp), query=False)
        self.assertEqual(ev[0]["status"], "allowed")

    def test_nodata_with_soa_is_allowed(self):
        c = Correlator()
        feed(c, 1.0, h.dns_query(7, "ok.example", 65))
        soa = h.rr(6, b"\x00" * 22)
        ev = feed(c, 1.1, h.dns_response(7, "ok.example", 65, authority=[soa]), query=False)
        self.assertEqual((ev[0]["status"], ev[0]["reply"]), ("allowed", "nodata"))

    def test_orphan_response_counter(self):
        c = Correlator()
        feed(c, 1.0, h.dns_response(9, "o.example", answers=[a("1.1.1.1")]), query=False)
        self.assertEqual(c.counters["orphan_responses"], 1)

    def test_allowed_nxdomain_error(self):
        for rcode, ans, want in [(0, [a("8.8.8.8")], "allowed"), (3, [], "nxdomain"), (2, [], "error")]:
            c = Correlator()
            feed(c, 1.0, h.dns_query(3, "x.example"))
            ev = feed(c, 1.1, h.dns_response(3, "x.example", rcode=rcode, answers=ans), query=False)
            self.assertEqual(ev[0]["status"], want)
            self.assertEqual(ev[0]["rcode"], rcode)

    def test_no_answer_after_10s(self):
        c = Correlator()
        feed(c, 100.0, h.dns_query(4, "slow.example"))
        self.assertEqual(c.tick(109.9), [])
        ev = c.tick(110.0)
        self.assertEqual(ev[0]["status"], "no_answer")
        self.assertIsNone(ev[0]["latency_ms"])
        self.assertEqual(c.pending, 0)

    def test_retransmit_within_2s(self):
        c = Correlator()
        feed(c, 1.0, h.dns_query(5, "r.example"))
        feed(c, 1.5, h.dns_query(5, "r.example"))
        self.assertEqual(c.pending, 1)
        self.assertEqual(c.counters["retransmits"], 1)
        ev = feed(c, 1.6, h.dns_response(5, "r.example", answers=[a("1.1.1.1")]), query=False)
        self.assertEqual(len(ev), 1)

    def test_orphan_and_limit(self):
        c = Correlator(max_open=3)
        feed(c, 1.0, h.dns_response(9, "o.example", answers=[a("1.1.1.1")]), query=False)
        self.assertEqual(c.counters["orphan_responses"], 1)
        for i in range(5):
            feed(c, 2.0 + i * 0.001, h.dns_query(i, "d.example"))
        self.assertEqual(c.pending, 3)
        self.assertEqual(c.counters["dropped"], 2)


if __name__ == "__main__":
    unittest.main()
