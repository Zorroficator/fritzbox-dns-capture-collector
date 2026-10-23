import unittest

import helpers as h
from netparse import parse_frame

DNS = h.dns_query(1, "example.org")


class NetTests(unittest.TestCase):
    def udp4(self, **kw):
        return h.eth(h.ipv4("192.168.1.5", "192.168.1.1", 17, h.udp(40000, 53, DNS)), **kw)

    def test_plain(self):
        p, r = parse_frame(self.udp4())
        self.assertIsNone(r)
        self.assertEqual((p.src_ip, p.dst_ip, p.src_port, p.dst_port, p.proto),
                         ("192.168.1.5", "192.168.1.1", 40000, 53, "udp"))
        self.assertEqual(p.src_mac, "02:00:00:00:00:01")
        self.assertEqual(p.payload, DNS)

    def test_vlan_and_double(self):
        for v in [(0x8100,), (0x88A8, 0x8100)]:
            p, _ = parse_frame(self.udp4(vlans=v))
            self.assertEqual(p.payload, DNS)

    def test_padding(self):
        p, _ = parse_frame(self.udp4() + b"\x00" * 10)
        self.assertEqual(p.payload, DNS)

    def test_fragment(self):
        f = h.eth(h.ipv4("1.1.1.1", "2.2.2.2", 17, h.udp(1, 53, DNS), flags_frag=0x2000))
        self.assertEqual(parse_frame(f), (None, "fragment"))
        f = h.eth(h.ipv4("1.1.1.1", "2.2.2.2", 17, h.udp(1, 53, DNS), flags_frag=0x0010))
        self.assertEqual(parse_frame(f), (None, "fragment"))

    def test_ipv6_ext_header(self):
        s = bytes([0xFE, 0x80] + [0] * 14)
        d = bytes([0x20, 0x01] + [0] * 13 + [1])
        hbh = bytes([17, 0]) + b"\x00" * 6      # hop-by-hop -> UDP
        frame = h.eth(h.ipv6(s, d, 0, hbh + h.udp(5000, 53, DNS)), etype=0x86DD)
        p, r = parse_frame(frame)
        self.assertIsNone(r)
        self.assertEqual(p.payload, DNS)
        self.assertEqual(p.src_ip, "fe80::")

    def test_ipv6_fragment_skipped(self):
        s = d = bytes(16)
        frag = bytes([17, 0, 0x00, 0x08, 0, 0, 0, 1])  # offset 1
        frame = h.eth(h.ipv6(s, d, 44, frag + b"x" * 8), etype=0x86DD)
        self.assertEqual(parse_frame(frame), (None, "fragment"))

    def test_truncated(self):
        full = self.udp4()
        for n in (5, 14, 20, 30, len(full) - 3):
            p, r = parse_frame(full[:n])
            self.assertIsNone(p)
            self.assertEqual(r, "truncated")

    def test_tcp53_marked(self):
        import struct
        tcp = struct.pack(">HH", 40000, 53) + b"\x00" * 16
        p, _ = parse_frame(h.eth(h.ipv4("1.1.1.1", "2.2.2.2", 6, tcp)))
        self.assertEqual(p.proto, "tcp")
        self.assertEqual(p.payload, b"")

    def test_garbage_never_raises(self):
        for n in range(0, 80):
            parse_frame(bytes(range(n)))


if __name__ == "__main__":
    unittest.main()
