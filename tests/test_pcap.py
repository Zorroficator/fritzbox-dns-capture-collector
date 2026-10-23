import unittest

import helpers as h
from pcap import PcapError, PcapReader


class PcapTests(unittest.TestCase):
    def _stream(self, magic, end, avm=False, link=1):
        return (h.pcap_global(magic, end, link) +
                h.pcap_record(100, 500000, b"abc", end, avm) +
                h.pcap_record(101, 0, b"defgh", end, avm))

    def test_variants(self):
        for magic, end, avm in [(0xA1B2C3D4, "<", False), (0xA1B2C3D4, ">", False),
                                (0xA1B2CD34, "<", True), (0xA1B2CD34, ">", True),
                                (0xA1B23C4D, "<", False)]:
            # the magic is written in the file's byte order
            r = PcapReader()
            recs = r.feed(self._stream(magic, end, avm))
            self.assertEqual([x[2] for x in recs], [b"abc", b"defgh"], (hex(magic), end))
            self.assertEqual(r.linktype, 1)
        r = PcapReader()
        recs = r.feed(self._stream(0xA1B2C3D4, "<"))
        self.assertAlmostEqual(recs[0][0], 100.5)

    def test_nano(self):
        r = PcapReader()
        recs = r.feed(h.pcap_global(0xA1B23C4D, "<") + h.pcap_record(1, 500000000, b"x"))
        self.assertAlmostEqual(recs[0][0], 1.5)
        self.assertEqual(r.magic_name, "pcap-ns-le")

    def test_incremental_small_pieces(self):
        data = self._stream(0xA1B2CD34, "<", avm=True)
        r = PcapReader()
        out = []
        for i in range(0, len(data), 3):
            out += r.feed(data[i:i + 3])
        self.assertEqual([x[2] for x in out], [b"abc", b"defgh"])

    def test_linktype_mask(self):
        r = PcapReader()
        r.feed(h.pcap_global(0xA1B2C3D4, "<", link=0xF0000001))
        self.assertEqual(r.linktype, 1)

    def test_too_large(self):
        import struct
        r = PcapReader()
        r.feed(h.pcap_global())
        with self.assertRaises(PcapError):
            r.feed(struct.pack("<IIII", 1, 0, 300 * 1024, 300 * 1024))

    def test_bad_magic(self):
        with self.assertRaises(PcapError):
            PcapReader().feed(b"<html>" + b"x" * 40)


if __name__ == "__main__":
    unittest.main()
