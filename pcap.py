"""Incremental pcap reader (standard, nanosecond variant, AVM 'modified pcap')."""
import struct

MAX_RECORD = 256 * 1024

# Magic (first 4 bytes as a big-endian number) -> (byte order, nano, avm, name)
_MAGICS = {
    0xA1B2C3D4: (">", False, False, "pcap-be"),
    0xD4C3B2A1: ("<", False, False, "pcap-le"),
    0xA1B23C4D: (">", True, False, "pcap-ns-be"),
    0x4D3CB2A1: ("<", True, False, "pcap-ns-le"),
    0xA1B2CD34: (">", False, True, "avm-be"),
    0x34CDB2A1: ("<", False, True, "avm-le"),
}


class PcapError(Exception):
    pass


def is_magic(first4: bytes) -> bool:
    return len(first4) >= 4 and struct.unpack(">I", first4[:4])[0] in _MAGICS


class PcapReader:
    def __init__(self):
        self._buf = bytearray()
        self._hdr = False
        self._end = "<"
        self._nano = False
        self._rec_hdr = 16
        self.magic_name = None
        self.linktype = None
        self.snaplen = None

    def feed(self, data: bytes) -> list:
        """Return a list of (ts, orig_len, frame_bytes) for all complete records."""
        self._buf += data
        out = []
        if not self._hdr:
            if len(self._buf) < 24:
                return out
            m = struct.unpack(">I", self._buf[:4])[0]
            if m not in _MAGICS:
                raise PcapError("no pcap magic")
            self._end, self._nano, avm, self.magic_name = _MAGICS[m]
            self._rec_hdr = 24 if avm else 16
            _, _, _, _, self.snaplen, link = struct.unpack(self._end + "HHiIII", self._buf[4:24])
            self.linktype = link & 0x0FFFFFFF
            del self._buf[:24]
            self._hdr = True
        div = 1e9 if self._nano else 1e6
        fmt = self._end + "IIII"
        pos = 0
        buf = self._buf
        while len(buf) - pos >= self._rec_hdr:
            sec, frac, incl, orig = struct.unpack_from(fmt, buf, pos)
            if incl > MAX_RECORD:
                raise PcapError("pcap out of sync (record length too large)")
            start = pos + self._rec_hdr
            if len(buf) - start < incl:
                break
            out.append((sec + frac / div, orig, bytes(buf[start:start + incl])))
            pos = start + incl
        if pos:
            del buf[:pos]
        return out
