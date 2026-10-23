"""DNS messages: header, first question, answers (A/AAAA/CNAME)."""
import ipaddress
import struct
from dataclasses import dataclass, field

MAX_JUMPS = 10
QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
          28: "AAAA", 33: "SRV", 64: "SVCB", 65: "HTTPS", 255: "ANY"}


class DnsError(Exception):
    pass


@dataclass
class DnsMessage:
    txid: int
    qr: int
    rcode: int
    qname: str
    qtype: int
    addrs: list = field(default_factory=list)   # A/AAAA as str
    cnames: list = field(default_factory=list)
    ancount: int = 0   # header: answer count
    tc: int = 0        # header: reply truncated
    nscount: int = 0   # header: authority count (SOA on a genuine NODATA)

    @property
    def qtype_name(self) -> str:
        return QTYPES.get(self.qtype, f"TYPE{self.qtype}")

    @property
    def blocked_answer(self) -> bool:
        """Blocked: unspecified address (0.0.0.0/::) OR box-synthesized NODATA
        (NOERROR, 0 answers, 0 authority, not truncated; genuine upstream NODATA carries a SOA)."""
        if self.qr and not self.tc and self.rcode == 0 and self.ancount == 0 and self.nscount == 0:
            return True
        return any(ipaddress.ip_address(a).is_unspecified for a in self.addrs)


def _esc_label(raw: bytes) -> str:
    """Label in RFC 1035 notation: lowercase, '.' and '\\' backslash-escaped,
    bytes outside 0x21-0x7E as \\DDD."""
    out = []
    for b in raw:
        if 0x41 <= b <= 0x5A:
            b += 32
        if b in (0x2E, 0x5C):
            out.append("\\" + chr(b))
        elif 0x21 <= b <= 0x7E:
            out.append(chr(b))
        else:
            out.append("\\%03d" % b)
    return "".join(out)


def read_name(msg: bytes, off: int):
    """-> (lowercase name without trailing dot, offset after the name in the original)."""
    labels = []
    pos = off
    end = None
    jumps = 0
    total = 0
    n = len(msg)
    while True:
        if pos >= n:
            raise DnsError("name truncated")
        ln = msg[pos]
        if ln == 0:
            pos += 1
            break
        if ln & 0xC0 == 0xC0:
            if pos + 1 >= n:
                raise DnsError("pointer truncated")
            ptr = ((ln & 0x3F) << 8) | msg[pos + 1]
            if end is None:
                end = pos + 2
            jumps += 1
            if jumps > MAX_JUMPS or ptr >= pos:
                raise DnsError("invalid name compression")
            pos = ptr
            continue
        if ln & 0xC0:
            raise DnsError("invalid label")
        if pos + 1 + ln > n:
            raise DnsError("label truncated")
        total += ln + 1
        if total > 255:
            raise DnsError("name too long")
        labels.append(_esc_label(msg[pos + 1:pos + 1 + ln]))
        pos += 1 + ln
    return ".".join(labels), (end if end is not None else pos)


def parse_message(msg: bytes) -> DnsMessage:
    if len(msg) < 12:
        raise DnsError("header truncated")
    txid, flags, qd, an, ns, _ar = struct.unpack_from(">HHHHHH", msg, 0)
    if qd < 1:
        raise DnsError("no question")
    qname, pos = read_name(msg, 12)
    if pos + 4 > len(msg):
        raise DnsError("question truncated")
    qtype = struct.unpack_from(">H", msg, pos)[0]
    pos += 4
    m = DnsMessage(txid, (flags >> 15) & 1, flags & 0xF, qname, qtype,
                   ancount=an, nscount=ns, tc=(flags >> 9) & 1)
    if not m.qr:
        return m
    # skip further questions
    try:
        for _ in range(qd - 1):
            _, pos = read_name(msg, pos)
            pos += 4
        for _ in range(min(an, 64)):
            _, pos = read_name(msg, pos)
            if pos + 10 > len(msg):
                break
            rtype, _cls, _ttl, rdlen = struct.unpack_from(">HHIH", msg, pos)
            pos += 10
            if pos + rdlen > len(msg):
                break
            if rtype == 1 and rdlen == 4:
                m.addrs.append(str(ipaddress.IPv4Address(msg[pos:pos + 4])))
            elif rtype == 28 and rdlen == 16:
                m.addrs.append(str(ipaddress.IPv6Address(msg[pos:pos + 16])))
            elif rtype == 5:
                m.cnames.append(read_name(msg, pos)[0])
            pos += rdlen
    except DnsError:
        pass  # answer section damaged: keep what was parsed so far
    return m
