"""Ethernet/VLAN/IPv4/IPv6/UDP parser. Never raises to the caller."""
import ipaddress
import struct
from dataclasses import dataclass


@dataclass
class Packet:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    src_mac: str
    dst_mac: str
    proto: str  # "udp" | "tcp"
    payload: bytes


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def parse_frame(data: bytes, linktype: int = 1):
    """-> (Packet|None, reason|None). reason: truncated, fragment, unsupported."""
    try:
        return _parse(data, linktype)
    except (struct.error, IndexError, ValueError):
        return None, "truncated"


def _parse(data, linktype):
    smac = dmac = ""
    if linktype == 1:
        if len(data) < 14:
            return None, "truncated"
        dmac, smac = _mac(data[0:6]), _mac(data[6:12])
        et = struct.unpack_from(">H", data, 12)[0]
        off = 14
        for _ in range(2):
            if et in (0x8100, 0x88A8):
                if len(data) < off + 4:
                    return None, "truncated"
                et = struct.unpack_from(">H", data, off + 2)[0]
                off += 4
        if et == 0x0800:
            return _ipv4(data, off, smac, dmac)
        if et == 0x86DD:
            return _ipv6(data, off, smac, dmac)
        return None, "unsupported"
    if linktype == 101:  # raw IP
        if not data:
            return None, "truncated"
        v = data[0] >> 4
        if v == 4:
            return _ipv4(data, 0, smac, dmac)
        if v == 6:
            return _ipv6(data, 0, smac, dmac)
    return None, "unsupported"


def _ipv4(data, off, smac, dmac):
    if len(data) < off + 20:
        return None, "truncated"
    vihl = data[off]
    ihl = (vihl & 0x0F) * 4
    if vihl >> 4 != 4 or ihl < 20:
        return None, "unsupported"
    total = struct.unpack_from(">H", data, off + 2)[0]
    flags_frag = struct.unpack_from(">H", data, off + 6)[0]
    if flags_frag & 0x2000 or flags_frag & 0x1FFF:
        return None, "fragment"
    proto = data[off + 9]
    if total < ihl or len(data) < off + total:
        return None, "truncated"
    src = str(ipaddress.IPv4Address(data[off + 12:off + 16]))
    dst = str(ipaddress.IPv4Address(data[off + 16:off + 20]))
    return _l4(data[off + ihl:off + total], proto, src, dst, smac, dmac)


def _ipv6(data, off, smac, dmac):
    if len(data) < off + 40:
        return None, "truncated"
    plen = struct.unpack_from(">H", data, off + 4)[0]
    nxt = data[off + 6]
    src = str(ipaddress.IPv6Address(data[off + 8:off + 24]))
    dst = str(ipaddress.IPv6Address(data[off + 24:off + 40]))
    if len(data) < off + 40 + plen:
        return None, "truncated"
    body = data[off + 40:off + 40 + plen]
    for _ in range(8):
        if nxt in (0, 43, 60):
            if len(body) < 8:
                return None, "truncated"
            hl = (body[1] + 1) * 8
            nxt = body[0]
            body = body[hl:]
        elif nxt == 44:
            if len(body) < 8:
                return None, "truncated"
            fo = struct.unpack_from(">H", body, 2)[0]
            if fo & 0xFFF9:  # offset != 0 or M flag
                return None, "fragment"
            nxt = body[0]
            body = body[8:]
        else:
            break
    return _l4(body, nxt, src, dst, smac, dmac)


def _l4(body, proto, src, dst, smac, dmac):
    if proto == 17:
        if len(body) < 8:
            return None, "truncated"
        sp, dp, ulen = struct.unpack_from(">HHH", body, 0)
        if ulen < 8 or ulen > len(body):
            return None, "truncated"
        return Packet(src, dst, sp, dp, smac, dmac, "udp", body[8:ulen]), None
    if proto == 6:
        if len(body) < 4:
            return None, "truncated"
        sp, dp = struct.unpack_from(">HH", body, 0)
        if 53 in (sp, dp):
            return Packet(src, dst, sp, dp, smac, dmac, "tcp", b""), None
    return None, "unsupported"
