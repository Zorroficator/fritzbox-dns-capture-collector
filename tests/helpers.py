"""Shared test helpers: set the import path, build synthetic bytes."""
import struct
import sys
from datetime import timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def pcap_global(magic=0xA1B2C3D4, end="<", link=1):
    return struct.pack(end + "IHHiIII", magic, 2, 4, 0, 0, 1600, link)


def pcap_record(ts_sec, frac, payload, end="<", avm=False):
    h = struct.pack(end + "IIII", ts_sec, frac, len(payload), len(payload))
    if avm:
        h += b"\x00" * 8
    return h + payload


def name_bytes(name):
    out = b""
    for lab in name.split("."):
        out += bytes([len(lab)]) + lab.encode()
    return out + b"\x00"


def dns_query(txid, name, qtype=1):
    return struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0) + name_bytes(name) + struct.pack(">HH", qtype, 1)


def rr(rtype, rdata, name=b"\xc0\x0c"):
    return name + struct.pack(">HHIH", rtype, 1, 60, len(rdata)) + rdata


def dns_response(txid, name, qtype=1, rcode=0, answers=(), authority=()):
    hdr = struct.pack(">HHHHHH", txid, 0x8180 | rcode, 1, len(answers), len(authority), 0)
    return hdr + name_bytes(name) + struct.pack(">HH", qtype, 1) + b"".join(answers) + b"".join(authority)


def udp(sport, dport, payload):
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def ipv4(src, dst, proto, body, flags_frag=0):
    s = bytes(int(x) for x in src.split("."))
    d = bytes(int(x) for x in dst.split("."))
    h = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(body), 1, flags_frag, 64, proto, 0) + s + d
    return h + body


def ipv6(src16, dst16, nxt, body):
    return struct.pack(">IHBB", 0x60000000, len(body), nxt, 64) + src16 + dst16 + body


MAC_A = bytes.fromhex("020000000001")
MAC_B = bytes.fromhex("020000000002")


def eth(payload, etype=0x0800, vlans=()):
    out = MAC_B + MAC_A
    for tpid in vlans:
        out += struct.pack(">HH", tpid, 5)
    return out + struct.pack(">H", etype) + payload


UTC = timezone.utc


def app_cfg(tmp, **limits):
    """Configuration for App tests: UTC, DB and JSON output below ``tmp``."""
    import config
    cfg = config.load_config()
    cfg["timezone"] = "UTC"
    cfg["db_path"] = str(Path(tmp) / "ftrap_dns.db")
    cfg["out_dir"] = str(Path(tmp) / "out")
    cfg["limits"].update(limits)
    return cfg
