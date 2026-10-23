"""Query <-> response matching with status. Time base = packet timestamps."""
from collections import OrderedDict


def reply_kind(msg) -> str:
    """Reply kind: ip | cname | nxdomain | blocked | nodata | error."""
    if msg.rcode == 3:
        return "nxdomain"
    if msg.rcode != 0:
        return "error"
    if msg.blocked_answer:
        return "blocked"
    if msg.addrs:
        return "ip"
    if msg.cnames:
        return "cname"
    return "nodata"


class Correlator:
    def __init__(self, timeout=10.0, retransmit=2.0, max_open=10000):
        self.timeout = timeout
        self.retransmit = retransmit
        self.max_open = max_open
        self._open = OrderedDict()
        self.counters = {"retransmits": 0, "orphan_responses": 0, "dropped": 0}

    @property
    def pending(self) -> int:
        return len(self._open)

    def feed(self, ts, pkt, msg) -> list:
        """pkt: netparse.Packet (UDP), msg: dnsparse.DnsMessage -> list of events."""
        events = self.tick(ts)
        if not msg.qr:
            if pkt.dst_port != 53:
                return events
            key = (pkt.src_ip, pkt.src_port, pkt.dst_ip, msg.txid, msg.qname, msg.qtype)
            old = self._open.get(key)
            if old is not None:
                if ts - old["ts"] <= self.retransmit:
                    self.counters["retransmits"] += 1
                    return events
                del self._open[key]
                events.append(self._event(old, "no_answer", None, None, "none"))
            self._open[key] = {"ts": ts, "ip": pkt.src_ip, "mac": pkt.src_mac, "sip": pkt.dst_ip,
                               "qname": msg.qname, "qtype": msg.qtype_name}
            while len(self._open) > self.max_open:
                self._open.popitem(last=False)
                self.counters["dropped"] += 1
        else:
            if pkt.src_port != 53:
                return events
            key = (pkt.dst_ip, pkt.dst_port, pkt.src_ip, msg.txid, msg.qname, msg.qtype)
            q = self._open.pop(key, None)
            if q is None:
                self.counters["orphan_responses"] += 1
                return events
            if msg.rcode == 0:
                status = "blocked" if msg.blocked_answer else "allowed"
            elif msg.rcode == 3:
                status = "nxdomain"
            else:
                status = "error"
            events.append(self._event(q, status, msg.rcode, round((ts - q["ts"]) * 1000, 1),
                                      reply_kind(msg)))
        return events

    def tick(self, now) -> list:
        events = []
        while self._open:
            key, q = next(iter(self._open.items()))
            if now - q["ts"] < self.timeout:
                break
            del self._open[key]
            events.append(self._event(q, "no_answer", None, None, "none"))
        return events

    @staticmethod
    def _event(q, status, rcode, latency, reply):
        return {"ts": q["ts"], "client_ip": q["ip"], "client_mac": q["mac"],
                "qname": q["qname"], "qtype": q["qtype"], "status": status,
                "rcode": rcode, "latency_ms": latency, "reply": reply,
                "server_ip": q.get("sip")}
