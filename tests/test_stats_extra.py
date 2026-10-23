import tempfile
import unittest
from datetime import datetime
from pathlib import Path

import helpers as h
import db as dbm
from correlate import Correlator
from dnsparse import parse_message
from netparse import Packet


def ev(ts, qname="a.example", status="allowed", ip="192.168.1.5", mac="aa", qtype="A"):
    return {"ts": ts, "client_ip": ip, "client_mac": mac, "qname": qname, "qtype": qtype,
            "status": status, "rcode": 0, "latency_ms": 1.0, "reply": "ip"}


NOW = datetime(2026, 10, 19, 12, 0, 0, tzinfo=h.UTC).timestamp()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = dbm.Db(Path(self.tmp.name) / "x.db", 24, 30, tz=h.UTC)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()


class SeriesTests(Base):
    def test_alignment_and_bounds(self):
        end = int(NOW // 600) * 600
        start = end - 143 * 600
        self.db.insert_events([
            ev(start), ev(start - 1),
            ev(end + 599, status="blocked"),
            ev(end + 5, status="nxdomain"), ev(end + 6),
        ])
        s = self.db.series_24h(NOW, since=start - 10000)
        b = s["buckets"]
        self.assertEqual((len(b), s["start"], s["step"]), (144, start, 600))
        self.assertTrue(all(x["ts"] % 600 == 0 for x in b))
        self.assertEqual(b[0]["allowed"], 1)
        self.assertEqual(b[1]["allowed"], 0)
        self.assertEqual(b[-1], {"ts": end, "allowed": 2, "blocked": 1, "nxdomain": 1, "no_answer": 0})

    def test_null_before_capture_since(self):
        end = int(NOW // 600) * 600
        since = end - 2 * 600 + 100
        self.db.insert_events([ev(since + 10)])
        b = self.db.series_24h(NOW, since=since)["buckets"]
        self.assertIsNone(b[-4]["allowed"])
        self.assertIsNotNone(b[-3]["allowed"])
        self.assertEqual(b[-1]["allowed"], 0)

    def test_all_null_without_data(self):
        b = self.db.series_24h(NOW, since=None)["buckets"]
        self.assertTrue(all(x["allowed"] is None for x in b))

    def test_clients_top6_rest(self):
        evs = []
        for i in range(8):
            for _ in range(10 - i):
                evs.append(ev(NOW - 100, ip=f"192.168.1.{10 + i}", mac=f"m{i}"))
        self.db.insert_events(evs)
        c = self.db.clients_24h(NOW, lambda ip, mac: "dev-" + ip.split(".")[-1])
        self.assertEqual([x["total"] for x in c["clients"]], [10, 9, 8, 7, 6, 5])
        self.assertEqual(c["clients"][0]["name"], "dev-10")
        self.assertEqual(c["rest"]["total"], 7)
        self.assertEqual(len(c["clients"][0]["series"]), 144)
        self.assertEqual(sum(c["rest"]["series"]), 7)
        self.assertEqual(c["clients"][0]["blocked"], 0)
        self.assertEqual(len(c["rest"]["blocked_series"]), 144)

    def test_clients_many_macs_bounded(self):
        db = dbm.Db(Path(self.tmp.name) / "y.db", 24, 30, tz=h.UTC, clients_per_day=50)
        evs = [ev(NOW - 100, ip=f"10.0.{i // 250}.{i % 250}", mac=f"m{i:04d}") for i in range(2000)]
        for i in range(6):                      # six clear leaders: 20 .. 15 queries
            evs += [ev(NOW - 100, ip=f"192.168.1.{i}", mac=f"top{i}") for _ in range(20 - i)]
        db.insert_events(evs)
        loaded = []

        class Spy:
            def __init__(self, conn):
                self._c = conn

            def execute(self, *a):
                cur = self._c.execute(*a)

                class Cur:
                    def fetchall(self):
                        rows = cur.fetchall()
                        loaded.append(len(rows))
                        return rows
                return Cur()
        real, db.conn = db.conn, Spy(db.conn)
        try:
            c = db.clients_24h(NOW)
            m = db.ip2mac()
        finally:
            db.conn = real
        self.assertEqual([x["total"] for x in c["clients"]], [20, 19, 18, 17, 16, 15])
        self.assertEqual(c["rest"]["total"], 2000)
        self.assertEqual(sum(c["rest"]["series"]), 2000)
        self.assertEqual(len(m), 50)
        self.assertLessEqual(max(loaded), 144)
        self.assertLessEqual(sum(loaded), 50 + 144 + 144 + 50)
        db.close()

    def test_clients_blocked_sums(self):
        self.db.insert_events([ev(NOW - 50, "a.example", "blocked"), ev(NOW - 40), ev(NOW - 30, "b.example", "blocked")])
        c = self.db.clients_24h(NOW)["clients"][0]
        self.assertEqual((c["total"], c["blocked"], sum(c["blocked_series"])), (3, 2, 2))


class PeriodTests(Base):
    def test_permitted_qtypes_statuses_active(self):
        self.db.insert_events([
            ev(NOW, "ok.example"), ev(NOW, "ok.example"), ev(NOW, "ads.example", "blocked"),
            ev(NOW, "gone.example", "nxdomain", qtype="AAAA", ip="192.168.1.6", mac="bb"),
            ev(NOW, "v6.example", qtype="HTTPS"),
        ])
        t = self.db.top(1, NOW)
        names = [x["qname"] for x in t["top_permitted"]]
        self.assertNotIn("ads.example", names)
        self.assertEqual(names[0], "ok.example")
        self.assertIn("ads.example", [x["qname"] for x in t["top_domains"]])
        self.assertEqual({x["qtype"]: x["n"] for x in t["qtypes"]}, {"A": 3, "AAAA": 1, "HTTPS": 1})
        self.assertAlmostEqual(t["qtypes"][0]["pct"], 60.0)
        self.assertEqual(t["statuses"], {"allowed": 3, "blocked": 1, "nxdomain": 1})
        self.assertEqual(t["active_clients"], 2)

    def test_qtype_upsert_and_retention(self):
        old = datetime(2026, 9, 1, 12, tzinfo=h.UTC).timestamp()
        self.db.insert_events([ev(NOW), ev(NOW + 1)])
        self.db.insert_events([ev(NOW + 2)])
        self.db.insert_events([ev(old, qtype="TXT")])
        n = self.db.conn.execute("SELECT n FROM dns_daily_qtype WHERE day='2026-10-19' AND qtype='A'").fetchone()[0]
        self.assertEqual(n, 3)
        self.db.retention(NOW)
        days = {r[0] for r in self.db.conn.execute("SELECT day FROM dns_daily_qtype")}
        self.assertEqual(days, {"2026-10-19"})


def pk(src, dst, sp, dp):
    return Packet(src, dst, sp, dp, "aa", "bb", "udp", b"")


class ReplyTests(unittest.TestCase):
    def run_case(self, rcode, answers, qtype=1, authority=()):
        c = Correlator()
        c.feed(1.0, pk("1.1.1.5", "1.1.1.1", 4000, 53), parse_message(h.dns_query(1, "x.example", qtype)))
        r = parse_message(h.dns_response(1, "x.example", qtype, rcode, answers, authority))
        return c.feed(1.1, pk("1.1.1.1", "1.1.1.5", 53, 4000), r)[0]

    def test_all_kinds(self):
        cn = h.rr(5, h.name_bytes("y.example"))
        self.assertEqual(self.run_case(0, [h.rr(1, b"\x01\x02\x03\x04")])["reply"], "ip")
        self.assertEqual(self.run_case(0, [cn])["reply"], "cname")
        self.assertEqual(self.run_case(3, [])["reply"], "nxdomain")
        self.assertEqual(self.run_case(0, [h.rr(1, b"\x00\x00\x00\x00")])["reply"], "blocked")
        soa = h.rr(6, b"\x00" * 22)
        self.assertEqual(self.run_case(0, [], 65, authority=[soa])["reply"], "nodata")
        self.assertEqual(self.run_case(0, [], 65)["reply"], "blocked")  # box-NODATA 0/0
        self.assertEqual(self.run_case(2, [])["reply"], "error")

    def test_none_on_timeout(self):
        c = Correlator()
        c.feed(1.0, pk("1.1.1.5", "1.1.1.1", 4000, 53), parse_message(h.dns_query(1, "x.example")))
        self.assertEqual(c.tick(20.0)[0]["reply"], "none")


if __name__ == "__main__":
    unittest.main()
