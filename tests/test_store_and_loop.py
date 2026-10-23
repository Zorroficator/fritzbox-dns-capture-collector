import json
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

import helpers as h
import capture
import config
import db as dbm
import ftrap_dns
from hosts import HostMap

try:
    from zoneinfo import ZoneInfo
    ZoneInfo("America/New_York")
    HAVE_NY = True
except Exception:      # no tz database on this machine
    HAVE_NY = False


def ev(ts, qname="a.example", status="allowed", ip="192.168.1.5", mac="aa:bb"):
    return {"ts": ts, "client_ip": ip, "client_mac": mac, "qname": qname, "qtype": "A",
            "status": status, "rcode": 0, "latency_ms": 1.0}


def utc(y, m, d, hh, mm=0):
    return datetime(y, m, d, hh, mm, tzinfo=h.UTC).timestamp()


class DbTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = dbm.Db(Path(self.tmp.name) / "d" / "x.db", 24, 30, tz=h.UTC)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_perms(self):
        import os, stat
        p = self.db.path
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(p.parent).st_mode), 0o700)

    def test_wal_and_shm_are_private(self):
        import os, stat
        old = os.umask(0o022)       # even with a permissive umask
        try:
            import tempfile
            with tempfile.TemporaryDirectory() as d:
                db = dbm.Db(Path(d) / "new" / "x.db", tz=h.UTC)
                db.insert_events([ev(utc(2026, 10, 19, 12))])
                base = str(db.path)
                for suffix in ("", "-wal", "-shm"):
                    self.assertTrue(os.path.exists(base + suffix), suffix)
                    self.assertEqual(stat.S_IMODE(os.stat(base + suffix).st_mode), 0o600, suffix)
                self.assertEqual(stat.S_IMODE(os.stat(db.path.parent).st_mode), 0o700)
                db.close()
        finally:
            os.umask(old)

    def test_upsert_sums(self):
        now = utc(2026, 10, 19, 12)
        self.db.insert_events([ev(now), ev(now + 1), ev(now + 2, "ads.example", "blocked")])
        self.db.insert_events([ev(now + 3, "ads.example", "blocked")])
        t = self.db.top(1, now + 10)
        self.assertEqual((t["total"], t["blocked"]), (4, 2))
        self.assertEqual(t["top_domains"][0], {"qname": "a.example", "n": 2})
        self.assertEqual(t["top_blocked"], [{"qname": "ads.example", "n": 2}])
        self.assertEqual(t["top_clients"][0]["n"], 4)
        self.assertEqual(t["top_clients_blocked"][0]["n"], 2)

    def test_top_clients_group_by_mac(self):
        now = utc(2026, 10, 19, 12)
        self.db.insert_events([ev(now, ip="192.168.1.5", mac="aa:bb"),
                               ev(now + 1, ip="fe80::1", mac="aa:bb", status="blocked"),
                               ev(now + 2, ip="192.168.1.6", mac="cc:dd")])
        t = self.db.top(1, now + 10)
        self.assertEqual(t["active_clients"], 2)
        self.assertEqual(t["top_clients"][0], {"name": "aa:bb", "n": 2, "blocked": 1})
        self.assertEqual(t["top_clients_blocked"], [{"name": "aa:bb", "n": 1, "total": 2}])

    def test_top_clients_legacy_ip_key(self):
        now = utc(2026, 10, 19, 12)
        self.db.insert_events([ev(now, ip="192.168.1.5", mac="aa:bb")])
        with self.db.conn:  # legacy row: IPv4 as key
            self.db.conn.execute("INSERT INTO dns_daily_client VALUES (?,?,?,?,?)",
                                 ("2026-10-18", "192.168.1.5", "old", 3, 1))
        t = self.db.top(7, now + 10)
        self.assertEqual(t["top_clients"], [{"name": "aa:bb", "n": 4, "blocked": 1}])

    def test_retention(self):
        now = utc(2026, 10, 19, 12)
        self.db.insert_events([ev(now - 25 * 3600), ev(now - 3600),
                               ev(utc(2026, 9, 10, 12), "old.example")])
        r = self.db.retention(now)
        self.assertEqual(r["events"], 2)
        self.assertEqual(self.db.conn.execute("SELECT COUNT(*) FROM dns_events").fetchone()[0], 1)
        days = {x[0] for x in self.db.conn.execute("SELECT day FROM dns_daily_domain")}
        self.assertNotIn("2026-09-10", days)
        self.assertIn("2026-10-18", days)

    def test_day_boundary_fixed_zone(self):
        self.assertEqual(dbm.local_day(utc(2026, 10, 25, 23, 30), h.UTC), "2026-10-25")
        self.assertEqual(dbm.local_day(utc(2026, 10, 26, 0, 30), h.UTC), "2026-10-26")

    def test_day_boundary_local_zone(self):
        ts = utc(2026, 10, 25, 23, 30)
        self.assertEqual(dbm.local_day(ts), datetime.fromtimestamp(ts).strftime("%Y-%m-%d"))

    @unittest.skipUnless(HAVE_NY, "tz database not available")
    def test_day_boundary_dst(self):
        # DST ends on 2026-11-01 in New York: EDT (UTC-4) before 06:00 UTC, EST (UTC-5) after
        ny = ZoneInfo("America/New_York")
        self.assertEqual(dbm.local_day(utc(2026, 11, 1, 3, 30), ny), "2026-10-31")
        self.assertEqual(dbm.local_day(utc(2026, 11, 1, 5, 30), ny), "2026-11-01")
        self.assertEqual(dbm.local_day(utc(2026, 11, 2, 4, 30), ny), "2026-11-01")

    def test_client_key(self):
        self.assertEqual(dbm.client_key("1.2.3.4", "aa"), "aa")
        self.assertEqual(dbm.client_key("fe80::1", "aa"), "aa")
        self.assertEqual(dbm.client_key("1.2.3.4", ""), "1.2.3.4")
        self.assertEqual(dbm.client_key("fe80::1", ""), "fe80::1")


class HostTests(unittest.TestCase):
    def test_mapping(self):
        m = HostMap()
        m.update([
            {"ip": "192.168.1.5", "mac": "AA:01", "hostname": "laptop"},
            {"ip": "192.168.1.6", "mac": "AA:02", "hostname": "tv"},
            {"ip": "192.168.1.7", "mac": "RR:00", "hostname": "nat-a"},
            {"ip": "192.168.1.8", "mac": "RR:00", "hostname": "nat-b"},
            {"ip": "", "mac": "AA:03", "hostname": "phone"},
        ])
        self.assertEqual(m.name_for("192.168.1.5", "x"), "laptop")
        self.assertEqual(m.name_for("fe80::1", "aa:02"), "tv")
        self.assertEqual(m.name_for("fe80::2", "aa:03"), "phone")
        self.assertEqual(m.name_for("fe80::3", "rr:00"), "fe80::3")   # MAC NAT
        self.assertEqual(m.name_for("192.168.1.99", "aa:99"), "192.168.1.99")

    def test_error_keeps_old(self):
        m = HostMap()
        m.update([{"ip": "1.1.1.1", "mac": "a", "hostname": "x"}])
        def bad():
            raise OSError("down")
        self.assertFalse(m.refresh(bad))
        self.assertEqual(m.errors, 1)
        self.assertEqual(m.name_for("1.1.1.1", ""), "x")


class FakeCap:
    def __init__(self, data):
        self.data = data
        self.stopped = False
    def open(self): pass
    def chunks(self):
        for i in range(0, len(self.data), 50):
            yield self.data[i:i + 50]
    def abort(self): pass
    def stop(self): self.stopped = True


class LoopTests(unittest.TestCase):
    def build_stream(self, n_live=0):
        out = h.pcap_global(0xA1B2C3D4, "<")
        ts = int(time.time())
        def frame(src, dst, sp, dp, pl):
            return h.eth(h.ipv4(src, dst, 17, h.udp(sp, dp, pl)))
        for i in range(n_live):
            name = f"h{i}.example"
            out += h.pcap_record(ts, 0, frame("192.168.1.5", "192.168.1.1", 40000 + i, 53, h.dns_query(i, name)))
            ans = [h.rr(1, b"\x00\x00\x00\x00")] if i % 2 else [h.rr(1, b"\x01\x02\x03\x04")]
            out += h.pcap_record(ts, 1000, frame("192.168.1.1", "192.168.1.5", 53, 40000 + i, h.dns_response(i, name, answers=ans)))
        return out

    def make_app(self, tmp, data, hm=None):
        cfg = h.app_cfg(tmp)
        return ftrap_dns.App(cfg, lambda: FakeCap(data), hostmap=hm)

    def test_file_mode_and_new_out_dir_modes(self):
        import os, stat
        with tempfile.TemporaryDirectory() as tmp:
            cfg = h.app_cfg(tmp)
            cfg["out_dir"] = str(Path(tmp) / "www" / "out")
            cfg["output"] = {"dir_mode": 0o750, "file_mode": 0o640}
            old = os.umask(0o077)
            try:
                app = ftrap_dns.App(cfg, lambda: FakeCap(b""))
                app.write_live()
                app.db.close()
            finally:
                os.umask(old)
            f = Path(cfg["out_dir"]) / "dns_live.json"
            self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o640)
            self.assertEqual(stat.S_IMODE(f.parent.stat().st_mode), 0o750)
            self.assertEqual(stat.S_IMODE(f.parent.parent.stat().st_mode), 0o750)

    def test_log_file_is_private(self):
        import logging, os, stat
        with tempfile.TemporaryDirectory() as tmp:
            old = os.umask(0o022)
            try:
                p = Path(tmp) / "logs" / "ftrap.log"
                config.ensure_private_dir(p.parent)
                handler = ftrap_dns.PrivateRotatingFileHandler(str(p), maxBytes=50, backupCount=1)
                rec = logging.LogRecord("x", logging.INFO, "f", 1, "m" * 80, None, None)
                handler.emit(rec)
                handler.emit(rec)       # forces a rotation, the new file must be private as well
                handler.close()
            finally:
                os.umask(old)
            for f in (p, Path(str(p) + ".1")):
                self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o600, f.name)

    def test_loop_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            hm = HostMap(); hm.update([{"ip": "192.168.1.5", "mac": "aa:bb", "hostname": "laptop"}])
            app = self.make_app(tmp, self.build_stream(250), hm)
            # end of the connection -> run() would reconnect; stop after the first session
            orig = app._session
            def once():
                orig()
                app.stop_event.set()
            app._session = once
            app.run()
            live = json.loads((Path(tmp) / "out" / "dns_live.json").read_text())
            top = json.loads((Path(tmp) / "out" / "dns_top.json").read_text())
            self.assertEqual(len(live["events"]), 200)
            self.assertEqual(live["events"][0]["name"], "laptop")
            self.assertEqual(set(live["events"][0]), {"ts", "name", "qname", "qtype", "status", "latency_ms", "reply"})
            self.assertEqual(top["periods"]["today"]["total"], 250)
            self.assertEqual(top["periods"]["today"]["blocked"], 125)
            self.assertEqual(top["periods"]["today"]["top_clients"][0]["name"], "laptop")
            self.assertEqual(set(top["periods"]), {"today", "7d", "30d"})
            self.assertEqual(set(top["health"]), {"connected", "last_error", "reconnects", "host_errors", "rate_limited",
                                              "capture_since", "connected_since", "last_packet_ts"})
            import sqlite3
            c = sqlite3.connect(str(Path(tmp) / "ftrap_dns.db"))
            self.assertEqual(c.execute("SELECT COUNT(*) FROM dns_events").fetchone()[0], 250)

    def test_tick_time_independent_of_wallclock(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = self.make_app(tmp, b"")
            app._last_pkt_ts = 1000.0          # box clock far behind the wall clock
            app._last_pkt_mono = time.monotonic()
            self.assertLess(app._tick_time(), 1005.0)
            app.db.close()


if __name__ == "__main__":
    unittest.main()
