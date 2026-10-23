import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import helpers as h
import capture
import credentials
import db as dbm
import dnsparse
import ftrap_dns
from hosts import HostMap
from test_store_and_loop import FakeCap, LoopTests
from test_stats_extra import ev


class AppTests(unittest.TestCase):
    def mk(self, tmp, cap=None, **limits):
        cfg = h.app_cfg(tmp, **limits)
        return ftrap_dns.App(cfg, cap or (lambda: FakeCap(b"")))

    def test_credentials_error_line_after_three(self):
        with tempfile.TemporaryDirectory() as tmp:
            n = []

            def fac():
                n.append(1)
                if len(n) >= 4:
                    app.stop_event.set()
                raise credentials.CredentialsError("gone")
            app = self.mk(tmp, fac)
            with mock.patch.object(app.stop_event, "wait"), self.assertLogs("ftrap_dns", "ERROR") as lg:
                app.run()
            self.assertEqual(sum("CREDENTIALS ERROR" in m for m in lg.output), 1)

    def test_rate_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = self.mk(tmp, client_per_min=3)
            now = (int(time.time() // 60)) * 60 + 1
            app._add([ev(now + i * 0.01) for i in range(5)])
            self.assertEqual(len(app.pending), 3)
            self.assertEqual(app.rate_limited_total, 2)
            self.assertEqual(app._health()["rate_limited"], 2)
            app.db.close()

    def test_global_events_per_min(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = self.mk(tmp, events_per_min=4)
            now = (int(time.time() // 60)) * 60 + 1
            app._add([ev(now + i * 0.01, ip=f"192.0.2.{i}", mac=f"m{i}") for i in range(6)])
            self.assertEqual(len(app.pending), 4)
            self.assertEqual(app.rate_limited_total, 2)
            app._add([ev(now + 60, ip="192.0.2.1", mac="m1")])     # next minute: counter resets
            self.assertEqual(len(app.pending), 5)
            app.db.close()

    def test_rate_dict_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = self.mk(tmp, clients_per_day=2, client_per_min=1)
            now = (int(time.time() // 60)) * 60 + 1
            app._add([ev(now + i * 0.01, ip=f"192.0.2.{i}", mac=f"m{i}") for i in range(5)])
            self.assertLessEqual(len(app._rate), 3)          # 2 clients + shared key
            # clients 0 and 1 and the first of the shared group pass, the rest is limited
            self.assertEqual(len(app.pending), 3)
            self.assertEqual(app.rate_limited_total, 2)
            app.db.close()

    def test_capture_since_survives_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = self.mk(tmp)
            old = time.time() - 20 * 86400
            app.db.health("connected", "", ts=old)
            app.db.health("connected", "", ts=old + 86400)
            app.db.close()
            app2 = ftrap_dns.App(h.app_cfg(tmp), lambda: FakeCap(b""))
            self.assertAlmostEqual(app2.capture_since, old, places=3)
            self.assertIsNone(app2._series_since)
            self.assertIsNotNone(app2.top_doc()["capture_since"])
            app2.db.close()

    def test_capture_since_ignores_expired_connects(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = self.mk(tmp)
            app.db.health("connected", "", ts=time.time() - 40 * 86400)
            self.assertIsNone(app.db.first_connected(30))
            app.db.close()

    def test_bad_timestamp(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = self.mk(tmp)
            app._add([ev(100.0), ev(time.time() + 3 * 86400), ev(time.time())])
            self.assertEqual(len(app.pending), 1)
            self.assertEqual(app.counters["ts_dropped"], 2)
            app.db.close()

    def test_disk_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = self.mk(tmp)
            app._add([ev(time.time())])
            with mock.patch.object(app, "_free_mb", return_value=1.0), \
                    self.assertLogs("ftrap_dns", "WARNING") as lg:
                app.flush()
                app._add([ev(time.time())])
                app.flush()
            self.assertEqual(len(lg.output), 1)
            self.assertEqual(app.counters["disk_guard"], 2)
            self.assertEqual(app.db.conn.execute("SELECT COUNT(*) FROM dns_events").fetchone()[0], 0)
            self.assertEqual(len(app.live), 2)
            app.db.close()

    def test_pump_does_not_hang_on_full_queue(self):
        class Flood:
            def open(self): pass
            def chunks(self):
                while True:
                    yield b"x"
            def abort(self): pass
            def stop(self): pass
        with tempfile.TemporaryDirectory() as tmp:
            app = self.mk(tmp, lambda: Flood())
            before = threading.active_count()
            with mock.patch.object(app, "_process", side_effect=lambda r, d: (_ for _ in ()).throw(
                    capture.CaptureError("stop"))):
                with self.assertRaises(capture.CaptureError):
                    app._session()
            time.sleep(1.5)
            self.assertLessEqual(threading.active_count(), before)
            app.db.close()

    def test_stop_not_error_in_health(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = self.mk(tmp)
            app.stop_event.set()
            app._report("x", "x")
            self.assertEqual(app.counters["errors"], 0)
            app.db.close()

    def test_capture_since_kept_and_health_in_docs(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = LoopTests().make_app(tmp, LoopTests().build_stream(3))
            n = []
            orig = app._session

            def twice():
                orig()
                n.append(1)
                if len(n) == 2:
                    app.stop_event.set()
            app._session = twice
            with mock.patch.object(app.stop_event, "wait"):
                first = None
                app.run()
            top = json.loads((Path(tmp) / "out" / "dns_top.json").read_text())
            live = json.loads((Path(tmp) / "out" / "dns_live.json").read_text())
            for doc in (top, live):
                for k in ("capture_since", "connected_since", "last_packet_ts"):
                    self.assertIn(k, doc["health"])
            self.assertIsNotNone(top["health"]["capture_since"])
            self.assertIsNotNone(top["health"]["last_packet_ts"])
            self.assertIsNone(top["health"]["connected_since"])   # not connected after the end
            self.assertIn("no_answer", top["series_24h"]["buckets"][-1])
            self.assertNotIn("top_domains", top["periods"]["today"])
            self.assertTrue(all("client_ip" not in e for e in live["events"]))


class DbTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = dbm.Db(Path(self.tmp.name) / "x.db", 24, 30, domains_per_day=2, tz=h.UTC)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_domain_cap(self):
        now = time.time()
        self.db.insert_events([ev(now, f"d{i}.example") for i in range(4)])
        self.db.insert_events([ev(now, "d0.example"), ev(now, "new.example")])
        rows = dict(self.db.conn.execute("SELECT qname, n FROM dns_daily_domain"))
        self.assertEqual(rows, {"d0.example": 2, "d1.example": 1, "(other)": 3})
        self.assertEqual(self.db.conn.execute("SELECT COUNT(*) FROM dns_events").fetchone()[0], 6)

    def test_client_cap(self):
        db = dbm.Db(Path(self.tmp.name) / "c.db", 24, 30, tz=h.UTC, clients_per_day=2)
        self.addCleanup(db.close)
        now = time.time()
        db.insert_events([ev(now, ip=f"192.0.2.{i}", mac=f"m{i}") for i in range(4)])
        db.insert_events([ev(now, ip="192.0.2.0", mac="m0"), ev(now, ip="192.0.2.9", mac="m9")])
        rows = {r[0]: r[1] for r in db.conn.execute("SELECT client_key, total FROM dns_daily_client")}
        self.assertEqual(rows, {"m0": 2, "m1": 1, "(other)": 3})
        # events keep the real client; only the daily totals are collapsed
        self.assertEqual(db.conn.execute("SELECT COUNT(DISTINCT client_mac) FROM dns_events").fetchone()[0], 5)

    def test_client_key_nat(self):
        self.assertEqual(dbm.client_key("1.2.3.4", "AA:01", {"aa:01"}), "1.2.3.4")
        self.assertEqual(dbm.client_key("1.2.3.4", "aa:02", {"aa:01"}), "aa:02")

    def test_real_name_not_overwritten(self):
        now = time.time()
        self.db.insert_events([ev(now)], lambda ip, mac: "laptop")
        self.db.insert_events([ev(now)], lambda ip, mac: ip)    # host list briefly gone -> raw IP
        self.assertEqual(self.db.conn.execute("SELECT name FROM dns_daily_client").fetchone()[0], "laptop")

    def test_no_answer_series(self):
        now = time.time()
        self.db.insert_events([ev(now, status="no_answer"), ev(now)])
        self.assertEqual(self.db.series_24h(now)["buckets"][-1]["no_answer"], 1)

    def test_pragmas(self):
        self.assertEqual(self.db.conn.execute("PRAGMA synchronous").fetchone()[0], 1)
        self.db.retention()


class MiscTests(unittest.TestCase):
    def test_label_escape(self):
        msg = bytes([3]) + b"a.B" + bytes([2]) + b"\x01 " + b"\x07example\x00"
        self.assertEqual(dnsparse.read_name(msg, 0)[0], "a\\.b.\\001\\032.example")

    def test_name_by_mac(self):
        m = HostMap()
        m.update([{"ip": "192.168.1.5", "mac": "AA:01", "hostname": "laptop"}])
        self.assertEqual(m.name_for("192.168.1.99", "aa:01"), "laptop")
        self.assertEqual(m.name_for("192.168.1.99", "aa:77"), "192.168.1.99")


class LoginBackoffTests(unittest.TestCase):
    def run_app(self, outcomes, block=0):
        """outcomes: 'login' | 'ok' | 'net'. Returns (requested waits, log, app)."""
        with tempfile.TemporaryDirectory() as tmp:
            cfg = h.app_cfg(tmp)
            app = ftrap_dns.App(cfg, lambda: None)
            app._last_cap = mock.Mock(block_time=lambda: block)
            it = iter(outcomes)

            def sess():
                o = next(it, None)
                if o is None:
                    app.stop_event.set()
                    raise capture.CaptureError("end")
                if o == "login":
                    raise capture.LoginError("x")
                if o == "net":
                    raise capture.CaptureError("net")
            waits = []
            with mock.patch.object(app, "_session", side_effect=sess), \
                    mock.patch.object(app.stop_event, "wait", side_effect=waits.append), \
                    self.assertLogs("ftrap_dns", "ERROR") as lg:
                app.run()
            return waits, lg.output, app

    def test_escalation_and_cap(self):
        waits, out, app = self.run_app(["login"] * 8)
        self.assertEqual(waits[:2], [5, 10])
        self.assertEqual(waits[2:6], [1800, 3600, 7200, 7200])
        self.assertEqual(sum("LOGIN ERROR" in m for m in out), 1)

    def test_reset_after_success(self):
        waits, out, app = self.run_app(["login", "login", "ok", "login", "login"])
        self.assertTrue(all(w < 1800 for w in waits))
        self.assertEqual(app._login_fails, 2)

    def test_unreachable_not_counted(self):
        waits, out, app = self.run_app(["net"] * 5)
        self.assertEqual(app._login_fails, 0)
        self.assertTrue(all(w < 1800 for w in waits))

    def test_block_time_raises_wait(self):
        waits, out, app = self.run_app(["login"] * 3, block=5000)
        self.assertEqual(waits[2], 5000)


class LoginViaRunTests(unittest.TestCase):
    """Real flow run() -> _session() with a fake capture."""
    def run_caps(self, caps, block=0):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = h.app_cfg(tmp)
            it = iter(caps)

            def fac():
                kind = next(it, None)
                if kind is None:
                    app.stop_event.set()
                    kind = "net"

                class Cap:
                    def open(self_):
                        if kind == "login":
                            raise capture.LoginError("x")
                    def chunks(self_):
                        raise capture.CaptureError("network down")
                        yield b""
                    def abort(self_): pass
                    def stop(self_): pass
                    def block_time(self_): return block
                return Cap()
            app = ftrap_dns.App(cfg, fac)
            waits = []
            with mock.patch.object(app.stop_event, "wait", side_effect=waits.append), \
                    self.assertLogs("ftrap_dns", "ERROR"):
                app.run()
            return waits

    def test_block_time_after_session_end(self):
        waits = self.run_caps(["login"] * 3, block=5000)
        self.assertEqual(waits[2], 5000)

    def test_reset_after_successful_open(self):
        waits = self.run_caps(["login", "login", "net", "login"])
        self.assertTrue(all(w < 1800 for w in waits), waits)
