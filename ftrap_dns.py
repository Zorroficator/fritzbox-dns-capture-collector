"""Long-running process: packet capture -> SQLite + dns_live.json + dns_top.json.

Usage: python3 ftrap_dns.py [--config PATH] [--password-stdin] [--allow-insecure-credentials]
Log: per-minute counters and errors only; never domains, devices, IPs or MACs.
"""
import argparse
import collections
import json
import logging
import logging.handlers
import os
import queue
import shutil
import signal
import threading
import time
import tomllib
from datetime import datetime, timezone
from pathlib import Path

import config
import dnsparse
import fritz_auth
import netparse
import pcap
from capture import Capture, CaptureError, LoginError, describe_exc
from correlate import Correlator
from credentials import CredentialsError, load_credentials, read_password_stdin
from db import OTHER, Db, client_key
from hosts import HostMap, make_fetch

log = logging.getLogger("ftrap_dns")

LIVE_MAX = 200
FLUSH_S, LIVE_S, TOP_S, RETENTION_S, HOSTS_S, STATS_S = 1.0, 5.0, 60.0, 3600.0, 600.0, 60.0
BACKOFF_MIN, BACKOFF_MAX = 5, 300
CREDENTIAL_FAILS = 3        # this many credential failures in a row -> one explicit ERROR line
LOGIN_FAILS = 3             # login rejected: from this many failures in a row use a long backoff
LOGIN_WAIT_MIN, LOGIN_WAIT_MAX = 1800, 7200   # do not extend the box's block time with bad logins
TS_MIN = datetime(2020, 1, 1, tzinfo=timezone.utc).timestamp()


def _iso(ts, tz=None):
    """ISO 8601 with offset; tz None = local system time zone."""
    dt = datetime.fromtimestamp(ts, tz)
    if dt.tzinfo is None:
        dt = dt.astimezone()
    return dt.isoformat(timespec="seconds")


class App:
    def __init__(self, cfg, capture_factory, hostmap=None, host_fetch=None, db=None):
        self.cfg = cfg
        self.capture_factory = capture_factory
        self.hostmap = hostmap or HostMap(cfg.get("aliases"))
        self.host_fetch = host_fetch
        self.tz = config.resolve_timezone(cfg["timezone"])
        ret = cfg["retention"]
        lim = cfg.get("limits", {})
        self.client_per_min = int(lim.get("client_per_min", 1200))
        self.min_free_mb = int(lim.get("min_free_mb", 1024))
        self.events_per_min = int(lim.get("events_per_min", 6000))
        self.clients_per_day = int(lim.get("clients_per_day", 500))
        out = cfg.get("output", {})
        self.dir_mode = out.get("dir_mode", 0o700)
        self.file_mode = out.get("file_mode", 0o600)
        self.hosts_every = float(cfg.get("hosts", {}).get("refresh_seconds", HOSTS_S))
        self.db = db or Db(cfg["db_path"], ret["events_hours"], ret["daily_days"],
                           int(lim.get("domains_per_day", 20000)), self.tz,
                           self.clients_per_day)
        self.out_dir = Path(cfg["out_dir"])
        self.stop_event = threading.Event()
        self.corr = Correlator()
        self.pending = []
        self.live = collections.deque(maxlen=LIVE_MAX)
        self.counters = collections.Counter()
        self.status_counts = collections.Counter()
        self.reconnects = 0
        self.connected = False
        self.last_error = ""
        # Shown to the user: oldest recorded connect within the retention window (so a
        # restart does not reset it), else the first connect of this process.
        # series_24h keeps using the process start (_series_since): it only decides where
        # "no data yet" (null) ends, and the first stored event already covers older data.
        try:
            self.capture_since = self.db.first_connected(ret["daily_days"])
        except Exception:
            self.capture_since = None
        self._series_since = None       # start of the first capture in this process
        self.connected_since = None     # current connection
        self.rate_limited_total = 0
        self._rate_min, self._rate, self._rate_total = None, {}, 0
        self._credential_fails = 0
        self._login_fails = 0
        self._disk_warn_mono = None
        self._deltas = {}
        self._last_pkt_wall = None
        self._cap = None
        self._last_cap = None           # only for block_time() after a session ended
        # tick time: last packet ts + monotonic time since that packet
        self._last_pkt_ts = None
        self._last_pkt_mono = None
        self._next = {"flush": 0, "live": 0, "top": 0, "ret": 0, "hosts": 0, "stats": 0}

    # -- control ----------------------------------------------------------
    def request_stop(self, *_a):
        self.stop_event.set()
        cap = self._cap
        if cap is not None:
            cap.abort()

    def run(self):
        backoff = BACKOFF_MIN
        while not self.stop_event.is_set():
            started = time.monotonic()
            wait_min = 0
            try:
                self._session()
                self.last_error = ""
                self._login_fails = 0
            except CredentialsError as exc:
                self._credential_fails += 1
                self._report("credentials_error",
                             "credentials unavailable: %s (failure %d)" % (exc, self._credential_fails))
                if self._credential_fails == CREDENTIAL_FAILS:
                    log.error("CREDENTIALS ERROR: %d failures in a row - check the credentials source, "
                              "no capture is running", CREDENTIAL_FAILS)
            except LoginError as exc:
                self._login_fails += 1
                self._report(exc.code, "capture: %s (failure %d)" % (exc, self._login_fails))
                if self._login_fails >= LOGIN_FAILS:
                    wait_min = min(LOGIN_WAIT_MIN * 2 ** (self._login_fails - LOGIN_FAILS), LOGIN_WAIT_MAX)
                    if self._login_fails == LOGIN_FAILS:
                        log.error("LOGIN ERROR: %d rejected logins in a row - check the credentials; "
                                  "further attempts only every %d s to %d s",
                                  LOGIN_FAILS, LOGIN_WAIT_MIN, LOGIN_WAIT_MAX)
                    wait_min = max(wait_min, self._block_time())
            except CaptureError as exc:
                self._report(exc.code, "capture: %s" % exc)
            except Exception as exc:  # the loop must never die
                self._report("internal_error", "unexpected error: %s" % describe_exc(exc))
            self.connected = False
            self.connected_since = None
            if self.stop_event.is_set():
                break
            self.reconnects += 1
            if time.monotonic() - started > 60:
                backoff = BACKOFF_MIN
            self._housekeeping(force_flush=True)
            self.stop_event.wait(max(backoff, wait_min))
            backoff = min(backoff * 2, BACKOFF_MAX)
        self._shutdown()

    def _block_time(self) -> int:
        """Login block time of the box (s), capped; failure/missing method -> 0."""
        try:
            return min(max(int(self._last_cap.block_time()), 0), LOGIN_WAIT_MAX)
        except Exception:
            return 0

    def _report(self, note, logmsg):
        """Count/log/record an error in health; an intended stop is not an error."""
        if self.stop_event.is_set():
            return
        self.last_error = note
        self.counters["errors"] += 1
        log.error("%s", logmsg)
        self._safe_health("error", note)

    def _safe_health(self, event, note):
        try:
            self.db.health(event, note)
        except Exception:
            pass

    def _shutdown(self):
        self._housekeeping(force_flush=True, final=True)
        self.db.close()

    # -- one connection ---------------------------------------------------
    def _session(self):
        cap = self.capture_factory()
        self._cap = self._last_cap = cap
        q = queue.Queue(maxsize=256)
        reader = pcap.PcapReader()

        done = threading.Event()   # session over: the pump must not hang on a full queue

        def put(item):
            while not done.is_set():
                try:
                    q.put(item, timeout=1.0)
                    return
                except queue.Full:
                    pass

        def pump():
            try:
                for chunk in cap.chunks():
                    put(chunk)
                    if done.is_set():
                        return
                put(None)
            except CaptureError as exc:
                put(exc)
            except Exception as exc:
                put(CaptureError(describe_exc(exc), "internal_error"))

        thread = None
        try:
            cap.open()
            if self.stop_event.is_set():
                return
            self.connected = True
            self._credential_fails = 0
            self._login_fails = 0
            self.connected_since = time.time()
            if self._series_since is None:
                self._series_since = self.connected_since
            if self.capture_since is None:
                self.capture_since = self.connected_since
            self._safe_health("connected", "")
            thread = threading.Thread(target=pump, daemon=True)
            thread.start()
            while True:
                try:
                    item = q.get(timeout=1.0)
                except queue.Empty:
                    item = b""
                if isinstance(item, CaptureError):
                    raise item
                if item is None:
                    return
                if item:
                    self._process(reader, item)
                self._housekeeping()
        finally:
            done.set()
            cap.abort()
            try:
                cap.stop()
            except Exception:
                pass
            if thread is not None:
                thread.join(timeout=5)
            self._cap = None

    def _process(self, reader, data):
        try:
            records = reader.feed(data)
        except pcap.PcapError as exc:
            raise CaptureError(str(exc), "pcap_error") from None
        for ts, _orig, frame in records:
            self.counters["packets"] += 1
            self._last_pkt_ts, self._last_pkt_mono = ts, time.monotonic()
            self._last_pkt_wall = time.time()
            pkt, reason = netparse.parse_frame(frame, reader.linktype)
            if pkt is None:
                self.counters["skipped"] += 1
                continue
            if pkt.proto == "tcp":
                self.counters["tcp53"] += 1
                continue
            try:
                msg = dnsparse.parse_message(pkt.payload)
            except dnsparse.DnsError:
                self.counters["dns_errors"] += 1
                continue
            self._add(self.corr.feed(ts, pkt, msg))

    def _rate_ok(self, e) -> bool:
        """Limit per client (key) and minute and globally per minute; above that only count."""
        minute = int(e["ts"] // 60)
        if self._rate_min is None or minute > self._rate_min:
            self._rate_min, self._rate, self._rate_total = minute, {}, 0
        self._rate_total += 1
        if self._rate_total > self.events_per_min:
            return False
        k = client_key(e["client_ip"], e["client_mac"], self.hostmap.nat_macs)
        if k not in self._rate and len(self._rate) >= self.clients_per_day:
            k = OTHER       # bound the dict (clients_per_day also caps distinct clients per minute):
                            # further clients share one counter (and one limit)
        n = self._rate.get(k, 0) + 1
        self._rate[k] = n
        return n <= self.client_per_min

    def _add(self, events):
        top = time.time() + 86400
        for e in events:
            if not (TS_MIN <= e["ts"] <= top):
                self.counters["ts_dropped"] += 1
                continue
            self.status_counts[e["status"]] += 1
            if not self._rate_ok(e):
                self.counters["rate_limited"] += 1
                self.rate_limited_total += 1
                continue
            self.pending.append(e)

    def _tick_time(self):
        """Time base for no_answer: last packet ts + elapsed monotonic time.

        Not max(packet ts, wall clock): if the box clock runs behind, every open
        query would expire as no_answer immediately. This keeps the box time
        authoritative and expiry still works without new packets."""
        if self._last_pkt_ts is None:
            return None
        return self._last_pkt_ts + (time.monotonic() - self._last_pkt_mono)

    # -- periodic work ----------------------------------------------------
    def _due(self, key, every, now):
        if now >= self._next[key]:
            self._next[key] = now + every
            return True
        return False

    def _housekeeping(self, force_flush=False, final=False):
        try:
            self._housekeeping_inner(force_flush, final)
        except Exception as exc:   # the capture must not fail because of side work
            self.counters["errors"] += 1
            log.error("housekeeping: %s", describe_exc(exc))

    def _housekeeping_inner(self, force_flush, final):
        now = time.monotonic()
        t = self._tick_time()
        if t is not None:
            self._add(self.corr.tick(t))
        if self.host_fetch and self._due("hosts", self.hosts_every, now):
            self.hostmap.refresh(self.host_fetch)
            if self.hostmap.errors:
                self.counters["host_errors"] = self.hostmap.errors
        if force_flush or self._due("flush", FLUSH_S, now):
            self.flush()
        if final or self._due("live", LIVE_S, now):
            self.write_live()
        if final or self._due("top", TOP_S, now):
            self.write_top()
        if self._due("ret", RETENTION_S, now):
            try:
                self.db.retention()
            except Exception:
                self.counters["errors"] += 1
        if self._due("stats", STATS_S, now) and not final:
            self._log_stats()

    def flush(self):
        if not self.pending:
            return
        batch, self.pending = self.pending, []
        for e in batch:
            self.live.append({"ts": e["ts"], "name": self.hostmap.name_for(e["client_ip"], e["client_mac"]),
                              "qname": e["qname"], "qtype": e["qtype"], "status": e["status"],
                              "latency_ms": e["latency_ms"], "reply": e["reply"]})
        if self._free_mb() < self.min_free_mb:     # disk guard: only count
            self.counters["disk_guard"] += len(batch)
            now = time.monotonic()
            if self._disk_warn_mono is None or now - self._disk_warn_mono >= 3600:
                self._disk_warn_mono = now
                log.warning("disk almost full (< %d MB free): no database writes", self.min_free_mb)
            return
        try:
            n = self.db.insert_events(batch, self.hostmap.name_for, self.hostmap.nat_macs)
            self.counters["events"] += n
        except Exception as exc:
            self.counters["errors"] += 1
            log.error("database write error: %s", type(exc).__name__)

    def _free_mb(self) -> float:
        try:
            return shutil.disk_usage(str(self.db.path.parent)).free / 1048576
        except OSError:
            return float("inf")

    def _health(self) -> dict:
        """Times as Unix seconds (None = unknown)."""
        def r(x):
            return round(x, 1) if x else None
        return {"connected": self.connected, "last_error": self.last_error,
                "reconnects": self.reconnects, "host_errors": self.hostmap.errors,
                "rate_limited": self.rate_limited_total,
                "capture_since": r(self.capture_since), "connected_since": r(self.connected_since),
                "last_packet_ts": r(self._last_pkt_wall)}

    def live_doc(self):
        return {"generated": _iso(time.time(), self.tz), "health": self._health(),
                "events": list(reversed(self.live))}

    def top_doc(self, now=None):
        now = time.time() if now is None else now
        nat = self.hostmap.nat_macs
        i2m = self.db.ip2mac(nat)    # once per document
        return {
            "generated": _iso(now, self.tz),
            "capture_since": _iso(self.capture_since, self.tz) if self.capture_since else None,
            "health": self._health(),
            "series_24h": self.db.series_24h(now, self._series_since),
            "clients_24h": self.db.clients_24h(now, self.hostmap.name_for, nat_macs=nat),
            "periods": {k: self._period(days, now, i2m, nat)
                        for k, days in (("today", 1), ("7d", 7), ("30d", 30))},
        }

    def _period(self, days, now, ip2mac, nat):
        t = self.db.top(days, now, ip2mac=ip2mac, nat_macs=nat)
        t.pop("top_domains", None)   # not used by the dashboard (top_permitted/top_blocked suffice)
        return t

    def _write_json(self, name, doc):
        try:
            config.write_private(self.out_dir / name, json.dumps(doc, ensure_ascii=False),
                                 self.file_mode, self.dir_mode)
        except Exception as exc:
            self.counters["errors"] += 1
            log.error("JSON write error: %s", type(exc).__name__)

    def write_live(self):
        self._write_json("dns_live.json", self.live_doc())

    def write_top(self):
        try:
            self._write_json("dns_top.json", self.top_doc())
        except Exception as exc:
            self.counters["errors"] += 1
            log.error("top document error: %s", type(exc).__name__)

    def _delta(self, key, value):
        """Cumulative counter -> per-minute delta."""
        d = value - self._deltas.get(key, 0)
        self._deltas[key] = value
        return d

    def _log_stats(self):
        c, s, cc = self.counters, self.status_counts, self.corr.counters
        log.info("packets=%d events=%d blocked=%d allowed=%d nxdomain=%d error=%d no_answer=%d "
                 "orphan_responses=%d open=%d dropped=%d retransmits=%d rate_limited=%d "
                 "ts_dropped=%d disk_guard=%d reconnects=%d errors=%d",
                 c["packets"], c["events"], s["blocked"], s["allowed"], s["nxdomain"], s["error"],
                 s["no_answer"], self._delta("orphans", cc["orphan_responses"]), self.corr.pending,
                 self._delta("dropped", cc["dropped"]), self._delta("retransmits", cc["retransmits"]),
                 c["rate_limited"], c["ts_dropped"], c["disk_guard"], self.reconnects, c["errors"])
        self.counters.clear()
        self.status_counts.clear()


class PrivateRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """Rotating log file that is always created (and re-created after rotation) with mode 600."""

    def _open(self):
        return os.fdopen(config.open_private(self.baseFilename), self.mode,
                         encoding=self.encoding, errors=self.errors)


def _setup_logging(logfile):
    fmt = "%(asctime)s %(levelname)s %(message)s"
    if logfile:
        p = Path(logfile).expanduser()
        config.ensure_private_dir(p.parent)
        h = PrivateRotatingFileHandler(str(p), maxBytes=1 << 20, backupCount=3)
    else:
        h = logging.StreamHandler()
    h.setFormatter(logging.Formatter(fmt))
    logging.basicConfig(level=logging.INFO, handlers=[h])


def main(argv=None) -> int:
    os.umask(0o077)
    ap = argparse.ArgumentParser(description="Capture FRITZ!Box DNS traffic into SQLite and JSON files.")
    ap.add_argument("--config", help="path to the TOML configuration file")
    ap.add_argument("--password-stdin", action="store_true",
                    help="read the capture user's password (one line) from stdin")
    ap.add_argument("--allow-insecure-credentials", action="store_true",
                    help="accept a credentials file readable by group/others")
    args = ap.parse_args(argv)
    try:
        cfg = config.load_config(args.config)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        logging.basicConfig(level=logging.INFO)
        log.error("aborting: invalid configuration: %s", exc)
        return 2
    _setup_logging(cfg.get("log_file"))
    warned = []

    try:
        stdin_pw = read_password_stdin() if args.password_stdin else None

        def get_credentials():
            def warn(msg):
                if not warned:
                    warned.append(1)
                    log.warning("%s", msg)
            return load_credentials(cfg, args.allow_insecure_credentials, stdin_pw, warn=warn)
        get_credentials()      # fail fast on missing or insecure credentials
    except CredentialsError as exc:
        log.error("aborting: %s", exc)
        return 2
    if cfg["box_url"].lower().startswith("http://"):
        log.warning("box_url uses plain http: the session ID, the DNS capture and TR-064 "
                    "digest authentication cross the network unencrypted; "
                    "https with pin_sha256 is recommended")
    config.ensure_private_dir(Path(cfg["db_path"]).parent)
    config.ensure_private_dir(cfg["out_dir"], cfg["output"]["dir_mode"])
    cp = cfg["capture"]
    pin, ca = cfg["pin_sha256"] or None, cfg["ca_file"] or None

    def factory():
        user, password = get_credentials()
        auth = fritz_auth.FritzAuth(cfg["box_url"], user, password, cfg["timeout_seconds"], ca, pin,
                                 allow_legacy_md5=cfg["allow_legacy_md5"])
        return Capture(cfg["box_url"], cfg["interface"], auth, idle_timeout=cp["idle_timeout_s"],
                       conn_factory=fritz_auth.make_conn_factory(cfg["box_url"], pin, ca),
                       connect_timeout=cp["connect_timeout_s"])

    host_fetch = make_fetch(cfg, get_credentials) if cfg["hosts"]["enabled"] else None
    app = App(cfg, factory, host_fetch=host_fetch)
    signal.signal(signal.SIGTERM, app.request_stop)
    signal.signal(signal.SIGINT, app.request_stop)
    app.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
