"""SQLite storage: individual queries (24 h) and daily totals (30 days).

Privacy: contents (domains/devices) are never logged.
"""
import os
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path

from config import ensure_private_dir, open_private

SCHEMA = """
CREATE TABLE IF NOT EXISTS dns_events (
  ts REAL NOT NULL, client_ip TEXT, client_mac TEXT, qname TEXT NOT NULL,
  qtype TEXT, status TEXT NOT NULL, rcode INTEGER, latency_ms REAL, server_ip TEXT);
CREATE INDEX IF NOT EXISTS idx_dns_events_ts ON dns_events(ts);
CREATE TABLE IF NOT EXISTS dns_daily_domain (
  day TEXT NOT NULL, qname TEXT NOT NULL, status TEXT NOT NULL, n INTEGER NOT NULL,
  PRIMARY KEY (day, qname, status));
CREATE TABLE IF NOT EXISTS dns_daily_client (
  day TEXT NOT NULL, client_key TEXT NOT NULL, name TEXT, total INTEGER NOT NULL,
  blocked INTEGER NOT NULL, PRIMARY KEY (day, client_key));
CREATE TABLE IF NOT EXISTS dns_daily_qtype (
  day TEXT NOT NULL, qtype TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (day, qtype));
CREATE TABLE IF NOT EXISTS capture_health (ts REAL NOT NULL, event TEXT NOT NULL, note TEXT);
"""


def local_day(ts: float, tz=None) -> str:
    """Calendar day of ``ts`` in ``tz`` (None = local system time zone)."""
    return datetime.fromtimestamp(ts, tz).strftime("%Y-%m-%d")


OTHER = "(other)"   # catch-all row once the daily limit of new domains is reached


def client_key(ip, mac, nat_macs=None) -> str:
    """Device = MAC (merges IPv4+IPv6); without a MAC, or with a NAT MAC (repeater), the IP."""
    if mac and not (nat_macs and mac.lower() in nat_macs):
        return mac
    return ip or "?"


class Db:
    def __init__(self, path, events_hours=24, daily_days=30, domains_per_day=20000, tz=None,
                 clients_per_day=500):
        self.path = Path(path).expanduser()
        ensure_private_dir(self.path.parent)
        self.tz = tz
        self.events_hours = events_hours
        self.daily_days = daily_days
        self.domains_per_day = domains_per_day
        self.clients_per_day = clients_per_day
        self._cli_count = {}
        self._dom_count = {}
        # The database is always private (600; new directory 700), whatever [output] says.
        os.close(open_private(self.path))   # exists with mode 600 before SQLite touches it
        old_umask = os.umask(0o077)          # -wal / -shm are created by SQLite itself
        try:
            self.conn = sqlite3.connect(str(self.path))
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")
            self.conn.execute("PRAGMA journal_size_limit=8388608")
            self.conn.executescript(SCHEMA)
            self.conn.commit()
        finally:
            os.umask(old_umask)
        for suffix in ("", "-wal", "-shm"):
            try:
                os.chmod(str(self.path) + suffix, 0o600)
            except OSError:
                pass

    def close(self):
        try:
            self.conn.close()
        except sqlite3.Error:
            pass

    def _cap_domains(self, dom_names_by_day) -> dict:
        """Limit new domains per day: -> {(day, qname): replacement qname}."""
        remap = {}
        for day, names in dom_names_by_day.items():
            if day not in self._dom_count:
                self._dom_count[day] = self.conn.execute(
                    "SELECT COUNT(DISTINCT qname) FROM dns_daily_domain WHERE day=?", (day,)).fetchone()[0]
            names = [n for n in names if n != OTHER]
            existing = set()
            for i in range(0, len(names), 500):
                part = names[i:i + 500]
                existing.update(r[0] for r in self.conn.execute(
                    "SELECT DISTINCT qname FROM dns_daily_domain WHERE day=? AND qname IN (%s)"
                    % ",".join("?" * len(part)), [day] + part))
            room = max(0, self.domains_per_day - self._dom_count[day])
            taken = 0
            for n in names:
                if n in existing:
                    continue
                if taken < room:
                    taken += 1
                else:
                    remap[(day, n)] = OTHER
            self._dom_count[day] += taken
        return remap

    def _cap_clients(self, keys_by_day) -> dict:
        """Limit distinct clients per day: -> {(day, client_key): OTHER} for new clients over the limit."""
        remap = {}
        for day, keys in keys_by_day.items():
            if day not in self._cli_count:
                self._cli_count[day] = self.conn.execute(
                    "SELECT COUNT(*) FROM dns_daily_client WHERE day=? AND client_key!=?",
                    (day, OTHER)).fetchone()[0]
            keys = [k for k in keys if k != OTHER]
            existing = set()
            for i in range(0, len(keys), 500):
                part = keys[i:i + 500]
                existing.update(r[0] for r in self.conn.execute(
                    "SELECT client_key FROM dns_daily_client WHERE day=? AND client_key IN (%s)"
                    % ",".join("?" * len(part)), [day] + part))
            room = max(0, self.clients_per_day - self._cli_count[day])
            taken = 0
            for k in keys:
                if k in existing:
                    continue
                if taken < room:
                    taken += 1
                else:
                    remap[(day, k)] = OTHER
            self._cli_count[day] += taken
        return remap

    def insert_events(self, events, name_fn=None, nat_macs=None) -> int:
        """Batch insert + upsert of the daily totals in ONE transaction."""
        if not events:
            return 0
        dom, cli, qt = {}, {}, {}
        rows = []
        names_by_day = {}
        for e in events:
            day = local_day(e["ts"], self.tz)
            names_by_day.setdefault(day, {})[e["qname"]] = None   # ordered set
        remap = self._cap_domains({d: list(n) for d, n in names_by_day.items()})
        keys_by_day = {}
        for e in events:
            keys_by_day.setdefault(local_day(e["ts"], self.tz), {})[
                client_key(e["client_ip"], e["client_mac"], nat_macs)] = None
        cremap = self._cap_clients({d: list(k) for d, k in keys_by_day.items()})
        for e in events:
            rows.append((e["ts"], e["client_ip"], e["client_mac"], e["qname"], e["qtype"],
                         e["status"], e["rcode"], e["latency_ms"], e.get("server_ip")))
            day = local_day(e["ts"], self.tz)
            k = (day, remap.get((day, e["qname"]), e["qname"]), e["status"])
            dom[k] = dom.get(k, 0) + 1
            qk = (day, e["qtype"] or "?")
            qt[qk] = qt.get(qk, 0) + 1
            ck = client_key(e["client_ip"], e["client_mac"], nat_macs)
            name = name_fn(e["client_ip"], e["client_mac"]) if name_fn else ck
            if (day, ck) in cremap:     # over the daily client limit: shared "(other)" row
                ck, name = OTHER, OTHER
            # never overwrite a real name with a raw address (None = do not overwrite)
            real = name not in (e["client_ip"], e["client_mac"], ck, "?", None, "")
            c = cli.setdefault((day, ck), [name, 0, 0, False])
            if real or not c[3]:
                c[0], c[3] = name, c[3] or real
            c[1] += 1
            c[2] += 1 if e["status"] == "blocked" else 0
        with self.conn:
            self.conn.executemany(
                "INSERT INTO dns_events(ts,client_ip,client_mac,qname,qtype,status,rcode,latency_ms,server_ip) "
                "VALUES (?,?,?,?,?,?,?,?,?)", rows)
            self.conn.executemany(
                "INSERT INTO dns_daily_domain(day,qname,status,n) VALUES (?,?,?,?) "
                "ON CONFLICT(day,qname,status) DO UPDATE SET n=n+excluded.n",
                [(d, q, s, n) for (d, q, s), n in dom.items()])
            self.conn.executemany(
                "INSERT INTO dns_daily_qtype(day,qtype,n) VALUES (?,?,?) "
                "ON CONFLICT(day,qtype) DO UPDATE SET n=n+excluded.n",
                [(d, k, n) for (d, k), n in qt.items()])
            self.conn.executemany(
                "INSERT INTO dns_daily_client(day,client_key,name,total,blocked) VALUES (?1,?2,?3,?4,?5) "
                "ON CONFLICT(day,client_key) DO UPDATE SET "
                "name=CASE WHEN ?6 THEN excluded.name ELSE COALESCE(name, excluded.name) END, "
                "total=total+excluded.total, blocked=blocked+excluded.blocked",
                [(d, k, v[0], v[1], v[2], int(v[3])) for (d, k), v in cli.items()])
        return len(rows)

    def retention(self, now=None) -> dict:
        now = time.time() if now is None else now
        cutoff_day = (datetime.fromtimestamp(now, self.tz).date()
                      - timedelta(days=self.daily_days - 1)).isoformat()
        with self.conn:
            a = self.conn.execute("DELETE FROM dns_events WHERE ts < ?",
                                  (now - self.events_hours * 3600,)).rowcount
            b = self.conn.execute("DELETE FROM dns_daily_domain WHERE day < ?", (cutoff_day,)).rowcount
            c = self.conn.execute("DELETE FROM dns_daily_client WHERE day < ?", (cutoff_day,)).rowcount
            self.conn.execute("DELETE FROM dns_daily_qtype WHERE day < ?", (cutoff_day,))
            self.conn.execute("DELETE FROM capture_health WHERE ts < ?", (now - self.daily_days * 86400,))
        self._dom_count.clear()
        self._cli_count.clear()
        try:
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.Error:
            pass
        return {"events": a, "domain_rows": b, "client_rows": c}

    def first_connected(self, daily_days, now=None):
        """Oldest 'connected' health entry within the retention window (Unix seconds) or None."""
        now = time.time() if now is None else now
        row = self.conn.execute("SELECT MIN(ts) FROM capture_health WHERE event='connected' AND ts>=?",
                                (now - daily_days * 86400,)).fetchone()
        return row[0] if row and row[0] is not None else None

    def health(self, event, note="", ts=None):
        with self.conn:
            self.conn.execute("INSERT INTO capture_health VALUES (?,?,?)",
                              (time.time() if ts is None else ts, event, note[:300]))

    def _since_day(self, days, now):
        return (datetime.fromtimestamp(now, self.tz).date() - timedelta(days=days - 1)).isoformat()

    def ip2mac(self, nat_macs=None) -> dict:
        """IP -> MAC from dns_events (without NAT MACs); for rows keyed by IP.

        At most ``clients_per_day`` distinct (IP, MAC) pairs are read (most recent
        first), so a device with changing MACs cannot blow up memory."""
        nat = nat_macs or ()
        rows = self.conn.execute(
            "SELECT client_ip, client_mac FROM dns_events "
            "WHERE client_ip IS NOT NULL AND client_mac IS NOT NULL AND client_mac!='' "
            "GROUP BY client_ip, client_mac ORDER BY MAX(ts) DESC LIMIT ?",
            (self.clients_per_day,)).fetchall()
        return {ip: mac for ip, mac in reversed(rows) if mac.lower() not in nat}  # newest wins

    def top(self, days, now=None, limit=10, ip2mac=None, nat_macs=None) -> dict:
        now = time.time() if now is None else now
        since = self._since_day(days, now)
        q = self.conn.execute
        total, blocked = q(
            "SELECT COALESCE(SUM(n),0), COALESCE(SUM(CASE WHEN status='blocked' THEN n END),0) "
            "FROM dns_daily_domain WHERE day>=?", (since,)).fetchone()
        dom = [{"qname": r[0], "n": r[1]} for r in q(
            "SELECT qname, SUM(n) s FROM dns_daily_domain WHERE day>=? GROUP BY qname "
            "ORDER BY s DESC, qname LIMIT ?", (since, limit))]
        blk = [{"qname": r[0], "n": r[1]} for r in q(
            "SELECT qname, SUM(n) s FROM dns_daily_domain WHERE day>=? AND status='blocked' "
            "GROUP BY qname ORDER BY s DESC, qname LIMIT ?", (since, limit))]
        # Rows keyed by IP (clients without a MAC, or NAT MACs) are mapped to the MAC
        # via the existing dns_events (retention: events_hours), so devices do not
        # appear twice.
        if ip2mac is None:
            ip2mac = self.ip2mac(nat_macs)
        names, agg = {}, {}
        for k, name, tot, blk_n in q("SELECT client_key, name, total, blocked FROM dns_daily_client "
                                     "WHERE day>=? ORDER BY day", (since,)):
            k = ip2mac.get(k, k)
            names[k] = name or names.get(k) or k
            a = agg.setdefault(k, [0, 0])
            a[0] += tot
            a[1] += blk_n
        by_total = [{"name": names[k], "n": v[0], "blocked": v[1]} for k, v in sorted(
            agg.items(), key=lambda kv: (-kv[1][0], kv[0]))[:limit]]
        by_blk = [{"name": names[k], "n": v[1], "total": v[0]} for k, v in sorted(
            ((k, v) for k, v in agg.items() if v[1] > 0),
            key=lambda kv: (-kv[1][1], kv[0]))[:limit]]
        perm = [{"qname": r[0], "n": r[1]} for r in q(
            "SELECT qname, SUM(n) s FROM dns_daily_domain WHERE day>=? AND status!='blocked' "
            "GROUP BY qname ORDER BY s DESC, qname LIMIT ?", (since, limit))]
        statuses = {r[0]: r[1] for r in q(
            "SELECT status, SUM(n) FROM dns_daily_domain WHERE day>=? GROUP BY status", (since,))}
        qrows = q("SELECT qtype, SUM(n) s FROM dns_daily_qtype WHERE day>=? GROUP BY qtype "
                  "ORDER BY s DESC, qtype", (since,)).fetchall()
        qsum = sum(r[1] for r in qrows) or 1
        qtypes = [{"qtype": r[0], "n": r[1], "pct": round(r[1] * 100.0 / qsum, 1)} for r in qrows]
        active = len(agg)
        return {"total": total, "blocked": blocked, "top_domains": dom, "top_permitted": perm,
                "qtypes": qtypes, "statuses": statuses, "active_clients": active, "top_blocked": blk,
                "top_clients": by_total, "top_clients_blocked": by_blk}

    # -- 24 h series (10 min buckets, aligned to the epoch) -------------------
    STEP = 600
    NB = 144

    def _window(self, now):
        end = int(now // self.STEP) * self.STEP
        return end - (self.NB - 1) * self.STEP

    def series_24h(self, now=None, since=None) -> dict:
        """since: earliest known data time; buckets entirely before it are null."""
        now = time.time() if now is None else now
        start = self._window(now)
        rows = self.conn.execute(
            "SELECT CAST(ts/? AS INTEGER) b, COUNT(*), SUM(status='blocked'), SUM(status='nxdomain'), MIN(ts), SUM(status='no_answer') "
            "FROM dns_events WHERE ts>=? GROUP BY b", (self.STEP, start)).fetchall()
        data = {r[0] * self.STEP: r for r in rows}
        first = min([r[4] for r in rows], default=None)
        cands = [x for x in (since, first) if x is not None]
        eff = min(cands) if cands else None
        out = []
        for i in range(self.NB):
            ts = start + i * self.STEP
            if eff is None or ts + self.STEP <= eff:
                out.append({"ts": ts, "allowed": None, "blocked": None, "nxdomain": None, "no_answer": None})
                continue
            r = data.get(ts)
            tot, blk, nx, na = (r[1], r[2] or 0, r[3] or 0, r[5] or 0) if r else (0, 0, 0, 0)
            out.append({"ts": ts, "allowed": tot - blk, "blocked": blk, "nxdomain": nx, "no_answer": na})
        return {"start": start, "step": self.STEP, "buckets": out}

    def clients_24h(self, now=None, name_fn=None, limit=6, nat_macs=None) -> dict:
        """Top ``limit`` clients (series per bucket) plus the rest.

        Memory and run time are bounded: only the ``clients_per_day`` busiest
        (IP, MAC) pairs are ranked, series are read for the top clients only and
        the rest is the bucket total minus the top series."""
        now = time.time() if now is None else now
        start = self._window(now)
        first = start // self.STEP
        q = self.conn.execute
        pairs = q("SELECT client_ip, client_mac, COUNT(*) c FROM dns_events WHERE ts>=? "
                  "GROUP BY client_ip, client_mac ORDER BY c DESC, client_ip, client_mac LIMIT ?",
                  (start, max(self.clients_per_day, limit))).fetchall()
        tot = {}
        for ip, mac, c in pairs:
            tot[client_key(ip, mac, nat_macs)] = tot.get(client_key(ip, mac, nat_macs), 0) + c
        top_keys = [k for k, _ in sorted(tot.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]]
        sel = [(ip, mac) for ip, mac, _ in pairs if client_key(ip, mac, nat_macs) in top_keys][:200]
        per = {k: [0] * self.NB for k in top_keys}
        blk = {k: [0] * self.NB for k in top_keys}
        ident = {}
        if sel:
            cond = " OR ".join(["(client_ip IS ? AND client_mac IS ?)"] * len(sel))
            args = [x for pair in sel for x in pair]
            for b, ip, mac, n, nb in q(
                    "SELECT CAST(ts/? AS INTEGER) b, client_ip, client_mac, COUNT(*), SUM(status='blocked') "
                    f"FROM dns_events WHERE ts>=? AND ({cond}) GROUP BY b, client_ip, client_mac",
                    [self.STEP, start, *args]).fetchall():
                k = client_key(ip, mac, nat_macs)
                idx = b - first
                if k in per and 0 <= idx < self.NB:
                    per[k][idx] += n
                    blk[k][idx] += nb or 0
                    ident[k] = (ip, mac)
        rest = [0] * self.NB
        rest_b = [0] * self.NB
        for b, n, nb in q("SELECT CAST(ts/? AS INTEGER) b, COUNT(*), SUM(status='blocked') "
                          "FROM dns_events WHERE ts>=? GROUP BY b", (self.STEP, start)).fetchall():
            if 0 <= b - first < self.NB:
                rest[b - first] = n
                rest_b[b - first] = nb or 0
        clients = []
        for k in top_keys:
            if not sum(per[k]):
                continue
            for i in range(self.NB):
                rest[i] -= per[k][i]
                rest_b[i] -= blk[k][i]
            ip, mac = ident[k]
            clients.append({"name": name_fn(ip, mac) if name_fn else k, "total": sum(per[k]),
                            "blocked": sum(blk[k]), "series": per[k], "blocked_series": blk[k]})
        return {"start": start, "step": self.STEP, "clients": clients,
                "rest": {"total": sum(rest), "blocked": sum(rest_b), "series": rest, "blocked_series": rest_b}}
