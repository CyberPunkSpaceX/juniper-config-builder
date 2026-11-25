"""Built-in syslog server: switch logs kept separately per client.

Runs inside the jobs service (``switchbuilder jobs``). It listens on UDP and
TCP (``EXB_SYSLOG_PORT``, default 5514; the stack publishes it as port 514 in
host mode, because the swarm routing mesh would hide the switches' addresses).

Each message is given to the client whose log networks contain the sender's
address (the most specific network wins). Messages from an address no client
claims are dropped and counted, so one client never sees another's logs, and a
stranger cannot fill the disk. Logs live in their own database
(``<data>/syslog.db``), apart from users and projects, and each client keeps
them for its own number of days.

Limits: a message is cut at 8 KB, each sender may send ``EXB_SYSLOG_RATE``
messages a second (default 200, the rest are dropped and counted), and each
client keeps at most ``EXB_SYSLOG_MAX_ROWS`` messages (default 2 million).
"""

from __future__ import annotations

import ipaddress
import logging
import os
import queue
import re
import socket
import socketserver
import sqlite3
import threading
import time
from pathlib import Path

log = logging.getLogger("exbuilder.syslog")

MAX_MSG = 8192
SEVERITIES = ("emergency", "alert", "critical", "error", "warning", "notice", "info", "debug")
FACILITIES = ("kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv", "ftp",
              "ntp", "audit", "alert", "clock", "local0", "local1", "local2", "local3", "local4", "local5", "local6",
              "local7")
SCHEMA = """
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    ts REAL NOT NULL,              -- when it arrived (unix time)
    source TEXT NOT NULL,          -- the sender's address
    host TEXT NOT NULL DEFAULT '', -- the host name in the message
    facility INTEGER NOT NULL DEFAULT 1,
    severity INTEGER NOT NULL DEFAULT 6,
    tag TEXT NOT NULL DEFAULT '',
    message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS logs_client_ts ON logs (client_id, ts);
CREATE INDEX IF NOT EXISTS logs_client_sev ON logs (client_id, severity, ts);
"""

_PRI = re.compile(r"^<(\d{1,3})>")
# RFC 5424: <PRI>1 TIMESTAMP HOST APP PROCID MSGID [SD] MSG
_5424 = re.compile(r"^1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|\[.*?\](?:\[.*?\])*) ?(.*)$", re.S)
# RFC 3164: <PRI>Mmm dd hh:mm:ss HOST TAG: MSG (many switches leave out the host, or add a year or a sequence number)
_3164_TIME = re.compile(r"^(?:\d+: )?\*?(?:[A-Z][a-z]{2} [ \d]\d (?:\d{4} )?\d\d:\d\d:\d\d(?:\.\d+)?(?: [A-Z]{2,5})?:?) ")
_TAG = re.compile(r"^([\w./%-]{1,48})(?:\[\d+\])?: ")


def db_path(data_dir: Path) -> Path:
    return Path(data_dir) / "syslog.db"


def connect(data_dir: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path(data_dir), timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    return conn


def parse(data: bytes) -> dict:
    """A syslog datagram -> {facility, severity, host, tag, message}."""
    text = data[:MAX_MSG].decode("utf-8", "replace").replace("\x00", "").strip()
    out = {"facility": 1, "severity": 5, "host": "", "tag": "", "message": text}
    m = _PRI.match(text)
    if m and int(m.group(1)) < 192:
        pri = int(m.group(1))
        out["facility"], out["severity"] = pri // 8, pri % 8
        text = text[m.end():]
    m = _5424.match(text)
    if m:
        out["host"] = "" if m.group(2) == "-" else m.group(2)[:120]
        out["tag"] = "" if m.group(3) == "-" else m.group(3)[:48]
        out["message"] = m.group(7).lstrip("\ufeff").strip() or text
        return out
    m = _3164_TIME.match(text)
    if m:
        text = text[m.end():]
        first = text.split(" ", 1)
        # A host name comes before the tag unless the first word already is the tag ("sshd[12]:", "%LINK-3-UPDOWN:")
        if len(first) == 2 and not first[0].endswith(":") and not _TAG.match(text) and not first[0].startswith("%"):
            out["host"] = first[0][:120]
            text = first[1]
    t = _TAG.match(text)
    if t:
        out["tag"] = t.group(1)
        text = text[t.end():]
    out["message"] = text.strip()
    return out


class Router:
    """Sender address -> client id, from each client's log networks (refreshed every minute)."""

    def __init__(self, load):
        self._load = load            # () -> [(client_id, "net, net")]
        self._nets: list = []
        self._at = 0.0
        self._lock = threading.Lock()

    def refresh(self, force: bool = False) -> None:
        with self._lock:
            if not force and time.monotonic() - self._at < 60:
                return
            nets = []
            for cid, text in self._load():
                for part in re.split(r"[\s,;]+", text or ""):
                    try:
                        nets.append((ipaddress.ip_network(part, strict=False), cid))
                    except ValueError:
                        continue
            nets.sort(key=lambda x: -x[0].prefixlen)       # most specific first
            self._nets, self._at = nets, time.monotonic()

    def client_of(self, addr: str) -> int | None:
        self.refresh()
        try:
            ip = ipaddress.ip_address(addr.split("%")[0])
        except ValueError:
            return None
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        for net, cid in self._nets:
            if ip.version == net.version and ip in net:
                return cid
        return None


class Store:
    """Takes messages from the listeners and writes them in batches."""

    def __init__(self, data_dir: Path, router: Router):
        self.data_dir, self.router = Path(data_dir), router
        self.q: queue.Queue = queue.Queue(maxsize=50_000)
        self.dropped = {"unknown": 0, "rate": 0, "full": 0}
        self._rate: dict[str, list] = {}
        try:
            self.rate = max(1, int(os.environ.get("EXB_SYSLOG_RATE", "200")))
        except ValueError:
            self.rate = 200

    def take(self, data: bytes, addr: str) -> None:
        now = time.time()
        sec = int(now)
        r = self._rate.get(addr)
        if r is None or r[0] != sec:
            if len(self._rate) > 10_000:
                self._rate.clear()
            r = self._rate[addr] = [sec, 0]
        r[1] += 1
        if r[1] > self.rate:
            self.dropped["rate"] += 1
            return
        cid = self.router.client_of(addr)
        if cid is None:
            self.dropped["unknown"] += 1
            return
        try:
            self.q.put_nowait((cid, now, addr, data))
        except queue.Full:
            self.dropped["full"] += 1

    def writer(self, stop: threading.Event) -> None:
        conn = connect(self.data_dir)
        last_report = time.monotonic()
        while not stop.is_set() or not self.q.empty():
            batch = []
            try:
                batch.append(self.q.get(timeout=0.5))
                while len(batch) < 2000:
                    batch.append(self.q.get_nowait())
            except queue.Empty:
                pass
            if batch:
                rows = []
                for cid, ts, addr, data in batch:
                    p = parse(data)
                    rows.append((cid, ts, addr, p["host"], p["facility"], p["severity"], p["tag"], p["message"]))
                try:
                    conn.executemany("INSERT INTO logs (client_id, ts, source, host, facility, severity, tag, message) "
                                     "VALUES (?, ?, ?, ?, ?, ?, ?, ?)", rows)
                    conn.commit()
                except sqlite3.Error:
                    log.exception("syslog: could not store %d messages", len(rows))
            if time.monotonic() - last_report > 3600 and any(self.dropped.values()):
                log.warning("syslog: dropped in the last hour: %s", self.dropped)
                self.dropped = dict.fromkeys(self.dropped, 0)
                last_report = time.monotonic()
        conn.close()


def prune(conn: sqlite3.Connection, keep_days: dict[int, int], max_rows: int | None = None) -> int:
    """Delete logs older than each client's days, and beyond max_rows per client. Returns rows deleted."""
    if max_rows is None:
        try:
            max_rows = int(os.environ.get("EXB_SYSLOG_MAX_ROWS", "2000000"))
        except ValueError:
            max_rows = 2_000_000
    gone = 0
    now = time.time()
    for (cid,) in conn.execute("SELECT DISTINCT client_id FROM logs").fetchall():
        days = keep_days.get(cid, 0)     # a client that turned logs off (or was deleted) keeps nothing
        gone += conn.execute("DELETE FROM logs WHERE client_id = ? AND ts < ?", (cid, now - days * 86400)).rowcount
        extra = conn.execute("SELECT id FROM logs WHERE client_id = ? ORDER BY id DESC LIMIT 1 OFFSET ?",
                             (cid, max_rows)).fetchone()
        if extra:
            gone += conn.execute("DELETE FROM logs WHERE client_id = ? AND id <= ?", (cid, extra[0])).rowcount
    conn.commit()
    return gone


# ------------------------------------------------------------- listeners
class _UDP(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.store.take(self.request[0], self.client_address[0])


class _TCP(socketserver.StreamRequestHandler):
    timeout = 300

    def handle(self):
        """Octet-counted (RFC 6587 "123 <PRI>...") or newline-separated messages."""
        addr = self.client_address[0]
        buf = b""
        while True:
            try:
                chunk = self.request.recv(65536)
            except OSError:
                return
            if not chunk:
                break
            buf += chunk
            while buf:
                m = re.match(rb"^(\d{1,5}) ", buf)
                if m:
                    n = int(m.group(1))
                    if len(buf) < m.end() + n:
                        break
                    self.server.store.take(buf[m.end():m.end() + n], addr)
                    buf = buf[m.end() + n:]
                elif b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if line.strip():
                        self.server.store.take(line, addr)
                else:
                    break
            if len(buf) > MAX_MSG * 4:
                buf = b""
        if buf.strip():
            self.server.store.take(buf, addr)


class _UDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    daemon_threads = True
    allow_reuse_address = True


class _TCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def _bind(cls, handler, port: int, store: Store):
    """An IPv6 socket that also takes IPv4 (addresses arrive as ::ffff:a.b.c.d), or IPv4 only."""
    for family, host in ((socket.AF_INET6, "::"), (socket.AF_INET, "0.0.0.0")):
        klass = type(cls.__name__, (cls,), {"address_family": family})
        try:
            srv = klass((host, port), handler)
            break
        except OSError:
            if family == socket.AF_INET:
                raise
    srv.store = store
    return srv


def serve(data_dir: Path, load_networks, stop: threading.Event, port: int | None = None) -> list:
    """Start the UDP and TCP listeners and the writer. Returns the servers (for tests and shutdown)."""
    if port is None:
        port = int(os.environ.get("EXB_SYSLOG_PORT", "5514") or 5514)
    store = Store(data_dir, Router(load_networks))
    connect(data_dir).close()
    servers = [_bind(_UDPServer, _UDP, port, store), _bind(_TCPServer, _TCP, port, store)]
    for srv in servers:
        threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.5}, daemon=True).start()
    threading.Thread(target=store.writer, args=(stop,), daemon=True).start()
    log.info("syslog server listening on port %d (udp and tcp)", port)
    return servers
