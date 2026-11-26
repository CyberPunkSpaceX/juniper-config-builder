"""The background jobs service: ``switchbuilder jobs``.

Runs next to the web service, on the same data volume, as its own process (the
web workers come and go, so they cannot keep a schedule or a listening port):

* every 30 seconds: the nightly backups whose time has come (web/nightly.py;
  each run is claimed in the database first, so it happens once) and the log
  alerts (web/logs.py);
* the syslog server (syslogd.py), unless ``EXB_SYSLOG_PORT`` is 0;
* every hour: old logs are deleted (each client's days to keep).
"""

from __future__ import annotations

import logging
import os
import signal
import sqlite3
import threading
import time

log = logging.getLogger("switchbuilder.jobs")
TICK = 30


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    from . import syslogd
    from .web import auth, create_app, logs, nightly
    create_app()          # creates or upgrades the database tables
    data = auth.data_dir()
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())

    def users_db():
        return sqlite3.connect(data / "users.db", timeout=30)

    def load_networks():
        conn = users_db()
        try:
            return logs.networks_for(conn)
        finally:
            conn.close()

    if os.environ.get("EXB_SYSLOG_PORT", "5514").strip() not in ("0", ""):
        syslogd.serve(data, load_networks, stop)
    log.info("jobs service started")
    last_prune = 0.0
    while not stop.is_set():
        try:
            conn = users_db()
            logs_conn = syslogd.connect(data)
            try:
                nightly.run_due(conn)
                logs.send_alerts(conn, logs_conn)
                if time.monotonic() - last_prune > 3600:
                    gone = syslogd.prune(logs_conn, logs.keep_days(conn))
                    if gone:
                        log.info("deleted %d old log messages", gone)
                    last_prune = time.monotonic()
            finally:
                conn.close()
                logs_conn.close()
        except Exception:  # noqa: BLE001 - keep the service alive
            log.exception("jobs tick failed")
        stop.wait(TICK)
    log.info("jobs service stopped")
    return 0
