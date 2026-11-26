"""The background jobs service: ``exbuilder jobs``.

Runs next to the web service, on the same data volume, as its own process (the
web workers come and go, so they cannot keep a schedule). Every 30 seconds it
starts the nightly backups whose time has come (web/nightly.py). Each run is
claimed in the database first, so a second copy of this service would not run
a backup twice.
"""

from __future__ import annotations

import logging
import signal
import sqlite3
import threading

log = logging.getLogger("exbuilder.jobs")
TICK = 30


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    from .web import auth, create_app, nightly
    create_app()          # creates or upgrades the database tables
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    log.info("jobs service started")
    while not stop.is_set():
        try:
            conn = sqlite3.connect(auth.data_dir() / "users.db", timeout=30)
            try:
                nightly.run_due(conn)
            finally:
                conn.close()
        except Exception:  # noqa: BLE001 - keep the service alive
            log.exception("jobs tick failed")
        stop.wait(TICK)
    log.info("jobs service stopped")
    return 0
