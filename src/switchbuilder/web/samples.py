"""Sample clients: ready-made training labs that ship with the app.

Each file in ``switchbuilder/samples/*.json`` is one client with its saved
projects and network maps, in Lab and Production. On start the server adds
every sample it has never added before, so a new install (and an existing one
after an upgrade) gets them once. A sample is added only once: delete it and it
stays deleted, also after restarts and upgrades. A Super Admin can add a deleted
sample back on the Clients page.

Everyone signed in can open a sample client as Read-only, so new people have
something to look at. Super Admins (and members made Configurator or Admin in
it) can change it like any other client.

Set ``EXB_SAMPLES=off`` to never add samples on start (they can still be added
by hand on the Clients page).

A sample file looks like::

    {"key": "evpn-erb", "name": "Training Lab - EVPN/VXLAN ERB",
     "description": "One line shown on the Clients page.",
     "projects": [{"space": "lab", "name": "...", "data": {...}}],
     "maps": [{"space": "lab", "name": "...", "data": {...}}]}
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
from importlib import resources

log = logging.getLogger("switchbuilder.samples")

KEY_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")
SPACES = ("production", "lab")
# Every root and user password in the shipped samples is the hash of this (never a real one).
SAMPLE_PASSWORD = "Sample-Lab-Root1"
SAMPLE_PASSWORD_NOTE = f"Switch root and labadmin password: {SAMPLE_PASSWORD}."

SCHEMA = """
CREATE TABLE IF NOT EXISTS samples_added (
    key TEXT PRIMARY KEY,
    added_at TEXT NOT NULL
);
"""


def enabled() -> bool:
    return os.environ.get("EXB_SAMPLES", "on").strip().lower() not in ("0", "off", "false", "no")


def available() -> list[dict]:
    """Every sample shipped with the app, sorted by name."""
    out = []
    folder = resources.files("switchbuilder") / "samples"
    if not folder.is_dir():
        return out
    for f in folder.iterdir():
        if not f.name.endswith(".json"):
            continue
        try:
            s = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            log.exception("sample %s is not valid JSON, skipped", f.name)
            continue
        if not isinstance(s, dict) or not KEY_RE.match(str(s.get("key", ""))) or not s.get("name"):
            log.warning("sample %s has no key or name, skipped", f.name)
            continue
        out.append(s)
    return sorted(out, key=lambda s: s["name"].lower())


def migrate(conn: sqlite3.Connection) -> None:
    """Add the ``clients.sample`` column and the record of added samples, then add new samples."""
    conn.executescript(SCHEMA)
    if "sample" not in {r[1] for r in conn.execute("PRAGMA table_info(clients)")}:
        conn.execute("ALTER TABLE clients ADD COLUMN sample TEXT")
    if enabled():
        done = {r[0] for r in conn.execute("SELECT key FROM samples_added")}
        for s in available():
            if s["key"] not in done:
                add(conn, s)


def add(conn: sqlite3.Connection, s: dict) -> int:
    """Add one sample as a client (or mark the client with its name as that sample). Returns the client id."""
    from .auth import _now
    now = _now()
    have = conn.execute("SELECT id FROM clients WHERE name = ?", (s["name"],)).fetchone()
    if have:   # already made by hand on this server (or renamed back): only mark it as the sample
        cid = have[0]
        conn.execute("UPDATE clients SET sample = ? WHERE id = ?", (s["key"], cid))
    else:
        cid = conn.execute("INSERT INTO clients (name, created_at, sample) VALUES (?, ?, ?)",
                           (s["name"], now, s["key"])).lastrowid
        for table in ("projects", "maps"):
            for item in s.get(table) or []:
                space = item.get("space") if item.get("space") in SPACES else "lab"
                name = str(item.get("name") or "").strip()[:100]
                if not name or not isinstance(item.get("data"), dict):
                    continue
                conn.execute(f"INSERT OR IGNORE INTO {table} (client_id, space, name, data, updated_at, updated_by) "
                             "VALUES (?, ?, ?, ?, ?, 'sample')", (cid, space, name, json.dumps(item["data"]), now))
    conn.execute("INSERT OR REPLACE INTO samples_added (key, added_at) VALUES (?, ?)", (s["key"], now))
    log.warning("Added the sample client %r.", s["name"])
    return cid


def missing(conn: sqlite3.Connection) -> list[dict]:
    """Samples with no client right now (deleted, or never added), for the Clients page."""
    have = {r[0] for r in conn.execute("SELECT sample FROM clients WHERE sample IS NOT NULL")}
    return [s for s in available() if s["key"] not in have]


def descriptions() -> dict:
    return {s["key"]: s.get("description", "") for s in available()}
