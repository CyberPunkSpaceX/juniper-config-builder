"""Switch logs (syslog) per client: settings, the Logs page, and log alerts.

The syslog server itself runs in the jobs service (``syslogd.py``). Here:

* a client admin turns logs on for the client, lists the networks its switches
  send from (empty = the client's SSH switch networks), the days to keep, and
  optionally an alert for serious messages (sent to the nightly backup alert
  targets, at most one alert every 5 minutes with everything since the last);
* everyone in the client reads and searches the logs on the Logs page.
"""

from __future__ import annotations

import csv
import io
import logging
import os
import re
import sqlite3
import time
from datetime import datetime, timezone

from flask import Blueprint, Response, flash, redirect, render_template, request, url_for

from .. import notify, sshfetch, syslogd
from . import auth, clients

bp = Blueprint("logs", __name__, template_folder="templates")
log = logging.getLogger("exbuilder.logs")

SCHEMA = """
CREATE TABLE IF NOT EXISTS syslog_settings (
    client_id INTEGER PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 0,
    networks TEXT NOT NULL DEFAULT '',      -- empty = the client's SSH switch networks
    keep_days INTEGER NOT NULL DEFAULT 30,
    alert_severity INTEGER NOT NULL DEFAULT -1,   -- -1 = no alerts, else alert at this severity or worse
    alert_match TEXT NOT NULL DEFAULT '',   -- and only when the message contains this text (empty = any)
    alert_last_id INTEGER NOT NULL DEFAULT 0,
    alert_last_ts REAL NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT ''
);
"""
ALERT_GAP = 300          # seconds between two log alerts of one client
PAGE = 500
RANGES = {"1h": 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400, "all": None}


def migrate(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)


def settings_of(conn: sqlite3.Connection, cid: int) -> dict:
    r = conn.execute("SELECT * FROM syslog_settings WHERE client_id = ?", (cid,)).fetchone()
    if r is None:
        return {"client_id": cid, "enabled": 0, "networks": "", "keep_days": 30, "alert_severity": -1,
                "alert_match": "", "alert_last_id": 0, "alert_last_ts": 0, "updated_at": "", "updated_by": ""}
    return dict(r)


def networks_for(conn: sqlite3.Connection) -> list[tuple[int, str]]:
    """[(client_id, networks)] of every client with logs on (the syslog router reads this)."""
    rows = conn.execute("SELECT s.client_id, s.networks, c.ssh_networks FROM syslog_settings s JOIN clients c "
                        "ON c.id = s.client_id WHERE s.enabled = 1").fetchall()
    return [(r[0], r[1] or r[2]) for r in rows]


def keep_days(conn: sqlite3.Connection) -> dict[int, int]:
    return {r[0]: r[1] for r in conn.execute("SELECT client_id, keep_days FROM syslog_settings WHERE enabled = 1")}


def server_address() -> str:
    return os.environ.get("EXB_SYSLOG_ADDRESS", "").strip()


# --------------------------------------------------------------- alerts
def send_alerts(conn: sqlite3.Connection, logs: sqlite3.Connection, now: float | None = None) -> list[int]:
    """Alert each client about serious messages since its last alert. Returns the clients alerted."""
    from . import nightly
    now = now or time.time()
    conn.row_factory = sqlite3.Row
    done = []
    for s in conn.execute("SELECT * FROM syslog_settings WHERE enabled = 1 AND alert_severity >= 0").fetchall():
        s = dict(s)
        if now - s["alert_last_ts"] < ALERT_GAP:
            continue
        cid = s["client_id"]
        if not s["alert_last_ts"]:     # alerts just turned on: start from now, not from old logs
            top = logs.execute("SELECT COALESCE(MAX(id), 0) FROM logs").fetchall()[0][0]
            conn.execute("UPDATE syslog_settings SET alert_last_id = ?, alert_last_ts = 1 WHERE client_id = ?",
                         (top, cid))
            conn.commit()
            continue
        q = "SELECT * FROM logs WHERE client_id = ? AND id > ? AND severity <= ?"
        args: list = [cid, s["alert_last_id"], s["alert_severity"]]
        if s["alert_match"]:
            q += " AND message LIKE ? ESCAPE '\\'"
            args.append("%" + _like(s["alert_match"]) + "%")
        rows = logs.execute(q + " ORDER BY id LIMIT 201", args).fetchall()
        top = logs.execute("SELECT COALESCE(MAX(id), 0) FROM logs").fetchall()[0][0]
        if not rows:
            conn.execute("UPDATE syslog_settings SET alert_last_id = ? WHERE client_id = ?", (max(top, s["alert_last_id"]), cid))
            conn.commit()
            continue
        client = conn.execute("SELECT name FROM clients WHERE id = ?", (cid,)).fetchone()
        ns = nightly.settings_of(conn, cid)
        emails, _ = notify.parse_emails(ns["emails"])
        hooks = nightly.hooks_of(ns)
        more = len(rows) > 200
        rows = rows[:200]
        lines = [f"{_when(r['ts'])} {r['host'] or r['source']} {syslogd.SEVERITIES[r['severity']]}: "
                 f"{(r['tag'] + ': ') if r['tag'] else ''}{r['message'][:300]}" for r in rows]
        if more:
            lines.append("… and more. See the Logs page.")
        title = f"{client['name'] if client else cid}: {len(rows)}{'+' if more else ''} switch log message" \
                f"{'s' if len(rows) != 1 else ''} at {syslogd.SEVERITIES[s['alert_severity']]} or worse"
        if emails or hooks:
            notify.send_all(emails, hooks, title, "\n".join(lines), {"client": client["name"] if client else cid})
        conn.execute("UPDATE syslog_settings SET alert_last_id = ?, alert_last_ts = ? WHERE client_id = ?",
                     (rows[-1]["id"] if more else max(top, rows[-1]["id"]), now, cid))
        conn.commit()
        done.append(cid)
    return done


def _like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _when(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# ------------------------------------------------------------------ pages
def _logs_db():
    path = syslogd.db_path(auth.data_dir())
    if not path.exists():
        return None
    return syslogd.connect(auth.data_dir())


def _query(cid: int, args) -> tuple[list[dict], dict]:
    f = {"q": (args.get("q") or "").strip()[:200], "host": (args.get("host") or "").strip()[:120],
         "sev": args.get("sev", "7"), "range": args.get("range", "24h"), "before": args.get("before", "")}
    if f["range"] not in RANGES:
        f["range"] = "24h"
    sql, params = "SELECT * FROM logs WHERE client_id = ?", [cid]
    try:
        sev = max(0, min(7, int(f["sev"])))
    except ValueError:
        sev = 7
    f["sev"] = str(sev)
    if sev < 7:
        sql += " AND severity <= ?"
        params.append(sev)
    if RANGES[f["range"]]:
        sql += " AND ts >= ?"
        params.append(time.time() - RANGES[f["range"]])
    if f["host"]:
        sql += " AND (host = ? OR source = ?)"
        params += [f["host"], f["host"]]
    if f["q"]:
        for word in f["q"].split()[:5]:
            sql += " AND (message LIKE ? ESCAPE '\\' OR tag LIKE ? ESCAPE '\\')"
            params += ["%" + _like(word) + "%"] * 2
    if f["before"].isdigit():
        sql += " AND id < ?"
        params.append(int(f["before"]))
    conn = _logs_db()
    if conn is None:
        return [], f
    try:
        rows = conn.execute(sql + f" ORDER BY id DESC LIMIT {PAGE}", params).fetchall()
    finally:
        conn.close()
    out = [{"id": r["id"], "time": _when(r["ts"]), "source": r["source"].removeprefix("::ffff:"), "host": r["host"],
            "severity": syslogd.SEVERITIES[r["severity"]], "sev": r["severity"],
            "facility": syslogd.FACILITIES[r["facility"]] if r["facility"] < len(syslogd.FACILITIES) else str(r["facility"]),
            "tag": r["tag"], "message": r["message"]} for r in rows]
    return out, f


@bp.get("/logs")
def logs_page():
    c = clients.current()
    if c is None:
        return redirect(url_for("clients.start_page"))
    s = settings_of(auth.db(), c["id"])
    rows, f = _query(c["id"], request.args)
    hosts = []
    conn = _logs_db()
    if conn is not None:
        try:
            hosts = [r[0] for r in conn.execute(
                "SELECT DISTINCT CASE WHEN host != '' THEN host ELSE source END FROM logs WHERE client_id = ? "
                "AND ts >= ? LIMIT 500", (c["id"], time.time() - 7 * 86400))]
        finally:
            conn.close()
    args = {k: v for k, v in request.args.items() if k in ("q", "host", "sev", "range")}
    older = url_for("logs.logs_page", **args, before=rows[-1]["id"]) if len(rows) == PAGE else ""
    return render_template("logs.html", c=c, s=s, rows=rows, f=f, older=older,
                           download=url_for("logs.logs_download", **request.args), hosts=sorted(hosts, key=str.lower),
                           severities=syslogd.SEVERITIES, ranges=RANGES, page=PAGE, is_admin=c["role"] == "admin")


@bp.get("/logs/data")
def logs_data():
    c = clients.need("viewer")
    rows, f = _query(c["id"], request.args)
    return {"rows": rows, "filters": f}


@bp.get("/logs/download")
def logs_download():
    c = clients.need("viewer")
    rows, _ = _query(c["id"], request.args)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["time (UTC)", "source", "host", "facility", "severity", "tag", "message"])
    for r in rows:
        w.writerow([r["time"], r["source"], r["host"], r["facility"], r["severity"], r["tag"],
                    re.sub(r"^[=+\-@]", "'\\g<0>", r["message"])])   # no formulas in Excel
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=logs-{stamp}.csv"})


@bp.get("/clients/<int:cid>/logs")
def settings_page(cid: int):
    c = clients._client_admin(cid)
    s = settings_of(auth.db(), cid)
    count = 0
    conn = _logs_db()
    if conn is not None:
        try:
            count = conn.execute("SELECT COUNT(*) FROM logs WHERE client_id = ?", (cid,)).fetchone()[0]
        finally:
            conn.close()
    from . import nightly
    ns = nightly.settings_of(auth.db(), cid)
    targets = len(notify.parse_emails(ns["emails"])[0]) + len(nightly.hooks_of(ns))
    return render_template("auth/logs_settings.html", c=c, s=s, count=count, severities=syslogd.SEVERITIES,
                           address=server_address(), ssh_nets=c["ssh_networks"], targets=targets)


@bp.post("/clients/<int:cid>/logs")
def settings_save(cid: int):
    c = clients._client_admin(cid)
    db, who = auth.db(), auth.current_user()["username"]
    back = redirect(url_for("logs.settings_page", cid=cid))
    problems = []
    nets_text = request.form.get("networks", "").strip()
    nets, net_problems = sshfetch.check_networks(nets_text)
    problems += net_problems
    try:
        days = int(request.form.get("keep_days", "30"))
        if not 1 <= days <= 3650:
            raise ValueError
    except ValueError:
        problems.append("Keep logs for 1 to 3650 days.")
        days = 30
    try:
        sev = int(request.form.get("alert_severity", "-1"))
        if not -1 <= sev <= 7:
            raise ValueError
    except ValueError:
        problems.append("Pick an alert level.")
        sev = -1
    match = request.form.get("alert_match", "").strip()[:200]
    enabled = 1 if request.form.get("enabled") else 0
    if enabled and not nets and not sshfetch.check_networks(c["ssh_networks"])[0]:
        problems.append("List the networks the switches send logs from (or set the SSH switch networks first).")
    if problems:
        for p in problems:
            flash(p, "error")
        return back
    old = settings_of(db, cid)
    db.execute("INSERT INTO syslog_settings (client_id, enabled, networks, keep_days, alert_severity, alert_match, "
               "alert_last_id, updated_at, updated_by) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?) ON CONFLICT (client_id) DO UPDATE "
               "SET enabled = excluded.enabled, networks = excluded.networks, keep_days = excluded.keep_days, "
               "alert_severity = excluded.alert_severity, alert_match = excluded.alert_match, "
               "alert_last_ts = CASE WHEN syslog_settings.alert_severity != excluded.alert_severity THEN 0 "
               "ELSE syslog_settings.alert_last_ts END, "
               "updated_at = excluded.updated_at, updated_by = excluded.updated_by",
               (cid, enabled, ", ".join(map(str, nets)), days, sev, match, auth._now(), who))
    db.commit()
    log.warning("audit: %r changed the log settings of client %r (%s, networks %s, %d days, alerts %s)", who,
                c["name"], "on" if enabled else "off", ", ".join(map(str, nets)) or "= SSH networks", days,
                syslogd.SEVERITIES[sev] if sev >= 0 else "off")
    if old["enabled"] and not enabled:
        flash("Logs are off: new messages are dropped, and the stored ones are deleted within the hour.", "ok")
    else:
        flash("Saved. The syslog server picks up the change within a minute.", "ok")
    return back


def init_app(app) -> None:
    app.register_blueprint(bp)
