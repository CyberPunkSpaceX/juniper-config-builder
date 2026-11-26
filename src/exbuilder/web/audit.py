"""Audit log and the scripting API.

Audit log
---------
Every change made in the app is kept in the ``audit_log`` table: who, when, from which address, in which client
and space, what was asked (method and path, never the request body, which can carry passwords) and how it ended
(the HTTP status). The ``audit: ...`` lines the app already logs (SSH fetches, nightly backups, users created,
settings changed...) and sign-ins land there too, with their text. Pure calculations (building a config, a
subnet calculator...) change nothing and are left out. Rows older than ``EXB_AUDIT_DAYS`` (365) are dropped.

Server admins see the whole log; a client admin sees the rows of their clients. ``/tools/audit`` shows it with
filters and a CSV download.

API
---
``/api/v1/...`` with HTTP Basic auth: your user name and the API token from your account page. Pick the client
with ``?client=<id or name>`` (needed when you are in more than one) and the space with ``?space=lab``
(production by default). Read-only people get passwords and keys hidden, like in the web UI.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import re
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

from flask import (
    Blueprint,
    Response,
    abort,
    g,
    has_request_context,
    jsonify,
    render_template,
    request,
)

from .. import __version__, redact
from ..generator import build
from . import auth, clients

bp = Blueprint("audit", __name__)
log = logging.getLogger("exbuilder.audit")

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,              -- 2026-11-26 14:03:12 UTC
    user TEXT NOT NULL DEFAULT '',
    client_id INTEGER,
    client TEXT NOT NULL DEFAULT '',
    space TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL,            -- change, sign-in, event, api
    method TEXT NOT NULL DEFAULT '',
    path TEXT NOT NULL DEFAULT '',
    status INTEGER,
    message TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS audit_log_at ON audit_log (at);
CREATE INDEX IF NOT EXISTS audit_log_client ON audit_log (client_id, at);
"""
KINDS = ("change", "sign-in", "event", "api")
MAX_ROWS = 5000

# POSTs that only compute something and change nothing: not worth a row (unless they log an audit line).
QUIET = {
    "api_generate", "excel_export", "fabric_generate", "fabric_zip", "generate", "import_config", "import_excel",
    "network_map", "network_map_unzip", "backups.compare_configs", "converter.run", "netbox.pull_preview",
    "netbox.push_plan", "toolkit.bulk_csv_template", "toolkit.bulk_run", "toolkit.bulk_zip", "toolkit.calc_poe",
    "toolkit.calc_split", "toolkit.calc_subnet", "toolkit.calc_vlans", "toolkit.checks_run",
    "toolkit.compliance_run", "toolkit.firmware_run", "toolkit.map_build", "clients.select", "clients.set_space",
}
SIGN_IN = {"auth.login", "auth.login_2fa", "auth.logout", "auth.setup", "saml.acs", "sso.oidc_callback"}
SIGN_IN_LOGGERS = ("exbuilder.auth", "exbuilder.sso", "exbuilder.saml")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def keep_days() -> int:
    try:
        return max(1, int(os.environ.get("EXB_AUDIT_DAYS", "365")))
    except ValueError:
        return 365


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(auth.data_dir() / "users.db", timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def migrate(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)


def prune(conn: sqlite3.Connection) -> None:
    cut = (datetime.now(timezone.utc) - timedelta(days=keep_days())).strftime("%Y-%m-%d %H:%M:%S UTC")
    conn.execute("DELETE FROM audit_log WHERE at < ?", (cut,))


def write(conn: sqlite3.Connection, **row) -> None:
    cols = ("at", "user", "client_id", "client", "space", "ip", "kind", "method", "path", "status", "message")
    row.setdefault("at", _now())
    vals = [row.get(k) for k in cols]
    vals = [v[:2000] if isinstance(v, str) else v for v in vals]
    conn.execute(f"INSERT INTO audit_log ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
                 [("" if v is None and k not in ("client_id", "status") else v) for k, v in zip(cols, vals)])


# ------------------------------------------------------------------ capture
def _wanted(record: logging.LogRecord) -> str | None:
    """The text of a log record the audit log keeps, or None."""
    try:
        msg = record.getMessage()
    except Exception:  # noqa: BLE001 - a bad format string must not break the request
        return None
    if msg.startswith("audit:"):
        return msg[6:].strip()
    if record.name in SIGN_IN_LOGGERS and record.levelno >= logging.INFO and not msg.startswith("No users yet"):
        return msg   # sign-ins, failed sign-ins, 2FA on and off
    return None


class Handler(logging.Handler):
    """Collects audit lines: inside a request they join that request's row, outside one (nightly) they get their own."""

    def __init__(self):
        super().__init__(logging.INFO)
        self._lock = threading.Lock()

    def emit(self, record: logging.LogRecord) -> None:
        msg = _wanted(record)
        if msg is None:
            return
        if has_request_context():
            g.setdefault("audit_msgs", []).append(msg)
            return
        try:
            with self._lock:
                conn = _conn()
                try:
                    migrate(conn)
                    write(conn, kind="event", user="(system)", message=msg)
                    conn.commit()
                finally:
                    conn.close()
        except Exception:  # noqa: BLE001 - logging must never raise
            self.handleError(record)


HANDLER = Handler()


def _install_handler() -> None:
    root = logging.getLogger("exbuilder")
    if HANDLER in root.handlers:
        return
    if not logging.getLogger().handlers:
        # Without a root handler, Python prints warnings through its last-resort handler. That stops once a
        # handler is attached here, so keep warnings on stderr (docker logs) ourselves.
        console = logging.StreamHandler()
        console.setLevel(logging.WARNING)
        console.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
        root.addHandler(console)
    root.addHandler(HANDLER)
    if root.getEffectiveLevel() > logging.INFO:
        root.setLevel(logging.INFO)


def _who() -> str:
    user = getattr(g, "user", None)
    if user is not None:
        return user["username"]
    if request.endpoint in ("auth.login",) and request.method == "POST":
        return request.form.get("username", "").strip()[:64]
    if request.authorization and request.authorization.username:
        return request.authorization.username[:64]
    return ""


def _after(resp: Response) -> Response:
    msgs = g.pop("audit_msgs", None)
    method = request.method
    endpoint = request.endpoint or ""
    api = request.path.startswith("/api/")
    if not msgs:
        if method in ("GET", "HEAD", "OPTIONS") or endpoint in QUIET or endpoint in ("auth.login", "auth.login_2fa"):
            return resp   # a sign-in that did not fail or finish logs its own line
        if resp.status_code == 404 and not endpoint:
            return resp
    c = g.get("audit_client")
    cid = (request.view_args or {}).get("cid")
    if c is None and isinstance(cid, int) and getattr(g, "user", None) is not None:
        r = auth.db().execute("SELECT id, name FROM clients WHERE id = ?", (cid,)).fetchone()
        c = {"id": r["id"], "name": r["name"], "space": ""} if r else None
    if c is None and getattr(g, "user", None) is not None and not api:
        try:
            c = clients.current()
        except Exception:  # noqa: BLE001
            c = None
    kind = "sign-in" if endpoint in SIGN_IN else "api" if api else "change"
    try:
        conn = auth.db()
        migrate(conn)
        write(conn, user=_who(), client_id=c["id"] if c else None, client=c["name"] if c else "",
              space=c.get("space", "") if c else "", ip=auth.client_ip()[:64], kind=kind, method=method,
              path=request.path[:300], status=resp.status_code, message="; ".join(msgs or []))
        conn.commit()
    except Exception:  # noqa: BLE001 - the audit log must not break the answer
        log.exception("could not write the audit log")
    return resp


# ------------------------------------------------------------------ who may read it
def readable_clients() -> list[dict] | None:
    """None: everything (server admin). Otherwise the clients where the user is an admin."""
    if clients._is_server_admin():
        return None
    return [c for c in clients.my_clients() if c["role"] == "admin"]


def query(args, scope: list[dict] | None, limit: int = 500) -> list[dict]:
    where, params = [], []
    if scope is not None:
        if not scope:
            return []
        where.append(f"client_id IN ({', '.join('?' * len(scope))})")
        params += [c["id"] for c in scope]
    if (u := str(args.get("user") or "").strip()):
        where.append("user = ? COLLATE NOCASE")
        params.append(u)
    if (cl := str(args.get("client") or "").strip()):
        if cl.isdigit():
            where.append("client_id = ?")
            params.append(int(cl))
        else:
            where.append("client = ? COLLATE NOCASE")
            params.append(cl)
    if (k := str(args.get("kind") or "")) in KINDS:
        where.append("kind = ?")
        params.append(k)
    if (q := str(args.get("q") or "").strip()):
        where.append("(message LIKE ? ESCAPE '\\' OR path LIKE ? ESCAPE '\\' OR ip LIKE ? ESCAPE '\\')")
        like = "%" + re.sub(r"([\\%_])", r"\\\1", q[:100]) + "%"
        params += [like, like, like]
    for key, op in (("since", ">="), ("until", "<=")):
        v = str(args.get(key) or "").strip()
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", v):
            where.append(f"substr(at, 1, 10) {op} ?")
            params.append(v)
    sql = "SELECT * FROM audit_log" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY id DESC LIMIT ?"
    conn = auth.db()
    migrate(conn)
    return [dict(r) for r in conn.execute(sql, params + [max(1, min(limit, MAX_ROWS))])]


def _limit(default: int = 500) -> int:
    try:
        return int(request.args.get("limit", default))
    except ValueError:
        return default


# ------------------------------------------------------------------ page
@bp.get("/tools/audit")
def page():
    scope = readable_clients()
    return render_template("tools/audit.html", version=__version__, can_read=scope is None or bool(scope),
                           everything=scope is None, scope=scope or [], days=keep_days(), kinds=KINDS,
                           base=request.host_url.rstrip("/"), mine=clients.my_clients())


@bp.get("/tools/audit/rows")
def rows():
    scope = readable_clients()
    if scope is not None and not scope:
        clients._json_abort(403, "The audit log is for admins.")
    conn = auth.db()
    migrate(conn)
    prune(conn)
    conn.commit()
    return {"rows": query(request.args, scope, _limit())}


@bp.get("/tools/audit/csv")
def rows_csv():
    scope = readable_clients()
    if scope is not None and not scope:
        abort(403)
    out = io.StringIO()
    cols = ("at", "user", "client", "space", "ip", "kind", "method", "path", "status", "message")
    w = csv.writer(out)
    w.writerow(cols)
    for r in query(request.args, scope, _limit(MAX_ROWS)):
        w.writerow([_cell(r[k]) for k in cols])
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=audit-log.csv"})


def _cell(v):
    """Spreadsheets run cells that start with = + - @ as formulas; a quote keeps them text."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


# ------------------------------------------------------------------ API v1
def _api_error(code: int, message: str):
    resp = jsonify(error=message)
    resp.status_code = code
    abort(resp)


def _api_client(role: str = "viewer") -> dict:
    mine = clients.my_clients()
    want = str(request.args.get("client") or "").strip()
    if want:
        c = next((x for x in mine if str(x["id"]) == want or x["name"].lower() == want.lower()), None)
        if c is None:
            _api_error(404, f"No client {want!r} for you. GET /api/v1/clients lists yours.")
    elif len(mine) == 1:
        c = mine[0]
    elif not mine:
        _api_error(409, "You are not in any client yet.")
    else:
        _api_error(400, "You are in several clients: add ?client=<id or name>.")
    space = str(request.args.get("space") or "production")
    if space not in clients.SPACES:
        _api_error(400, "space is production or lab.")
    c = {**c, "space": space}
    g.audit_client = c
    if clients.RANK[c["role"]] < clients.RANK[role]:
        _api_error(403, f"You need the {role} role in {c['name']} for this.")
    return c


def _project_row(c: dict, pid: int):
    r = auth.db().execute("SELECT * FROM projects WHERE id = ? AND client_id = ? AND space = ?",
                          (pid, c["id"], c["space"])).fetchone()
    if r is None:
        _api_error(404, "No such project in this client and space.")
    return r


@bp.get("/api/v1/clients")
def api_clients():
    return {"clients": [{"id": c["id"], "name": c["name"], "role": c["role"]} for c in clients.my_clients()]}


@bp.get("/api/v1/projects")
def api_projects():
    c = _api_client()
    rows = auth.db().execute("SELECT id, name, updated_at, updated_by FROM projects WHERE client_id = ? AND space = ? "
                             "ORDER BY name COLLATE NOCASE", (c["id"], c["space"]))
    return {"client": c["name"], "space": c["space"], "projects": [dict(r) for r in rows]}


@bp.get("/api/v1/projects/<int:pid>")
def api_project(pid: int):
    c = _api_client()
    r = _project_row(c, pid)
    data = json.loads(r["data"])
    hidden = not clients.can_see_secrets(c)
    return {"id": r["id"], "name": r["name"], "updated_at": r["updated_at"], "updated_by": r["updated_by"],
            "data": redact.project(data) if hidden else data, "redacted": hidden}


@bp.get("/api/v1/projects/<int:pid>/config")
def api_project_config(pid: int):
    c = _api_client()
    data = json.loads(_project_row(c, pid)["data"])
    if not clients.can_see_secrets(c):
        data = redact.project(data)
    result = build(data)
    if result.errors:
        return {"errors": result.errors, "warnings": result.warnings}, 422
    text = result.hier_text if request.args.get("format") == "hierarchy" else result.set_text
    return Response(text, mimetype="text/plain")


@bp.put("/api/v1/projects/<name>")
def api_project_put(name: str):
    from . import MAX_PROJECT_BYTES

    c = _api_client("editor")
    name = name.strip()[:100]
    if not name or not clients.NAME_RE.match(name):
        _api_error(400, "That is not a usable project name.")
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        _api_error(400, "Send the project as a JSON object (the builder's project file).")
    if isinstance(data.get("data"), dict) and set(data) <= {"name", "data"}:
        data = data["data"]   # the shape GET /api/v1/projects/<id> returns
    text = json.dumps(data)
    if len(text) > MAX_PROJECT_BYTES:
        _api_error(413, "Project is too large.")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    db = auth.db()
    existed = db.execute("SELECT 1 FROM projects WHERE client_id = ? AND space = ? AND name = ?",
                         (c["id"], c["space"], name)).fetchone() is not None
    db.execute("INSERT INTO projects (client_id, space, name, data, updated_at, updated_by) VALUES (?, ?, ?, ?, ?, ?) "
               "ON CONFLICT (client_id, space, name) DO UPDATE SET data = excluded.data, "
               "updated_at = excluded.updated_at, updated_by = excluded.updated_by",
               (c["id"], c["space"], name, text, now, g.user["username"]))
    db.commit()
    pid = db.execute("SELECT id FROM projects WHERE client_id = ? AND space = ? AND name = ?",
                     (c["id"], c["space"], name)).fetchone()[0]
    log.info("audit: %s %s project %r over the API", g.user["username"], "updated" if existed else "created", name)
    return {"id": pid, "name": name, "updated_at": now, "created": not existed}, (200 if existed else 201)


@bp.get("/api/v1/backups")
def api_backups():
    c = _api_client()
    sql = ("SELECT id, host, address, source, note, lines, created_at, created_by FROM config_backups "
           "WHERE client_id = ? AND space = ?")
    params: list = [c["id"], c["space"]]
    if (host := str(request.args.get("host") or "").strip()):
        sql += " AND host = ? COLLATE NOCASE"
        params.append(host)
    rows = [dict(r) for r in auth.db().execute(sql + " ORDER BY host COLLATE NOCASE, id DESC", params)]
    if request.args.get("latest"):
        seen, keep = set(), []
        for r in rows:
            if r["host"].lower() not in seen:
                seen.add(r["host"].lower())
                keep.append(r)
        rows = keep
    return {"client": c["name"], "space": c["space"], "backups": rows}


@bp.get("/api/v1/backups/<int:bid>")
def api_backup(bid: int):
    c = _api_client()
    r = auth.db().execute("SELECT * FROM config_backups WHERE id = ? AND client_id = ? AND space = ?",
                          (bid, c["id"], c["space"])).fetchone()
    if r is None:
        _api_error(404, "No such backup in this client and space.")
    hidden = not clients.can_see_secrets(c)
    text = redact.config(r["text"]) if hidden else r["text"]
    if request.args.get("format") == "text":
        return Response(text, mimetype="text/plain")
    out = {k: r[k] for k in ("id", "host", "address", "source", "note", "lines", "created_at", "created_by")}
    return {**out, "text": text, "redacted": hidden}


@bp.get("/api/v1/audit")
def api_audit():
    scope = readable_clients()
    if scope is not None and not scope:
        _api_error(403, "The audit log is for admins.")
    return {"rows": query(request.args, scope, _limit())}


def init_app(app) -> None:
    app.register_blueprint(bp)
    app.after_request(_after)
    _install_handler()
    with app.app_context():
        try:
            conn = _conn()
            migrate(conn)
            prune(conn)
            conn.commit()
            conn.close()
        except sqlite3.Error:
            pass
