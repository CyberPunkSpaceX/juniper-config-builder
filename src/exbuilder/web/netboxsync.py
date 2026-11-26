"""NetBox sync page (see netbox.py): per-client NetBox settings, pull devices into projects, push projects to NetBox.

A client admin sets the NetBox address and API token here (the token is encrypted with the master key). Editors
can pull devices into projects of the current space. Pushing to NetBox changes another system, so it needs the
client admin role; the plan is always shown first and is worked out again on the server when it is applied.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from flask import Blueprint, abort, render_template, request

from .. import __version__, netbox
from . import auth, clients

bp = Blueprint("netbox", __name__, url_prefix="/tools/netbox")
log = logging.getLogger("exbuilder.netbox")
MAX_PROJECT_BYTES = 512 * 1024

SCHEMA = """
CREATE TABLE IF NOT EXISTS netbox_settings (
    client_id INTEGER PRIMARY KEY,
    url TEXT NOT NULL,
    token TEXT NOT NULL,           -- encrypted with the master key
    verify INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL
);
"""


def _db():
    db = auth.db()
    db.executescript(SCHEMA)
    return db


def _row(cid: int):
    return _db().execute("SELECT * FROM netbox_settings WHERE client_id = ?", (cid,)).fetchone()


def _connect(cid: int) -> netbox.Netbox:
    r = _row(cid)
    if r is None:
        _err(409, "NetBox is not set up for this client yet. A client admin adds it at the top of this page.")
    token = clients._fernet().decrypt(r["token"].encode()).decode()
    try:
        return netbox.Netbox(r["url"], token, verify_tls=bool(r["verify"]))
    except netbox.NetboxError as exc:
        _err(400, str(exc))


def _err(code: int, message: str):
    clients._json_abort(code, message)


def _body() -> dict:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        abort(400, "Send a JSON object.")
    return data


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


@bp.get("/")
def page():
    c = clients.current()
    r = _row(c["id"]) if c else None
    return render_template("tools/netbox.html", version=__version__, client=c,
                           nb={"configured": r is not None, "url": r["url"] if r else "", "verify": bool(r["verify"]) if r else True,
                               "updated": f"{r['updated_at']} by {r['updated_by']}" if r else ""},
                           role=c["role"] if c else "")


@bp.post("/settings")
def save_settings():
    c = clients.need("admin")
    body = _body()
    url = str(body.get("url") or "").strip()
    if not url:
        _db().execute("DELETE FROM netbox_settings WHERE client_id = ?", (c["id"],))
        auth.db().commit()
        log.info("audit: %s removed NetBox from client %r", auth.current_user()["username"], c["name"])
        return {"ok": True, "configured": False}
    try:
        url = netbox.check_url(url)
    except netbox.NetboxError as exc:
        return {"error": str(exc)}, 400
    token = str(body.get("token") or "").strip()
    old = _row(c["id"])
    if not token and old is None:
        return {"error": "Paste the NetBox API token."}, 400
    if token and (len(token) > 300 or any(ch.isspace() for ch in token)):
        return {"error": "That does not look like a NetBox API token."}, 400
    enc = clients._fernet().encrypt(token.encode()).decode() if token else old["token"]
    _db().execute("INSERT INTO netbox_settings (client_id, url, token, verify, updated_at, updated_by) VALUES (?, ?, ?, ?, ?, ?) "
                  "ON CONFLICT (client_id) DO UPDATE SET url = excluded.url, token = excluded.token, "
                  "verify = excluded.verify, updated_at = excluded.updated_at, updated_by = excluded.updated_by",
                  (c["id"], url, enc, 0 if body.get("insecure") else 1, _now(), auth.current_user()["username"]))
    auth.db().commit()
    log.info("audit: %s set NetBox for client %r to %s", auth.current_user()["username"], c["name"], url)
    return {"ok": True, "configured": True, "url": url}


@bp.get("/sites")
def sites():
    c = clients.need("viewer")
    nb = _connect(c["id"])
    try:
        status = nb.status()
        sites = nb.list("/api/dcim/sites/")
        roles = nb.list("/api/dcim/device-roles/")
    except netbox.NetboxError as exc:
        return {"error": str(exc)}, 502
    return {"version": status.get("netbox-version", ""),
            "sites": [{"id": s["id"], "name": s.get("name", "")} for s in sites],
            "roles": [{"id": r["id"], "name": r.get("name", "")} for r in roles]}


def _site(body) -> int:
    try:
        return int(body.get("site_id"))
    except (TypeError, ValueError):
        _err(400, "Pick a NetBox site.")


def _templates(c, body) -> dict:
    """vendor -> template project, from the saved projects the user picked."""
    out = {}
    ids = [x for x in body.get("template_ids") or [] if str(x).isdigit()][:20]
    for pid in ids:
        r = auth.db().execute("SELECT data FROM projects WHERE id = ? AND client_id = ? AND space = ?",
                              (int(pid), c["id"], c["space"])).fetchone()
        if r:
            data = json.loads(r["data"])
            out.setdefault(str(data.get("vendor") or "juniper"), data)
    return out


@bp.post("/pull")
def pull_preview():
    c = clients.need("viewer")
    body = _body()
    from . import _defaults
    try:
        return netbox.pull(_connect(c["id"]), _site(body), _templates(c, body), _defaults)
    except netbox.NetboxError as exc:
        return {"error": str(exc)}, 502


@bp.post("/pull/save")
def pull_save():
    """Pull again and save the picked devices as projects of the current client and space."""
    c = clients.need("editor")
    body = _body()
    from . import _defaults
    try:
        res = netbox.pull(_connect(c["id"]), _site(body), _templates(c, body), _defaults)
    except netbox.NetboxError as exc:
        return {"error": str(exc)}, 502
    want = {int(x) for x in body.get("device_ids") or [] if str(x).isdigit()}
    picked = [d for d in res["devices"] if d.get("project") and (not want or d["netbox_id"] in want)]
    if not picked:
        return {"error": "No devices to save."}, 400
    db = auth.db()
    names = [d["name"][:100] for d in picked]
    q = ",".join("?" * len(names))
    taken = [r[0] for r in db.execute(f"SELECT name FROM projects WHERE client_id = ? AND space = ? AND name IN ({q})",
                                      (c["id"], c["space"], *names))]
    if taken and not body.get("overwrite"):
        return {"error": f"{len(taken)} of these are already projects here: {', '.join(taken[:10])}. Tick “Replace "
                         "projects with the same name” to update them.", "exists": taken}, 409
    user, now = auth.current_user()["username"], _now()
    for d, name in zip(picked, names):
        text = json.dumps(d["project"])
        if len(text) > MAX_PROJECT_BYTES:
            continue
        db.execute("INSERT INTO projects (client_id, space, name, data, updated_at, updated_by) VALUES (?, ?, ?, ?, ?, ?) "
                   "ON CONFLICT (client_id, space, name) DO UPDATE SET data = excluded.data, "
                   "updated_at = excluded.updated_at, updated_by = excluded.updated_by",
                   (c["id"], c["space"], name, text, now, user))
    db.commit()
    log.info("audit: %s pulled %d devices from NetBox site %s into %s (%s)", user, len(picked), res["site"].get("name"),
             c["name"], c["space"])
    return {"saved": len(picked), "client": c["name"], "space": c["space"]}


def _push_projects(c, body) -> list[dict]:
    ids = [int(x) for x in body.get("project_ids") or [] if str(x).isdigit()][:netbox.MAX_DEVICES]
    if not ids:
        _err(400, "Pick the projects to push.")
    q = ",".join("?" * len(ids))
    rows = auth.db().execute(f"SELECT name, data FROM projects WHERE client_id = ? AND space = ? AND id IN ({q}) "
                             "ORDER BY name COLLATE NOCASE", (c["id"], c["space"], *ids)).fetchall()
    return [{"name": r["name"], "data": json.loads(r["data"])} for r in rows]


def _role(body) -> int | None:
    try:
        return int(body.get("role_id")) if body.get("role_id") not in (None, "") else None
    except (TypeError, ValueError):
        return None


@bp.post("/push/plan")
def push_plan():
    c = clients.need("admin")
    body = _body()
    try:
        plan = netbox.plan_push(_connect(c["id"]), _site(body), _push_projects(c, body), _role(body))
    except netbox.NetboxError as exc:
        return {"error": str(exc)}, 502
    for s in plan["steps"]:
        s.pop("call", None)
    return plan


@bp.post("/push/apply")
def push_apply():
    """Work the plan out again and run the steps the user ticked (by their text, so a changed plan is refused)."""
    c = clients.need("admin")
    body = _body()
    nb = _connect(c["id"])
    try:
        plan = netbox.plan_push(nb, _site(body), _push_projects(c, body), _role(body))
    except netbox.NetboxError as exc:
        return {"error": str(exc)}, 502
    want = [str(x) for x in body.get("steps") or []]
    known = {s["what"]: s for s in plan["steps"]}
    missing = [w for w in want if w not in known]
    if missing:
        return {"error": "NetBox or the projects changed since the plan was made. Make the plan again.",
                "changed": missing[:10]}, 409
    picked = [known[w] for w in dict.fromkeys(want)]
    # Devices first, so IP addresses can be assigned in a later push.
    picked.sort(key=lambda s: {"device": 0, "vlan": 1, "ip": 2}[s["kind"]])
    results = netbox.apply(nb, picked)
    log.info("audit: %s pushed %d changes to NetBox %s for client %r (%d failed)", auth.current_user()["username"],
             len(results), nb.base, c["name"], sum(1 for r in results if not r["ok"]))
    return {"results": results}


def init_app(app) -> None:
    app.register_blueprint(bp)
