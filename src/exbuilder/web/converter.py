"""The Converter: paste a switch config from one vendor, get the same setup for another.

The result can be saved as a project in a client's Lab space. From there it is tested,
approved and promoted to Production like any other Lab project (see promote.py).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from flask import Blueprint, abort, redirect, render_template, request, session, url_for

from .. import convert, vendors
from ..convert import portmap
from . import auth, clients

bp = Blueprint("converter", __name__)
log = logging.getLogger("exbuilder.converter")
MAX_TEXT = 1_500_000
MAX_PROJECT_BYTES = 512 * 1024


def _editable_clients() -> list[dict]:
    return [c for c in clients.my_clients() if clients.RANK[c["role"]] >= clients.RANK["editor"]]


@bp.get("/convert")
def page():
    targets = [v.to_dict() for v in vendors.VENDORS.values() if v.ready]
    model_lists = {v["key"]: [m for m in portmap.model_names(v["key"]) if m != "Custom"] for v in targets}
    return render_template("convert.html", vendors=targets, readers=convert.READERS, models=model_lists,
                           clients=_editable_clients(), current=clients.current(),
                           is_admin=clients._is_server_admin())


@bp.post("/convert/run")
def run():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        abort(400)
    text = str(body.get("text") or "")
    if not text.strip():
        return {"error": "Paste a config first."}, 400
    if len(text) > MAX_TEXT:
        return {"error": "That config is too large."}, 400
    source = str(body.get("source") or "").strip().lower()
    if source and not vendors.known(source):
        source = ""
    res = convert.convert(text, source, str(body.get("target") or "").strip().lower(),
                          str(body.get("model") or "").strip(), str(body.get("source_model") or "").strip())
    if "error" in res:
        return res, 400
    res["detected"] = not source
    return res


@bp.post("/convert/save")
def save():
    """Save a converted project into a client's Lab space."""
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        abort(400)
    try:
        cid = int(body.get("client_id"))
    except (TypeError, ValueError):
        return {"error": "Pick a client."}, 400
    role = clients.role_in(cid)
    if role is None:
        return {"error": "You are not a member of that client."}, 403
    if clients.RANK[role] < clients.RANK["editor"]:
        return {"error": "You need the editor role in that client to save projects."}, 403
    name = str(body.get("name") or "").strip()[:100]
    data = body.get("data")
    if not name or not isinstance(data, dict):
        return {"error": "Give the project a name."}, 400
    if not vendors.known(data.get("vendor")):
        return {"error": "The project has no known vendor."}, 400
    text = json.dumps(data)
    if len(text) > MAX_PROJECT_BYTES:
        return {"error": "Project is too large."}, 400
    db = auth.db()
    if db.execute("SELECT 1 FROM projects WHERE client_id = ? AND space = 'lab' AND name = ?",
                  (cid, name)).fetchone() and not body.get("overwrite"):
        return {"error": f"The Lab space already has a project called {name}.", "exists": True}, 409
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    user = auth.current_user()["username"]
    db.execute("INSERT INTO projects (client_id, space, name, data, updated_at, updated_by) VALUES (?, 'lab', ?, ?, ?, ?) "
               "ON CONFLICT (client_id, space, name) DO UPDATE SET data = excluded.data, "
               "updated_at = excluded.updated_at, updated_by = excluded.updated_by", (cid, name, text, now, user))
    db.commit()
    pid = db.execute("SELECT id FROM projects WHERE client_id = ? AND space = 'lab' AND name = ?", (cid, name)).fetchone()[0]
    log.info("audit: converter saved %r (%s) to Lab of client %s by %s", name, data.get("vendor"), cid, user)
    return {"id": pid, "name": name, "vendor": data["vendor"]}


@bp.post("/convert/client")
@auth.admin_required
def new_client():
    """Make a client without leaving the Converter (server admins only, like the Clients page)."""
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        abort(400)
    cid, error = clients.create(str(body.get("name") or "").strip())
    if error:
        return {"error": error}, 400
    return {"id": cid, "name": clients.row(cid)["name"]}


@bp.post("/convert/open")
def open_in_lab():
    """Switch to that client's Lab space and open the saved project in its vendor's builder."""
    try:
        cid, pid = int(request.form.get("client_id", "")), int(request.form.get("project_id", ""))
    except ValueError:
        abort(400)
    if clients.role_in(cid) is None:
        abort(403)
    row = auth.db().execute("SELECT data FROM projects WHERE id = ? AND client_id = ? AND space = 'lab'",
                            (pid, cid)).fetchone()
    if row is None:
        abort(404)
    vendor = vendors.get(json.loads(row["data"]).get("vendor")).key
    session["client_id"] = cid
    session["client_chosen"] = True
    session["space"] = "lab"
    return redirect(url_for("builder", vendor=vendor, project=pid))


def init_app(app) -> None:
    app.register_blueprint(bp)
