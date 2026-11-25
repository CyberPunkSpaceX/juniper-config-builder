"""From Lab to Production: request approval, approve, then promote.

A project tested in a client's Lab space can be copied into its Production
space, but only after a review:

1. An editor asks for approval of a saved Lab project. The project is frozen
   as it is at that moment (a snapshot), and it must build with no errors.
2. A client admin approves or rejects it, with a note. When the client has
   another admin, people can't approve their own request.
3. A client admin promotes the approved snapshot into Production, under the
   same project name. If the Lab project was changed after approval, it has to
   be approved again. The Production project it replaces is kept, so a
   promotion can be undone.

Every step is in the audit log and in the client's list of reviews.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3

from flask import Blueprint, abort, request

from . import auth, clients

bp = Blueprint("promote", __name__)
log = logging.getLogger("exbuilder.promote")

SCHEMA = """
CREATE TABLE IF NOT EXISTS project_reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    lab_project_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    vendor TEXT NOT NULL DEFAULT 'juniper',
    data TEXT NOT NULL,                       -- the snapshot that is reviewed and promoted
    sha TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',   -- pending, approved, rejected, promoted, undone, replaced
    note TEXT NOT NULL DEFAULT '',
    requested_by TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    decided_by TEXT NOT NULL DEFAULT '',
    decided_at TEXT NOT NULL DEFAULT '',
    decision_note TEXT NOT NULL DEFAULT '',
    promoted_by TEXT NOT NULL DEFAULT '',
    promoted_at TEXT NOT NULL DEFAULT '',
    prod_project_id INTEGER,
    replaced_data TEXT                        -- the Production project it overwrote, for undo
);
"""
OPEN = ("pending", "approved")


def migrate(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _audit(c: dict, what: str) -> None:
    log.warning("audit: %r %s (client %r)", auth.current_user()["username"], what, c["name"])


def _review(c: dict, rid: int) -> sqlite3.Row:
    r = auth.db().execute("SELECT * FROM project_reviews WHERE id = ? AND client_id = ?", (rid, c["id"])).fetchone()
    if r is None:
        abort(404)
    return r


def _admins(cid: int) -> int:
    """People who can approve in this client: its admins and the server admins (who manage every client)."""
    return auth.db().execute(
        "SELECT COUNT(*) FROM users u WHERE u.active = 1 AND (u.role = 'admin' OR EXISTS (SELECT 1 FROM "
        "client_members m WHERE m.user_id = u.id AND m.client_id = ? AND m.role = 'admin'))", (cid,)).fetchone()[0]


def _out(r: sqlite3.Row, lab_sha: str | None) -> dict:
    d = {k: r[k] for k in r.keys() if k not in ("data", "replaced_data")}
    d["lab_changed"] = r["status"] in OPEN and lab_sha is not None and lab_sha != r["sha"]
    d["lab_gone"] = r["status"] in OPEN and lab_sha is None
    d["can_undo"] = r["status"] == "promoted"
    return d


@bp.get("/promote")
def reviews():
    """The client's reviews, newest first (both spaces can see them)."""
    c = clients.need("viewer")
    db = auth.db()
    rows = db.execute("SELECT * FROM project_reviews WHERE client_id = ? ORDER BY id DESC LIMIT 100",
                      (c["id"],)).fetchall()
    shas = {r["id"]: _sha(r["data"]) for r in db.execute(
        "SELECT id, data FROM projects WHERE client_id = ? AND space = 'lab'", (c["id"],))}
    me = auth.current_user()["username"]
    return {"reviews": [_out(r, shas.get(r["lab_project_id"])) for r in rows],
            "role": c["role"], "space": c["space"], "me": me,
            "self_approve": _admins(c["id"]) <= 1}


@bp.post("/promote/request")
def request_approval():
    c = clients.need("editor")
    if c["space"] != "lab":
        clients._json_abort(409, "Approvals start from the Lab space. Switch to Lab at the top of the page.")
    body = request.get_json(silent=True) or {}
    try:
        pid = int(body.get("project_id"))
    except (TypeError, ValueError):
        return {"error": "Pick a saved Lab project."}, 400
    db = auth.db()
    p = db.execute("SELECT * FROM projects WHERE id = ? AND client_id = ? AND space = 'lab'", (pid, c["id"])).fetchone()
    if p is None:
        return {"error": "That Lab project doesn't exist (save it first)."}, 404
    data = json.loads(p["data"])
    from ..generator import build
    res = build(data)
    if res.errors:
        return {"error": f"The project has {len(res.errors)} error(s) to fix before it can be approved, first: "
                         f"{res.errors[0].get('section')}: {res.errors[0].get('message')}"}, 400
    who = auth.current_user()["username"]
    now = auth._now()
    db.execute("UPDATE project_reviews SET status = 'replaced', decision_note = 'A newer request replaced this one.' "
               "WHERE client_id = ? AND lab_project_id = ? AND status IN ('pending', 'approved')", (c["id"], pid))
    rid = db.execute(
        "INSERT INTO project_reviews (client_id, lab_project_id, name, vendor, data, sha, note, requested_by, "
        "requested_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (c["id"], pid, p["name"], str(data.get("vendor") or "juniper"), p["data"], _sha(p["data"]),
         str(body.get("note") or "").strip()[:500], who, now)).lastrowid
    db.commit()
    _audit(c, f"asked for approval to promote Lab project {p['name']!r} (review {rid})")
    return {"id": rid, "status": "pending"}


@bp.post("/promote/<int:rid>/<action>")
def decide(rid: int, action: str):
    if action not in ("approve", "reject", "promote", "undo", "cancel"):
        abort(404)
    c = clients.need("editor" if action == "cancel" else "admin")
    r = _review(c, rid)
    body = request.get_json(silent=True) or {}
    note = str(body.get("note") or "").strip()[:500]
    who = auth.current_user()["username"]
    now = auth._now()
    db = auth.db()

    if action == "cancel":
        if r["status"] != "pending" or (r["requested_by"] != who and c["role"] != "admin"):
            return {"error": "Only a pending request can be cancelled, by the person who made it or an admin."}, 400
        db.execute("UPDATE project_reviews SET status = 'replaced', decided_by = ?, decided_at = ?, "
                   "decision_note = 'Cancelled.' WHERE id = ?", (who, now, rid))
        db.commit()
        _audit(c, f"cancelled approval request {rid} for {r['name']!r}")
        return {"status": "replaced"}

    if action in ("approve", "reject"):
        if r["status"] != "pending":
            return {"error": f"This request is {r['status']}, not waiting for a decision."}, 400
        if action == "approve" and r["requested_by"] == who and _admins(c["id"]) > 1:
            return {"error": "Another admin of this client has to approve your own request."}, 403
        if action == "reject" and not note:
            return {"error": "Say why it is rejected, so the requester knows what to fix."}, 400
        status = "approved" if action == "approve" else "rejected"
        db.execute("UPDATE project_reviews SET status = ?, decided_by = ?, decided_at = ?, decision_note = ? "
                   "WHERE id = ?", (status, who, now, note, rid))
        db.commit()
        _audit(c, f"{status} promoting {r['name']!r} to Production (review {rid})")
        return {"status": status}

    if action == "promote":
        if r["status"] != "approved":
            return {"error": "Only an approved request can be promoted."}, 400
        lab = db.execute("SELECT data FROM projects WHERE id = ? AND client_id = ? AND space = 'lab'",
                         (r["lab_project_id"], c["id"])).fetchone()
        if lab is not None and _sha(lab["data"]) != r["sha"]:
            return {"error": "The Lab project was changed after it was approved. Ask for approval again."}, 409
        old = db.execute("SELECT id, data FROM projects WHERE client_id = ? AND space = 'production' AND name = ?",
                         (c["id"], r["name"])).fetchone()
        db.execute("INSERT INTO projects (client_id, space, name, data, updated_at, updated_by) "
                   "VALUES (?, 'production', ?, ?, ?, ?) ON CONFLICT (client_id, space, name) DO UPDATE SET "
                   "data = excluded.data, updated_at = excluded.updated_at, updated_by = excluded.updated_by",
                   (c["id"], r["name"], r["data"], now, f"{who} (promoted from Lab)"))
        pid = db.execute("SELECT id FROM projects WHERE client_id = ? AND space = 'production' AND name = ?",
                         (c["id"], r["name"])).fetchone()[0]
        db.execute("UPDATE project_reviews SET status = 'promoted', promoted_by = ?, promoted_at = ?, "
                   "prod_project_id = ?, replaced_data = ? WHERE id = ?",
                   (who, now, pid, old["data"] if old else None, rid))
        db.commit()
        _audit(c, f"promoted Lab project {r['name']!r} to Production (review {rid}, approved by {r['decided_by']!r})")
        return {"status": "promoted", "production_project_id": pid, "replaced": old is not None}

    # undo
    if r["status"] != "promoted":
        return {"error": "Only a promotion can be undone."}, 400
    later = db.execute("SELECT 1 FROM project_reviews WHERE client_id = ? AND name = ? AND status = 'promoted' "
                       "AND id > ?", (c["id"], r["name"], rid)).fetchone()
    if later:
        return {"error": "A later promotion of this project exists; undo that one first."}, 409
    if r["replaced_data"] is None:
        db.execute("DELETE FROM projects WHERE id = ? AND client_id = ? AND space = 'production'",
                   (r["prod_project_id"], c["id"]))
    else:
        db.execute("UPDATE projects SET data = ?, updated_at = ?, updated_by = ? WHERE id = ? AND client_id = ? "
                   "AND space = 'production'", (r["replaced_data"], now, f"{who} (undid a promotion)",
                                                r["prod_project_id"], c["id"]))
    db.execute("UPDATE project_reviews SET status = 'undone', decision_note = ? WHERE id = ?",
               ((r["decision_note"] + " " if r["decision_note"] else "") + f"Undone by {who} at {now}.", rid))
    db.commit()
    _audit(c, f"undid the promotion of {r['name']!r} (review {rid})")
    return {"status": "undone"}


@bp.get("/promote/<int:rid>/data")
def snapshot(rid: int):
    """The reviewed snapshot, so a reviewer can open exactly what is being approved."""
    c = clients.need("viewer")
    r = _review(c, rid)
    return {"name": r["name"], "data": json.loads(r["data"])}


def init_app(app) -> None:
    app.register_blueprint(bp)
