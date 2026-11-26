"""Global: one client's whole network on one page, and the history of each switch.

After picking a client, Global shows every switch the client has in a space
(Production by default, or Lab) as a clickable diagram, with a list to jump
straight to a switch. The switches come from what the app already keeps:

* config backups (SSH fetch, nightly backups, before and after a push, uploads),
* saved network maps (their configs and the LLDP text pasted with them),
* saved projects (a switch that is built but never read shows as "planned"),
* cables found with the auto map (LLDP / CDP, see toolkit.py), saved here.

Cables come from the configs (topology.py: LLDP, point-to-point addresses,
descriptions) and from the last LLDP / CDP discovery saved on this page.

A switch's page lists every change to it, newest first: config versions,
pushes, project saves, Lab-to-Production reviews and (for client admins) the
audit log. Each one says who and when, and opens a diff.

Isolation and roles: everything is read from the current client only. Read-only
people see configs and diffs with passwords and keys hidden, and do not see
the audit log (client admins and Super Admins do, as on the audit page).
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3

from flask import Blueprint, abort, redirect, render_template, request, session, url_for

from .. import __version__, redact, topology
from .. import compare as cmp
from ..generator import build
from . import auth, backups, clients

bp = Blueprint("overview", __name__)
log = logging.getLogger("exbuilder.overview")

SCHEMA = """
CREATE TABLE IF NOT EXISTS global_layouts (
    client_id INTEGER NOT NULL,
    space TEXT NOT NULL,
    data TEXT NOT NULL,             -- {"pos": {host: {x, y}}, "links": [...], "found_at", "found_by"}
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (client_id, space)
);
"""
MAX_LAYOUT_BYTES = 512 * 1024
MAX_LINKS = 2000
KINDS = {"config": "Config version", "push": "Push", "project": "Project saved", "review": "Lab to Production",
         "audit": "Audit log"}
PUSH_HIDDEN = ("previewed", "cancelled")


def migrate(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)


def _key(name: str) -> str:
    """sw1.example.com / SW1 -> sw1, to match the same switch across sources."""
    name = str(name or "").strip().lower()
    if re.fullmatch(r"[\d.]+|[0-9a-f:]+", name):
        return name
    return name.split(".")[0]


def _space() -> str:
    want = request.args.get("space")
    if want in clients.SPACES:
        session["space"] = want
        return want
    return clients.space()


def _client(role: str = "viewer") -> dict:
    c = clients.need(role)
    return {**c, "space": _space()}


def _has_table(db, name: str) -> bool:
    return db.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)).fetchone() is not None


def _layout(db, c: dict) -> dict:
    migrate(db)
    r = db.execute("SELECT data, updated_at, updated_by FROM global_layouts WHERE client_id = ? AND space = ?",
                   (c["id"], c["space"])).fetchone()
    if r is None:
        return {"pos": {}, "links": []}
    try:
        data = json.loads(r["data"])
    except ValueError:
        data = {}
    return {"pos": data.get("pos") or {}, "links": data.get("links") or [], "found_at": data.get("found_at", ""),
            "found_by": data.get("found_by", ""), "updated_at": r["updated_at"], "updated_by": r["updated_by"]}


def _project_host(data: dict) -> str:
    return str(((data or {}).get("system") or {}).get("hostname") or "").strip()


# ------------------------------------------------------------- inventory
def inventory(db, c: dict) -> dict:
    """Every switch of the client in the space: {key: {...}}, plus the latest config text of each."""
    sw: dict[str, dict] = {}
    texts: dict[str, str] = {}
    lldp: dict[str, str] = {}

    def add(name: str, **info) -> dict:
        k = _key(name)
        s = sw.setdefault(k, {"host": name, "address": "", "vendor": "", "last_backup": "", "last_backup_by": "",
                              "versions": 0, "projects": [], "sources": []})
        for f, v in info.items():
            if v and not s.get(f):
                s[f] = v
        return s

    rows = db.execute("SELECT id, host, address, source, created_at, created_by, text FROM config_backups "
                      "WHERE client_id = ? AND space = ? ORDER BY id DESC", (c["id"], c["space"])).fetchall()
    for r in rows:
        s = add(r["host"])
        s["versions"] += 1
        if "backups" not in s["sources"]:
            s["sources"].append("backups")
        if not s["address"] and r["address"]:
            s["address"] = r["address"]
        if not s["last_backup"]:
            from ..convert import detect
            s["last_backup"], s["last_backup_by"] = r["created_at"], r["created_by"]
            s["vendor"] = s["vendor"] or detect(r["text"])
            texts[_key(r["host"])] = r["text"]
    for m in db.execute("SELECT data FROM maps WHERE client_id = ? AND space = ? ORDER BY updated_at DESC",
                        (c["id"], c["space"])):
        try:
            items = json.loads(m["data"]).get("items") or []
        except (ValueError, AttributeError):
            continue
        for it in items:
            if not isinstance(it, dict) or not str(it.get("text") or "").strip():
                continue
            host = backups.host_of(str(it.get("text")), str(it.get("name") or ""))
            s = add(host)
            if "maps" not in s["sources"]:
                s["sources"].append("maps")
            texts.setdefault(_key(host), str(it.get("text")))
            if it.get("lldp"):
                lldp.setdefault(_key(host), str(it["lldp"]))
    for p in db.execute("SELECT id, name, data, updated_at FROM projects WHERE client_id = ? AND space = ?",
                        (c["id"], c["space"])):
        try:
            data = json.loads(p["data"])
        except ValueError:
            continue
        host = _project_host(data)
        if not host:
            continue
        s = add(host, vendor=str(data.get("vendor") or "juniper"))
        s["projects"].append({"id": p["id"], "name": p["name"], "updated_at": p["updated_at"]})
        if "projects" not in s["sources"]:
            s["sources"].append("projects")
    for link in _layout(db, c)["links"]:
        for end in ("a", "b"):
            if link.get(end + "_read"):
                add(str(link.get(end) or ""), address=str(link.get(end + "_mgmt") or ""))
    sw.pop("", None)
    return {"switches": sw, "texts": texts, "lldp": lldp}


def _links(inv: dict, layout: dict) -> list[dict]:
    """Cables between the client's switches, from the configs and from the saved LLDP / CDP discovery."""
    keys = [k for k in inv["switches"] if k in inv["texts"]]
    out, seen = [], set()

    def put(a: str, a_if: str, b: str, b_if: str, how: str) -> None:
        if a not in inv["switches"] or b not in inv["switches"] or a == b:
            return
        ends = tuple(sorted([(a, a_if or ""), (b, b_if or "")]))
        pair = tuple(sorted([a, b]))
        for x in out:   # the same cable seen another way
            if tuple(sorted([x["a"], x["b"]])) == pair and ({(x["a"], x["a_if"]), (x["b"], x["b_if"])} & set(ends)
                                                            or not (a_if or b_if) or not (x["a_if"] or x["b_if"])):
                if how not in x["found"]:
                    x["found"].append(how)
                return
        if ends in seen:
            return
        seen.add(ends)
        out.append({"a": a, "a_if": a_if or "", "b": b, "b_if": b_if or "", "found": [how]})

    if keys:
        try:
            m = topology.analyze([{"text": inv["texts"][k], "name": inv["switches"][k]["host"],
                                   "lldp": inv["lldp"].get(k, "")} for k in keys])
            ids = {s["id"]: _key(s["hostname"]) for s in m["switches"]}
            for x in m["links"]:
                a, b = ids.get(x["a"]), ids.get(x["b"])
                for how in x["found"] or ["config"]:
                    put(a, x["a_if"], b, x["b_if"], how)
        except Exception:  # noqa: BLE001 - a config the map can't read must not break the page
            log.exception("global map: reading the configs failed")
    for x in layout["links"]:
        put(_key(x.get("a")), str(x.get("a_if") or ""), _key(x.get("b")), str(x.get("b_if") or ""),
            "LLDP/CDP discovery")
    return out


# ----------------------------------------------------------------- pages
@bp.get("/global")
def global_page():
    """The client's overview: all switches in a diagram, and a list to jump to one."""
    if auth.current_user() is None:
        return redirect(url_for("auth.login", next=request.full_path))
    if session.get("space") not in clients.SPACES:
        session["space"] = "production"
    if len(clients.my_clients()) > 1 and not session.get("client_chosen"):
        return redirect(url_for("clients.pick_page", next=url_for("overview.global_page")))
    c = clients.current()
    if c is None:
        return render_template("global.html", client=None, version=__version__)
    _space()
    return render_template("global.html", client=clients.current(), version=__version__,
                           can_edit=clients.RANK[c["role"]] >= clients.RANK["editor"],
                           can_discover=c["role"] == "admin")


@bp.get("/global/data")
def global_data():
    c = _client()
    db = auth.db()
    layout = _layout(db, c)
    inv = inventory(db, c)
    pushes = {}
    if c["space"] == "production":
        for r in db.execute("SELECT host, status, pushed_at, created_at FROM config_pushes WHERE client_id = ? "
                            "ORDER BY id", (c["id"],)):
            pushes[r["host"]] = r
    switches = []
    for k, s in sorted(inv["switches"].items(), key=lambda kv: kv[1]["host"].lower()):
        p = pushes.get(s["address"]) or pushes.get(s["host"])
        switches.append({"key": k, **s, "planned": not s["versions"] and "maps" not in s["sources"],
                         "last_push": (p["pushed_at"] or p["created_at"]) if p else "",
                         "url": url_for("overview.switch_page", host=s["host"])})
    return {"client": c["name"], "space": c["space"], "space_name": clients.SPACES[c["space"]],
            "switches": switches, "links": _links(inv, layout), "pos": layout["pos"],
            "discovered": {"at": layout.get("found_at", ""), "by": layout.get("found_by", ""),
                           "links": len(layout["links"])}}


@bp.post("/global/layout")
def global_layout():
    """Save where the switches sit in the diagram (editors), and the cables an LLDP / CDP discovery found (admins)."""
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        abort(400, "Send JSON.")
    c = _client("editor")
    db = auth.db()
    cur = _layout(db, c)
    data = {"pos": cur["pos"], "links": cur["links"], "found_at": cur.get("found_at", ""),
            "found_by": cur.get("found_by", "")}
    me = auth.current_user()["username"]
    if isinstance(body.get("pos"), dict):
        pos = {}
        for host, p in list(body["pos"].items())[:2000]:
            try:
                pos[_key(host)[:100]] = {"x": round(float(p["x"]), 1), "y": round(float(p["y"]), 1)}
            except (TypeError, ValueError, KeyError):
                continue
        data["pos"] = pos
    if "discovery" in body:
        if c["role"] != "admin":
            clients._json_abort(403, "Saving cables from a discovery needs the Admin role in this client.")
        found = body.get("discovery") or {}
        nodes = {n.get("id"): n for n in found.get("nodes") or [] if isinstance(n, dict)}
        links = []
        for x in (found.get("links") or [])[:MAX_LINKS]:
            if not isinstance(x, dict):
                continue
            a, b = nodes.get(x.get("a")) or {}, nodes.get(x.get("b")) or {}
            links.append({"a": str(a.get("name") or x.get("a") or "")[:100], "a_if": str(x.get("a_if") or "")[:60],
                          "b": str(b.get("name") or x.get("b") or "")[:100], "b_if": str(x.get("b_if") or "")[:60],
                          "a_read": bool(a.get("read")), "b_read": bool(b.get("read")),
                          "a_mgmt": str(a.get("mgmt") or "")[:60], "b_mgmt": str(b.get("mgmt") or "")[:60]})
        data.update(links=links, found_at=auth._now(), found_by=me)
        log.warning("audit: %r saved %d LLDP/CDP cable(s) to the Global map of %s (client %r)", me, len(links),
                    c["space"], c["name"])
    text = json.dumps(data)
    if len(text) > MAX_LAYOUT_BYTES:
        return {"error": "That is too much to save."}, 400
    db.execute("INSERT INTO global_layouts (client_id, space, data, updated_at, updated_by) VALUES (?, ?, ?, ?, ?) "
               "ON CONFLICT (client_id, space) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at, "
               "updated_by = excluded.updated_by", (c["id"], c["space"], text, auth._now(), me))
    db.commit()
    return {"ok": True, "links": len(data["links"])}


def _find(db, c: dict, host: str) -> dict:
    inv = inventory(db, c)
    s = inv["switches"].get(_key(host))
    if s is None:
        abort(404)
    return {**s, "key": _key(host), "text": inv["texts"].get(_key(host), ""), "all": inv["switches"]}


@bp.get("/global/switch/<host>")
def switch_page(host: str):
    c = _client()
    s = _find(auth.db(), c, host)
    others = sorted(({"host": x["host"], "url": url_for("overview.switch_page", host=x["host"])}
                     for x in s["all"].values()), key=lambda x: x["host"].lower())
    text = s["text"] if clients.can_see_secrets(c) else redact.config(s["text"])
    return render_template("global_switch.html", client=c, sw={k: v for k, v in s.items() if k not in ("all", "text")},
                           config=text, others=others, version=__version__, kinds=KINDS,
                           redacted=not clients.can_see_secrets(c), audit=c["role"] == "admin",
                           changes_url=url_for("overview.switch_changes", host=s["host"]),
                           change_url=url_for("overview.switch_change", host=s["host"]))


# --------------------------------------------------------------- history
def _sortable(ts: str) -> str:
    """'2026-11-26 00:37 UTC' and '2026-11-26 00:37:12 UTC' -> comparable text."""
    ts = str(ts or "").replace(" UTC", "").replace("T", " ")
    return ts + ":00" if len(ts) == 16 else ts


def _backup_ids(db, c: dict, s: dict) -> list[sqlite3.Row]:
    return db.execute("SELECT id, host, address, source, note, created_at, created_by, lines FROM config_backups "
                      "WHERE client_id = ? AND space = ? AND lower(host) IN (?, ?) ORDER BY id DESC",
                      (c["id"], c["space"], s["host"].lower(), s["key"])).fetchall()


def _reviews(db, c: dict, s: dict) -> list[sqlite3.Row]:
    names = {p["name"] for p in s["projects"]}
    out = []
    for r in db.execute("SELECT * FROM project_reviews WHERE client_id = ? ORDER BY id", (c["id"],)):
        try:
            host = _project_host(json.loads(r["data"]))
        except ValueError:
            host = ""
        if r["name"] in names or (host and _key(host) == s["key"]):
            out.append(r)
    return out


def _pushes(db, c: dict, s: dict, bids: set) -> list[sqlite3.Row]:
    if c["space"] != "production":
        return []
    q = ",".join("?" * len(PUSH_HIDDEN))
    rows = db.execute(f"SELECT * FROM config_pushes WHERE client_id = ? AND status NOT IN ({q}) ORDER BY id DESC",
                      (c["id"], *PUSH_HIDDEN)).fetchall()
    names = {s["host"].lower(), s["key"], (s["address"] or "").lower()} - {""}
    return [r for r in rows if r["host"].lower() in names or _key(r["host"]) == s["key"]
            or (r["backup_id"] in bids) or (r["after_backup_id"] in bids)]


def _audit_rows(db, c: dict, s: dict) -> list[sqlite3.Row]:
    if c["role"] != "admin" or not _has_table(db, "audit_log"):
        return []
    terms = {s["host"], s["address"]} - {""}
    if not terms:
        return []
    cond = " OR ".join("message LIKE ? OR path LIKE ?" for _ in terms)
    args = [x for t in terms for x in (f"%{t}%", f"%{t}%")]
    return db.execute(f"SELECT * FROM audit_log WHERE client_id = ? AND ({cond}) ORDER BY id DESC LIMIT 300",
                      (c["id"], *args)).fetchall()


@bp.get("/global/switch/<host>/changes")
def switch_changes(host: str):
    """Every change to the switch, newest first: [{kind, id, title, who, when, detail}]."""
    c = _client()
    db = auth.db()
    s = _find(db, c, host)
    rows = _backup_ids(db, c, s)
    events = []
    for r in rows:
        events.append({"kind": "config", "id": r["id"], "when": r["created_at"], "who": r["created_by"] or "the server",
                       "title": f"Config version from {backups.SOURCES.get(r['source'], r['source'])}",
                       "detail": " · ".join(x for x in (r["address"], f"{r['lines']} lines", r["note"]) if x)})
    for r in _pushes(db, c, s, {r["id"] for r in rows}):
        events.append({"kind": "push", "id": r["id"], "when": r["pushed_at"] or r["created_at"],
                       "who": r["pushed_by"] or r["created_by"],
                       "title": f"Push of {r['project_name']} ({r['mode']}): {r['status'].replace('_', ' ')}",
                       "detail": " · ".join(x for x in (r["host"], f"decided by {r['decided_by']} {r['decided_at']}"
                                                        if r["decided_by"] else "", r["message"][:200]) if x)})
    for p in s["projects"]:
        row = db.execute("SELECT updated_by FROM projects WHERE id = ?", (p["id"],)).fetchone()
        events.append({"kind": "project", "id": p["id"], "when": p["updated_at"], "who": row["updated_by"] if row else "",
                       "title": f"Project {p['name']} saved ({clients.SPACES[c['space']]})", "detail": ""})
    for r in _reviews(db, c, s):
        steps = [("requested", r["requested_at"], r["requested_by"], r["note"])]
        if r["decided_by"]:
            word = "rejected" if r["status"] == "rejected" else "approved"
            steps.append((word, r["decided_at"], r["decided_by"], r["decision_note"]))
        if r["promoted_by"]:
            steps.append(("promoted to Production", r["promoted_at"], r["promoted_by"], ""))
        if r["status"] == "undone":
            steps.append(("promotion undone", "", "", ""))
        for word, when, who, note in steps:
            if not when and word != "promotion undone":
                continue
            events.append({"kind": "review", "id": r["id"], "when": when or r["promoted_at"], "who": who,
                           "title": f"Lab to Production: {r['name']} {word}", "detail": note[:300]})
    for r in _audit_rows(db, c, s):
        events.append({"kind": "audit", "id": r["id"], "when": r["at"], "who": r["user"],
                       "title": r["message"][:160] or f"{r['method']} {r['path']}",
                       "detail": f"{r['method']} {r['path']} → {r['status'] or ''}".strip(" →")})
    events.sort(key=lambda e: _sortable(e["when"]), reverse=True)
    return {"host": s["host"], "space": c["space"], "events": events, "redacted": not clients.can_see_secrets(c),
            "audit": c["role"] == "admin"}


def _config_of(data: dict, secrets: bool) -> str:
    if not secrets:
        data = redact.project(data)
    res = build(data)
    return res.set_text or res.hier_text or ""


@bp.get("/global/switch/<host>/change")
def switch_change(host: str):
    """One change: who, when and what changed (a diff), with secrets hidden for Read-only people."""
    c = _client()
    db = auth.db()
    s = _find(db, c, host)
    kind = request.args.get("kind", "")
    try:
        cid = int(request.args.get("id", ""))
    except ValueError:
        abort(400, "Which change?")
    see = clients.can_see_secrets(c)
    hide = (lambda t: t) if see else redact.config
    if kind == "config":
        r = db.execute("SELECT * FROM config_backups WHERE id = ? AND client_id = ? AND space = ?",
                       (cid, c["id"], c["space"])).fetchone()
        if r is None or _key(r["host"]) != s["key"]:
            abort(404)
        before = backups.previous(db, r)
        head = {"title": f"Config version from {backups.SOURCES.get(r['source'], r['source'])}", "who": r["created_by"],
                "when": r["created_at"], "backup_id": r["id"]}
        if before is None:
            return {**head, "first": True, "text": hide(r["text"]), "redacted": not see}
        result = cmp.compare(hide(before["text"]), hide(r["text"]))
        return {**head, "result": result, "before": {"when": before["created_at"], "who": before["created_by"],
                                                     "source": backups.SOURCES.get(before["source"], before["source"])},
                "redacted": not see}
    if kind == "push":
        rows = _pushes(db, c, s, {r["id"] for r in _backup_ids(db, c, s)})
        r = next((x for x in rows if x["id"] == cid), None)
        if r is None:
            abort(404)
        out = {"title": f"Push of {r['project_name']}", "who": r["pushed_by"] or r["created_by"],
               "when": r["pushed_at"] or r["created_at"], "status": r["status"], "message": r["message"],
               "mode": r["mode"], "diff": hide(r["diff"]), "redacted": not see}
        if r["backup_id"] and r["after_backup_id"]:
            a = db.execute("SELECT text FROM config_backups WHERE id = ? AND client_id = ?", (r["backup_id"], c["id"])).fetchone()
            b = db.execute("SELECT text FROM config_backups WHERE id = ? AND client_id = ?",
                           (r["after_backup_id"], c["id"])).fetchone()
            if a and b:
                out["result"] = cmp.compare(hide(a["text"]), hide(b["text"]))
        return out
    if kind == "project":
        if not any(p["id"] == cid for p in s["projects"]):
            abort(404)
        p = db.execute("SELECT * FROM projects WHERE id = ? AND client_id = ? AND space = ?",
                       (cid, c["id"], c["space"])).fetchone()
        if p is None:
            abort(404)
        now = _config_of(json.loads(p["data"]), see)
        out = {"title": f"Project {p['name']}", "who": p["updated_by"], "when": p["updated_at"], "redacted": not see}
        # Compared with what the switch runs now, when there is a backup of it.
        live = db.execute("SELECT text, created_at FROM config_backups WHERE client_id = ? AND space = ? AND "
                          "lower(host) IN (?, ?) ORDER BY id DESC LIMIT 1",
                          (c["id"], c["space"], s["host"].lower(), s["key"])).fetchone()
        if live and now:
            out["result"] = cmp.compare(hide(live["text"]), now)
            out["against"] = f"the switch's last config version ({live['created_at']})"
        else:
            out["text"] = now
        return out
    if kind == "review":
        reviews = _reviews(db, c, s)
        r = next((x for x in reviews if x["id"] == cid), None)
        if r is None:
            abort(404)
        now = _config_of(json.loads(r["data"]), see)
        out = {"title": f"Lab to Production: {r['name']}", "status": r["status"], "who": r["requested_by"],
               "when": r["requested_at"], "decided_by": r["decided_by"], "decided_at": r["decided_at"],
               "promoted_by": r["promoted_by"], "promoted_at": r["promoted_at"], "note": r["note"],
               "decision_note": r["decision_note"], "redacted": not see}
        before = next((x for x in reversed(reviews) if x["id"] < r["id"] and x["name"] == r["name"]
                       and x["status"] in ("promoted", "undone")), None)
        if before is None and r["replaced_data"]:
            out["against"] = "the Production project it replaced"
            out["result"] = cmp.compare(_config_of(json.loads(r["replaced_data"]), see), now)
        elif before is not None:
            out["against"] = f"the version promoted before ({before['promoted_at'] or before['requested_at']})"
            out["result"] = cmp.compare(_config_of(json.loads(before["data"]), see), now)
        else:
            out["text"] = now
        return out
    if kind == "audit":
        r = next((x for x in _audit_rows(db, c, s) if x["id"] == cid), None)
        if r is None:
            abort(404)
        return {"title": "Audit log entry", "who": r["user"], "when": r["at"], "audit": {
            k: r[k] for k in r.keys() if k in ("ip", "kind", "method", "path", "status", "message", "space")}}
    abort(400, "Unknown kind of change.")


def init_app(app) -> None:
    app.register_blueprint(bp)
