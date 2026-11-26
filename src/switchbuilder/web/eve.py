"""EVE-NG labs from the network map (see eveng.py), per client.

A client admin sets the EVE-NG address, account and default image on the
client page. Building a lab and reading configs back run as background jobs:
their progress is kept in the database, so any web worker can report it.
"""

from __future__ import annotations

import json
import logging
import re
import secrets
import sqlite3
import threading
import time

from flask import Blueprint, abort, request

from .. import cryptpw, eveng, evelab
from . import auth, clients

bp = Blueprint("eve", __name__)
log = logging.getLogger("switchbuilder.eve")

SCHEMA = """
CREATE TABLE IF NOT EXISTS eve_labs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    path TEXT NOT NULL,
    template TEXT NOT NULL,
    image TEXT NOT NULL,
    nodes TEXT NOT NULL DEFAULT '[]',     -- [{name, hostname, eve_id, ports}]
    lab_password TEXT NOT NULL,           -- encrypted; the exb-lab console login
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS eve_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'running',   -- running, done, failed
    steps TEXT NOT NULL DEFAULT '[]',
    result TEXT,
    created_by TEXT NOT NULL,
    updated_at REAL NOT NULL
);
"""
CLIENT_COLUMNS = {"eve_url": "TEXT NOT NULL DEFAULT ''", "eve_user": "TEXT NOT NULL DEFAULT ''",
                  "eve_password": "TEXT", "eve_folder": "TEXT NOT NULL DEFAULT '/exbuilder'",
                  "eve_verify": "INTEGER NOT NULL DEFAULT 1", "eve_template": "TEXT NOT NULL DEFAULT 'vjunosswitch'",
                  "eve_image": "TEXT NOT NULL DEFAULT ''"}
FOLDER_RE = re.compile(r"^(/[A-Za-z0-9_-]{1,40}){1,4}$")
STALE = 3 * 3600   # a job silent this long is shown as failed (its worker died)


def migrate(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    have = {r[1] for r in conn.execute("PRAGMA table_info(clients)")}
    for col, kind in CLIENT_COLUMNS.items():
        if col not in have:
            conn.execute(f"ALTER TABLE clients ADD COLUMN {col} {kind}")


# ------------------------------------------------------------ settings
def settings(row) -> dict:
    """What the page may know (never the password)."""
    return {"configured": bool(row["eve_url"] and row["eve_user"] and row["eve_password"]),
            "url": row["eve_url"], "user": row["eve_user"], "folder": row["eve_folder"],
            "verify": bool(row["eve_verify"]), "template": row["eve_template"], "image": row["eve_image"]}


def save_settings(cid: int, form) -> list[str]:
    """From the client page form. Returns problems (nothing saved if any)."""
    url = form.get("eve_url", "").strip()
    user = form.get("eve_user", "").strip()
    folder = form.get("eve_folder", "").strip() or "/exbuilder"
    problems = []
    if url:
        try:
            eveng.check_url(url)
        except eveng.EveError as exc:
            problems.append(str(exc))
    if user and not auth.USERNAME_RE.match(user):
        problems.append("The EVE-NG username has characters that are not allowed.")
    if not FOLDER_RE.match(folder):
        problems.append("The lab folder looks like /exbuilder or /tests/switches (letters, digits, - and _).")
    if problems:
        return problems
    db = auth.db()
    db.execute("UPDATE clients SET eve_url = ?, eve_user = ?, eve_folder = ?, eve_verify = ? WHERE id = ?",
               (url, user, folder, 0 if form.get("eve_insecure") else 1, cid))
    if form.get("eve_password"):
        db.execute("UPDATE clients SET eve_password = ? WHERE id = ?",
                   (clients._fernet().encrypt(form["eve_password"].encode()).decode(), cid))
    if not url:
        db.execute("UPDATE clients SET eve_password = NULL WHERE id = ?", (cid,))
    return []


def page_settings() -> dict:
    """For the builder page: is EVE-NG set up for the current client, and may this user build labs."""
    c = clients.current()
    if c is None or c["space"] != "lab":
        return {"configured": False, "role": "", "space": c["space"] if c else "production"}
    out = settings(clients.row(c["id"]))
    out.pop("user", None)
    out["role"] = c["role"]
    out["space"] = "lab"
    return out


def connect(row) -> eveng.Eve:
    if not (row["eve_url"] and row["eve_user"] and row["eve_password"]):
        raise eveng.EveError("EVE-NG is not set up for this client. A client admin adds it on the client page.")
    pw = clients._fernet().decrypt(row["eve_password"].encode()).decode()
    eve = eveng.Eve(row["eve_url"], row["eve_user"], pw, verify_tls=bool(row["eve_verify"]))
    eve.login()
    return eve


def test(row) -> str:
    eve = connect(row)
    try:
        st = eve.status()
        images = eve.juniper_images()
        images_cache = eve.images(r".")
    finally:
        eve.logout()
    usable = [f"{i['label']}: {len(i['images'])} image(s)" for i in images if i["supported"]]
    found = []
    for lab in evelab.LABS.values():
        if lab.vendor != "juniper" and eve_has(row, lab, images_cache):
            found.append(lab.label)
    return (f"Connected to EVE-NG {st.get('version', '')}. "
            + (f"Juniper lab images: {'; '.join(usable)}." if usable else "No vJunos-switch or vJunos-router images found.")
            + (f" Other vendors with a lab image: {', '.join(found)}." if found else
               " No other vendors' lab images found (vEOS, Cat9kv, Nexus 9000v, OS10, EXOS, AOS-CX, CHR)."))


def eve_has(row, lab, cache: list) -> bool:
    return any(re.search(lab.match, f"{i['template']} {i['label']}", re.I) for i in cache)


# ----------------------------------------------------------------- jobs
class Job:
    """Progress of a background job, written to the database as it goes."""

    def __init__(self, cid: int, kind: str, who: str):
        self.path = auth.data_dir() / "users.db"
        self.who = who
        self.steps: list[dict] = []
        with self._db() as conn:
            self.id = conn.execute("INSERT INTO eve_jobs (client_id, kind, created_by, updated_at) VALUES (?, ?, ?, ?)",
                                   (cid, kind, who, time.time())).lastrowid

    def _db(self):
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def step(self, text: str, level: str = "info") -> None:
        self.steps.append({"t": time.strftime("%H:%M:%S", time.gmtime()), "text": text, "level": level})
        with self._db() as conn:
            conn.execute("UPDATE eve_jobs SET steps = ?, updated_at = ? WHERE id = ?",
                         (json.dumps(self.steps), time.time(), self.id))

    def finish(self, ok: bool, result=None) -> None:
        with self._db() as conn:
            conn.execute("UPDATE eve_jobs SET status = ?, result = ?, steps = ?, updated_at = ? WHERE id = ?",
                         ("done" if ok else "failed", json.dumps(result), json.dumps(self.steps), time.time(), self.id))


def _run(job: Job, fn, *args) -> None:
    def main():
        try:
            job.finish(True, fn(job, *args))
        except eveng.EveError as exc:
            job.step(str(exc), "error")
            job.finish(False)
        except Exception as exc:  # noqa: BLE001 - report, don't crash the worker
            log.exception("EVE-NG job %s failed", job.id)
            job.step(f"Unexpected problem: {exc.__class__.__name__}: {exc}"[:400], "error")
            job.finish(False)
    threading.Thread(target=main, daemon=True, name=f"eve-job-{job.id}").start()


def _build(job: Job, row: dict, name: str, template: str, image: str, items: list, positions: dict,
           replace: bool, start: bool, who: str) -> dict:
    spec = eveng.TEMPLATES[template]
    p = eveng.plan(items, positions, template)
    for n in p["notes"]:
        job.step(n, "warn")
    lab_pw = secrets.token_urlsafe(12)
    lab_hash = cryptpw.sha512_crypt(lab_pw)
    configs = {}
    for node in p["nodes"]:
        lines, notes = eveng.lab_config(node["text"], node["ports"], lab_hash)
        configs[node["name"]] = lines
        for n in notes:
            job.step(f"{node['hostname']}: {n}")
    eve = connect(row)
    try:
        folder = row["eve_folder"] or "/exbuilder"
        job.step(f"Signed in to EVE-NG. Making the lab {folder}/{name}.")
        eve.ensure_folder(folder)
        lab = f"{folder}/{name}.unl"
        if eve.lab_exists(lab):
            if not replace:
                raise eveng.EveError(f"A lab called {name} already exists in {folder}. Pick another name, "
                                     "or tick 'Replace it'.")
            try:
                eve.stop(lab)
            except eveng.EveError:
                pass
            eve.delete_lab(lab)
            job.step("Deleted the old lab with the same name.")
        lab = eve.create_lab(folder, name, f"Built by Multi-Vendor Switch Config Builder for {row['name']} by {who}.")
        ids = {}
        for node in p["nodes"]:
            ids[node["name"]] = eve.add_node(lab, {
                "type": "qemu", "template": template, "image": image, "name": node["name"],
                "cpu": spec["cpu"], "ram": spec["ram"], "ethernet": spec["ports"] + spec["first"],
                "console": "telnet", "icon": spec["icon"], "left": node["left"], "top": node["top"], "delay": 0})
        job.step(f"Added {len(ids)} {spec['label']} node(s).")
        for link in p["links"]:
            a, b = p["nodes"][link["a"]], p["nodes"][link["b"]]
            net = eve.add_network(lab, link["name"], (a["left"] + b["left"]) // 2, (a["top"] + b["top"]) // 2)
            for node, port in ((a, link["a_port"]), (b, link["b_port"])):
                idx = int(node["ports"][port].rsplit("/", 1)[1]) + spec["first"]
                eve.connect(lab, ids[node["name"]], {idx: net})
        job.step(f"Connected {len(p['links'])} link(s).")
        nodes = [{"name": n["name"], "hostname": n["hostname"], "eve_id": ids[n["name"]], "ports": n["ports"]}
                 for n in p["nodes"]]
        db = sqlite3.connect(job.path, timeout=10)
        with db:
            lab_id = db.execute(
                "INSERT INTO eve_labs (client_id, name, path, template, image, nodes, lab_password, created_at, "
                "created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (row["id"], name, lab, template, image, json.dumps(nodes),
                 clients._fernet().encrypt(lab_pw.encode()).decode(), auth._now(), who)).lastrowid
        db.close()
        log.warning("audit: %r built EVE-NG lab %s for client %r", who, lab, row["name"])
        result = {"lab_id": lab_id, "lab": lab, "nodes": nodes, "loaded": []}
        if not start:
            job.step("The lab is ready. Start it and load the configs from the lab list when you want.", "ok")
            return result
        result["loaded"] = _start_and_load(job, eve, lab, nodes, configs, lab_pw)
        return result
    finally:
        eve.logout()


def _build_one(job: Job, row: dict, name: str, template: str, image: str, project: dict, replace: bool,
               start: bool, who: str) -> dict:
    """A one-switch lab from the project open in the builder (any vendor with a lab image)."""
    vendor = str(project.get("vendor") or "juniper")
    lab_def = evelab.LABS[vendor]
    lab_pw = secrets.token_urlsafe(12)
    lines, mapping, notes = evelab.lab_text(project, lab_pw, cryptpw.sha512_crypt(lab_pw))
    for n in notes:
        job.step(n, "warn" if "left out" in n else "info")
    hostname = str((project.get("system") or {}).get("hostname") or project.get("name") or "switch")
    node_name = re.sub(r"[^A-Za-z0-9_-]", "-", hostname)[:30] or "switch"
    eve = connect(row)
    try:
        folder = row["eve_folder"] or "/exbuilder"
        job.step(f"Signed in to EVE-NG. Making the lab {folder}/{name}.")
        eve.ensure_folder(folder)
        lab = f"{folder}/{name}.unl"
        if eve.lab_exists(lab):
            if not replace:
                raise eveng.EveError(f"A lab called {name} already exists in {folder}. Pick another name, "
                                     "or tick 'Replace it'.")
            try:
                eve.stop(lab)
            except eveng.EveError:
                pass
            eve.delete_lab(lab)
            job.step("Deleted the old lab with the same name.")
        lab = eve.create_lab(folder, name, f"{lab_def.label} lab of {hostname}, built by Multi-Vendor Switch "
                                           f"Config Builder for {row['name']} by {who}.")
        eve_id = eve.add_node(lab, {
            "type": "qemu", "template": template, "image": image, "name": node_name,
            "cpu": lab_def.cpu, "ram": lab_def.ram, "ethernet": lab_def.ports + 1,
            "console": "telnet", "icon": lab_def.icon, "left": 300, "top": 200, "delay": 0})
        job.step(f"Added a {lab_def.label} node ({lab_def.cpu} CPU, {lab_def.ram // 1024 or 1} GB RAM). "
                 "Connect its ports to EVE-NG networks or other nodes to test traffic.")
        nodes = [{"name": node_name, "hostname": hostname, "eve_id": eve_id, "ports": mapping,
                  "vendor": vendor, "dialect": lab_def.dialect, "boot": lab_def.boot}]
        db = sqlite3.connect(job.path, timeout=10)
        with db:
            lab_id = db.execute(
                "INSERT INTO eve_labs (client_id, name, path, template, image, nodes, lab_password, created_at, "
                "created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (row["id"], name, lab, template, image, json.dumps(nodes),
                 clients._fernet().encrypt(lab_pw.encode()).decode(), auth._now(), who)).lastrowid
        db.close()
        log.warning("audit: %r built EVE-NG %s lab %s for client %r", who, vendor, lab, row["name"])
        result = {"lab_id": lab_id, "lab": lab, "nodes": nodes, "loaded": []}
        if not start:
            job.step("The lab is ready. Start it and load the config from the lab list when you want.", "ok")
            return result
        result["loaded"] = _start_and_load(job, eve, lab, nodes, {node_name: lines}, lab_pw)
        return result
    finally:
        eve.logout()


def _start_and_load(job: Job, eve: eveng.Eve, lab: str, nodes: list, configs: dict, lab_pw: str) -> list:
    eve.start(lab)
    boot = nodes[0].get("boot") if nodes else ""
    job.step(f"Started the lab. It takes about {boot or '5 to 10 minutes'} to boot; the config goes in as each "
             "node is ready.")
    results: dict[str, str] = {}

    def load(node):
        con = None
        try:
            host, port = eve.console(lab, node["eve_id"])
            lines = configs[node["name"]]
            if node.get("dialect", "junos") == "junos":
                con = eveng.Console(host, port)
                con.login([("root", ""), (eveng.LAB_USER, lab_pw)])
                con.push(lines, eveng.top_levels(lines))
                results[node["name"]] = "ok"
                job.step(f"{node['name']}: config loaded and committed.", "ok")
            else:
                con = evelab.LabConsole(host, port, node["dialect"], lab_pw)
                con.login()
                job.step(f"{node['name']}: signed in on the console, typing {len(lines)} lines.")
                refused = con.push(lines)
                results[node["name"]] = "ok"
                for r in refused[:20]:
                    job.step(f"{node['name']}: refused: {r}"[:400], "warn")
                if len(refused) > 20:
                    job.step(f"{node['name']}: {len(refused) - 20} more lines refused.", "warn")
                job.step(f"{node['name']}: config typed in and saved"
                         + (f" ({len(refused)} line(s) refused, see above)." if refused else "."),
                         "warn" if refused else "ok")
        except (eveng.EveError, OSError) as exc:
            results[node["name"]] = str(exc)
            job.step(f"{node['name']}: {exc}", "error")
        finally:
            if con:
                con.close()

    threads = [threading.Thread(target=load, args=(n,), daemon=True) for n in nodes]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    done = [{"name": k, "result": v} for k, v in results.items()]
    bad = [d for d in done if d["result"] != "ok"]
    if bad:
        job.step(f"{len(done) - len(bad)} of {len(done)} configs loaded. Open the failed nodes' consoles in "
                 "EVE-NG to see why.", "warn")
    else:
        job.step("All configs loaded. Test away.", "ok")
    return done


def _pull(job: Job, row: dict, lab_row: dict) -> dict:
    eve = connect(row)
    try:
        lab_pw = clients._fernet().decrypt(lab_row["lab_password"].encode()).decode()
        nodes = json.loads(lab_row["nodes"])
        out = []
        for node in nodes:
            con = None
            try:
                host, port = eve.console(lab_row["path"], node["eve_id"])
                if node.get("dialect", "junos") == "junos":
                    con = eveng.Console(host, port)
                    con.login([(eveng.LAB_USER, lab_pw), ("root", "")], boot_timeout=120)
                    text = con.pull()
                    back = {v: k for k, v in node["ports"].items()}   # lab port -> real port
                    text = eveng.rename_ports(text, back)
                    text = "\n".join(ln for ln in text.split("\n") if f"login user {eveng.LAB_USER} " not in ln)
                else:
                    con = evelab.LabConsole(host, port, node["dialect"], lab_pw)
                    con.login(boot_timeout=120)
                    text = evelab.strip_lab_user(evelab.rename_back(con.pull(), node["ports"]))
                out.append({"name": node["hostname"], "text": text, "lldp": "",
                            "vendor": node.get("vendor", "juniper")})
                job.step(f"{node['name']}: read {text.count(chr(10))} lines.", "ok")
            except (eveng.EveError, OSError) as exc:
                job.step(f"{node['name']}: {exc}", "error")
            finally:
                if con:
                    con.close()
        junos = [o for o in out if o["vendor"] == "juniper"]
        if junos:   # keep them as config backups too (backups and compare are Junos only for now)
            from . import backups
            with job._db() as conn:
                backups.store(conn, lab_row["client_id"], junos, "eve", job.who, note=f"lab {lab_row['name']}",
                              space="lab")
        return {"items": out}
    finally:
        eve.logout()


# --------------------------------------------------------------- routes
def _client_row(role: str):
    c = clients.need_lab(role)
    return c, dict(clients.row(c["id"]))


@bp.get("/eve/images")
def images():
    c, row = _client_row("editor")
    try:
        eve = connect(row)
        try:
            return {"images": eve.juniper_images(), "settings": settings(row)}
        finally:
            eve.logout()
    except eveng.EveError as exc:
        return {"error": str(exc), "settings": settings(row)}, 400


@bp.get("/eve/labs")
def labs():
    c, row = _client_row("viewer")
    rows = auth.db().execute("SELECT id, name, path, template, image, nodes, created_at, created_by FROM eve_labs "
                             "WHERE client_id = ? ORDER BY id DESC", (c["id"],)).fetchall()
    jobs = auth.db().execute("SELECT id, kind, status, updated_at FROM eve_jobs WHERE client_id = ? AND status = "
                             "'running' ORDER BY id DESC", (c["id"],)).fetchall()
    return {"labs": [dict(r, nodes=json.loads(r["nodes"])) for r in rows], "settings": settings(row),
            "running": [dict(j) for j in jobs], "can_build": c["role"] == "admin",
            "web": row["eve_url"]}


@bp.post("/eve/labs")
def build():
    body = request.get_json(silent=True) or {}
    c, row = _client_row("admin")
    name = str(body.get("name") or "").strip()
    if not eveng.NAME_RE.match(name):
        return {"error": "Lab names are letters, digits, - and _ (up to 48), starting with a letter or digit."}, 400
    template = str(body.get("template") or row["eve_template"] or "vjunosswitch")
    image = str(body.get("image") or row["eve_image"] or "")
    if template not in eveng.TEMPLATES or not image:
        return {"error": "Pick a vJunos-switch image first."}, 400
    items = body.get("items") or []
    if not isinstance(items, list) or not items or not all(isinstance(i, dict) for i in items):
        return {"error": "Add some switches to the map first."}, 400
    if len(items) > 20:
        return {"error": "At most 20 switches in one lab."}, 400
    if not settings(row)["configured"]:
        return {"error": "EVE-NG is not set up for this client yet."}, 400
    who = auth.current_user()["username"]
    auth.db().execute("UPDATE clients SET eve_template = ?, eve_image = ? WHERE id = ?", (template, image[:200], c["id"]))
    auth.db().commit()
    job = Job(c["id"], "build", who)
    _run(job, _build, row, name, template, image, items, body.get("positions") or {}, bool(body.get("replace")),
         bool(body.get("start", True)), who)
    return {"job": job.id}


def _lab(cid: int, lid: int):
    r = auth.db().execute("SELECT * FROM eve_labs WHERE id = ? AND client_id = ?", (lid, cid)).fetchone()
    if r is None:
        abort(404)
    return dict(r)


@bp.post("/eve/labs/<int:lid>/<action>")
def lab_action(lid: int, action: str):
    c, row = _client_row("admin" if action in ("delete", "start", "stop", "forget") else "editor")
    lab = _lab(c["id"], lid)
    who = auth.current_user()["username"]
    if action == "pull":
        job = Job(c["id"], "pull", who)
        _run(job, _pull, row, lab)
        return {"job": job.id}
    if action == "forget":
        auth.db().execute("DELETE FROM eve_labs WHERE id = ?", (lid,))
        auth.db().commit()
        return {"ok": True}
    try:
        eve = connect(row)
        try:
            if action == "start":
                eve.start(lab["path"])
            elif action == "stop":
                eve.stop(lab["path"])
            elif action == "delete":
                try:
                    eve.stop(lab["path"])
                except eveng.EveError:
                    pass
                if eve.lab_exists(lab["path"]):
                    eve.delete_lab(lab["path"])
                auth.db().execute("DELETE FROM eve_labs WHERE id = ?", (lid,))
                auth.db().commit()
            else:
                abort(400)
        finally:
            eve.logout()
    except eveng.EveError as exc:
        return {"error": str(exc)}, 400
    log.warning("audit: %r %s EVE-NG lab %s (client %r)", who, action, lab["path"], c["name"])
    return {"ok": True}


@bp.get("/eve/vendor")
def vendor_lab():
    """What a vendor's lab runs on, and the matching images on this client's EVE-NG."""
    vendor = request.args.get("vendor", "juniper")
    info = evelab.catalog().get(vendor) or {"vendor": vendor, "possible": False,
                                            "why": "This vendor has no EVE-NG lab image."}
    if not info["possible"]:
        return {"lab": info, "images": []}
    c, row = _client_row("editor")
    lab_def = evelab.LABS[vendor]
    try:
        eve = connect(row)
        try:
            found = eve.images(lab_def.match)
        finally:
            eve.logout()
    except eveng.EveError as exc:
        return {"lab": info, "images": [], "error": str(exc), "settings": settings(row)}, 400
    return {"lab": info, "images": found, "settings": settings(row)}


@bp.post("/eve/project-labs")
def build_one():
    body = request.get_json(silent=True) or {}
    c, row = _client_row("admin")
    project = body.get("project")
    if not isinstance(project, dict):
        return {"error": "Send the project."}, 400
    vendor = str(project.get("vendor") or "juniper")
    if vendor not in evelab.LABS:
        return {"error": evelab.NO_LAB.get(vendor, "This vendor has no EVE-NG lab image.")}, 400
    name = str(body.get("name") or "").strip()
    if not eveng.NAME_RE.match(name):
        return {"error": "Lab names are letters, digits, - and _ (up to 48), starting with a letter or digit."}, 400
    template = str(body.get("template") or "").strip()
    image = str(body.get("image") or "").strip()
    if not re.match(r"^[A-Za-z0-9_.-]{1,60}$", template) or not re.match(r"^[A-Za-z0-9_.+-]{1,200}$", image):
        return {"error": f"Pick the {evelab.LABS[vendor].label} image first."}, 400
    if not settings(row)["configured"]:
        return {"error": "EVE-NG is not set up for this client yet."}, 400
    try:
        evelab.lab_project(project, "check-only")
    except eveng.EveError as exc:
        return {"error": str(exc)}, 400
    who = auth.current_user()["username"]
    job = Job(c["id"], "build", who)
    _run(job, _build_one, row, name, template, image, project, bool(body.get("replace")),
         bool(body.get("start", True)), who)
    return {"job": job.id}


@bp.get("/eve/jobs/<int:jid>")
def job_status(jid: int):
    c = clients.need("viewer")
    r = auth.db().execute("SELECT * FROM eve_jobs WHERE id = ? AND client_id = ?", (jid, c["id"])).fetchone()
    if r is None:
        abort(404)
    status = r["status"]
    if status == "running" and time.time() - r["updated_at"] > STALE:
        status = "failed"
    return {"id": r["id"], "kind": r["kind"], "status": status, "steps": json.loads(r["steps"]),
            "result": json.loads(r["result"]) if r["result"] else None}


def init_app(app) -> None:
    app.register_blueprint(bp)
