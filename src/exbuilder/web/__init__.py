"""Web GUI for EX Config Builder.

The page is a single-page form. Every change is sent to ``/generate`` as JSON
and the config comes back; nothing is stored unless the user saves the
project. Saved projects live in the same SQLite database as the users, one
list per user.

Settings (environment variables):

* ``EXB_DATA_DIR``: where users, projects and the session key are stored (default /data).
* ``EXB_USERNAME`` / ``EXB_PASSWORD`` (or ``EXB_PASSWORD_FILE``): the first
  admin, created on first start when there are no users. Without them the
  first sign-in is admin / admin with a forced password change. See auth.py.
* ``EXB_SECURE_COOKIES``: set to true once the UI is served over HTTPS.
* ``EXB_REQUIRE_2FA``: make two-factor sign-in compulsory.
"""

from __future__ import annotations

import json
import zoneinfo
from datetime import datetime, timezone

from flask import Flask, Response, abort, render_template, request

from .. import __version__, fabric, models
from ..generator import DEFAULTS, build
from . import auth

MAX_PROJECT_BYTES = 512 * 1024


def _timezones() -> list[str]:
    try:
        zones = zoneinfo.available_timezones()
    except Exception:  # noqa: BLE001 - no tz database: offer UTC only
        zones = set()
    return ["UTC", *sorted(z for z in zones if "/" in z and not z.startswith(("Etc/", "SystemV/", "posix/", "right/")))]


def _project_from_request() -> dict:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        abort(400, "Send the project as a JSON object.")
    return data


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
    auth.init_app(app)
    zones = _timezones()

    @app.after_request
    def headers(resp: Response) -> Response:
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        return resp

    @app.get("/")
    def index():
        return render_template("builder.html", version=__version__, catalog=models.catalog(),
                               defaults=DEFAULTS, timezones=zones, fabric_templates=fabric.TEMPLATES,
                               fabric_flavors=fabric.FLAVORS, fabric_defaults=fabric.DEFAULTS)

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "version": __version__}

    @app.post("/generate")
    def generate():
        return build(_project_from_request()).to_dict()

    # ------------------------------------------------------- fabric wizard
    def _fabric_result() -> dict:
        body = _project_from_request()
        spec, base = body.get("fabric"), body.get("base") or {}
        if not isinstance(spec, dict) or not isinstance(base, dict):
            abort(400, "Send {fabric: {...}, base: {...}}.")
        return fabric.generate(spec, base)

    @app.post("/fabric")
    def fabric_generate():
        result = _fabric_result()
        return (result, 400) if "error" in result else result

    @app.post("/fabric/zip")
    def fabric_zip():
        result = _fabric_result()
        if "error" in result:
            return result, 400
        return Response(fabric.to_zip(result), mimetype="application/zip",
                        headers={"Content-Disposition": "attachment; filename=fabric-configs.zip"})

    # -------------------------------------------------------- saved projects
    def _uid() -> int:
        return auth.current_user()["id"]

    @app.get("/projects")
    def projects_list():
        rows = auth.db().execute(
            "SELECT id, name, updated_at FROM projects WHERE owner_id = ? ORDER BY name COLLATE NOCASE", (_uid(),))
        return {"projects": [dict(r) for r in rows]}

    @app.get("/projects/<int:pid>")
    def projects_get(pid: int):
        row = auth.db().execute("SELECT * FROM projects WHERE id = ? AND owner_id = ?", (pid, _uid())).fetchone()
        if row is None:
            abort(404)
        return {"id": row["id"], "name": row["name"], "data": json.loads(row["data"])}

    @app.post("/projects")
    def projects_save():
        body = _project_from_request()
        name = str(body.get("name") or "").strip()[:100]
        data = body.get("data")
        if not name or not isinstance(data, dict):
            return {"error": "Give the project a name."}, 400
        text = json.dumps(data)
        if len(text) > MAX_PROJECT_BYTES:
            return {"error": "Project is too large."}, 400
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        db = auth.db()
        db.execute("INSERT INTO projects (owner_id, name, data, updated_at) VALUES (?, ?, ?, ?) "
                   "ON CONFLICT (owner_id, name) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at",
                   (_uid(), name, text, now))
        db.commit()
        pid = db.execute("SELECT id FROM projects WHERE owner_id = ? AND name = ?", (_uid(), name)).fetchone()[0]
        return {"id": pid, "name": name, "updated_at": now}

    @app.post("/projects/<int:pid>/delete")
    def projects_delete(pid: int):
        db = auth.db()
        cur = db.execute("DELETE FROM projects WHERE id = ? AND owner_id = ?", (pid, _uid()))
        db.commit()
        if cur.rowcount == 0:
            abort(404)
        return {"deleted": pid}

    # -------------------------------------------------------------- scripts
    @app.get("/api/models")
    def api_models():
        return {"models": models.catalog()}

    @app.post("/api/generate")
    def api_generate():
        """For scripts.

        curl -u user:TOKEN -H 'Content-Type: application/json' --data @project.json \\
             'https://host/api/generate?format=set'
        """
        result = build(_project_from_request())
        fmt = request.args.get("format", "json")
        if fmt in ("set", "hierarchy"):
            if result.errors:
                return {"errors": result.errors, "warnings": result.warnings}, 422
            return Response(result.set_text if fmt == "set" else result.hier_text, mimetype="text/plain")
        return result.to_dict()

    @app.errorhandler(400)
    def bad_request(err):
        if request.is_json or request.path != "/":
            return {"error": getattr(err, "description", "Bad request")}, 400
        return err

    return app
