import json
import sqlite3

import pytest

flask = pytest.importorskip("flask")

from test_auth import ADMIN, add_user, app, admin, csrf, login  # noqa: F401,E402
from test_builder_web import token  # noqa: E402


def _form(client, path, **data):
    return client.post(path, data={"csrf_token": csrf(client, "/clients"), **data})


def _bob(app, admin, role=None, client_id=1):
    add_user(admin)
    if role:
        _form(admin, f"/clients/{client_id}", action="member_add", username="bob", role=role)
    bob = app.test_client()
    assert login(bob, "bob", "bob-password-1").status_code == 302
    return bob


def test_first_client_and_switcher(app, admin):
    page = admin.get("/").get_data(as_text=True)
    assert 'id="client-pick"' in page and ">Default</option>" in page and "Save to Default" in page
    resp = _form(admin, "/clients", name="Acme Corp")
    assert resp.status_code == 302 and resp.location.endswith("/clients/2")
    assert _form(admin, "/clients", name="acme corp").status_code == 302  # duplicate: refused with a message
    assert len(admin.get("/clients").get_data(as_text=True).split("<b>Acme Corp</b>")) == 2
    assert _form(admin, "/clients", name="<script>").status_code == 302
    assert "&lt;script&gt;" not in admin.get("/clients").get_data(as_text=True)


def test_projects_and_maps_are_per_client(app, admin):
    hdr = {"X-CSRF-Token": token(admin)}
    admin.post("/projects", json={"name": "Floor 2", "data": {"system": {"hostname": "f2"}}}, headers=hdr)
    admin.post("/maps", json={"name": "HQ", "data": {"items": [{"name": "sw1", "text": "set x"}], "pos": {}}},
               headers=hdr)
    _form(admin, "/clients", name="Acme")
    _form(admin, "/clients/select", client_id="2")
    assert admin.get("/projects").json == {"projects": [], "client": "Acme", "can_edit": True}
    assert admin.get("/maps").json["maps"] == []
    admin.post("/projects", json={"name": "Floor 2", "data": {"system": {"hostname": "acme"}}}, headers=hdr)
    _form(admin, "/clients/select", client_id="1")
    (p,) = admin.get("/projects").json["projects"]
    assert admin.get(f"/projects/{p['id']}").json["data"]["system"]["hostname"] == "f2"
    (m,) = admin.get("/maps").json["maps"]
    assert m["name"] == "HQ" and admin.get(f"/maps/{m['id']}").json["data"]["items"][0]["name"] == "sw1"
    assert admin.post(f"/maps/{m['id']}/delete", json={}, headers=hdr).status_code == 200
    assert admin.post("/maps", json={"name": "", "data": {}}, headers=hdr).status_code == 400


def test_roles(app, admin):
    hdr = {"X-CSRF-Token": token(admin)}
    pid = admin.post("/projects", json={"name": "P", "data": {}}, headers=hdr).json["id"]
    _form(admin, "/clients", name="Acme")
    bob = _bob(app, admin)
    bh = {"X-CSRF-Token": token(bob)}
    # Not in any client: can build, can't save or see anything.
    page = bob.get("/").get_data(as_text=True)
    assert 'id="client-pick"' not in page and "not in any client" in page
    assert bob.get("/projects").status_code == 409
    assert bob.post("/projects", json={"name": "x", "data": {}}, headers=bh).status_code == 409
    assert bob.post("/generate", json={}, headers=bh).status_code == 200
    # Viewer of Default: reads, can't write, can't open Acme.
    _form(admin, "/clients/1", action="member_add", username="bob", role="viewer")
    assert bob.get("/projects").json["can_edit"] is False
    assert bob.get(f"/projects/{pid}").status_code == 200
    assert bob.post("/projects", json={"name": "x", "data": {}}, headers=bh).status_code == 403
    assert bob.post(f"/projects/{pid}/delete", json={}, headers=bh).status_code == 403
    assert bob.post("/clients/select", data={"csrf_token": csrf(bob), "client_id": "2"}).status_code == 403
    assert bob.get("/clients/1").status_code == 403
    assert "Acme" not in bob.get("/").get_data(as_text=True)
    # Editor: saves.
    _form(admin, "/clients/1", action="member_role", user_id="2", role="editor")
    assert bob.post("/projects", json={"name": "x", "data": {}}, headers=bh).status_code == 200
    assert bob.get("/clients/1").status_code == 403
    # Client admin: manages people and SSH, but can't rename or delete the client.
    _form(admin, "/clients/1", action="member_role", user_id="2", role="admin")
    assert bob.get("/clients/1").status_code == 200
    assert _form(bob, "/clients/1", action="rename", name="Mine").status_code == 400
    assert _form(bob, "/clients/1", action="delete", confirm="Default").status_code == 400
    assert bob.post("/clients", data={"csrf_token": csrf(bob), "name": "New"}).status_code == 403
    # Removed: back to nothing.
    _form(admin, "/clients/1", action="member_remove", user_id="2")
    assert bob.get("/projects").status_code == 409


def test_delete_client_needs_its_name(app, admin):
    hdr = {"X-CSRF-Token": token(admin)}
    _form(admin, "/clients", name="Acme")
    _form(admin, "/clients/select", client_id="2")
    admin.post("/projects", json={"name": "P", "data": {}}, headers=hdr)
    _form(admin, "/clients/2", action="delete", confirm="acme")
    assert "<b>Acme</b>" in admin.get("/clients").get_data(as_text=True)
    _form(admin, "/clients/2", action="delete", confirm="Acme")
    assert "<b>Acme</b>" not in admin.get("/clients").get_data(as_text=True)
    assert admin.get("/projects").json["client"] == "Default"  # falls back to a client that exists


def test_ssh_settings_are_checked(app, admin, monkeypatch):
    monkeypatch.delenv("EXB_SSH_ALLOW", raising=False)
    _form(admin, "/clients/1", action="ssh", networks="8.8.8.0/24", ssh_user="")
    page = admin.get("/clients/1").get_data(as_text=True)
    assert "8.8.8.0/24" not in page.split('name="networks"')[1].split("</textarea>")[0]
    _form(admin, "/clients/1", action="ssh", networks="10.40.10.0/24, 10.40.20.0/24", ssh_user="exbuilder-ro")
    page = admin.get("/clients/1").get_data(as_text=True)
    assert "10.40.10.0/24, 10.40.20.0/24" in page and 'value="exbuilder-ro"' in page


def test_migration_from_before_clients(monkeypatch, tmp_path):
    """A database with per-user projects moves into the first client."""
    conn = sqlite3.connect(tmp_path / "users.db")
    conn.executescript("""
        CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', active INTEGER NOT NULL DEFAULT 1,
            must_change INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, last_login TEXT);
        CREATE TABLE projects (id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL, name TEXT NOT NULL,
            data TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE (owner_id, name));
    """)
    from werkzeug.security import generate_password_hash
    for name, role in (("admin", "admin"), ("bob", "user")):
        conn.execute("INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, 'x')",
                     (name, generate_password_hash(name + "-password-1"), role))
    for owner, pname in ((1, "Core"), (2, "Core"), (2, "Floor 3")):
        conn.execute("INSERT INTO projects (owner_id, name, data, updated_at) VALUES (?, ?, ?, 'then')",
                     (owner, pname, json.dumps({"by": owner})))
    conn.commit()
    conn.close()
    (tmp_path / "ssh_known_hosts").write_text("10.0.0.1 ssh-ed25519 AAAA\n")
    monkeypatch.setenv("EXB_DATA_DIR", str(tmp_path))
    from exbuilder.web import create_app
    application = create_app()
    application.testing = True
    bob = application.test_client()
    assert login(bob, "bob", "bob-password-1").status_code == 302
    names = sorted(p["name"] for p in bob.get("/projects").json["projects"])
    assert names == ["Core", "Core (bob)", "Floor 3"]
    assert bob.get("/projects").json["can_edit"]  # owners become editors
    assert (tmp_path / "clients" / "1" / "ssh_known_hosts").read_text().startswith("10.0.0.1")
    assert not (tmp_path / "ssh_known_hosts").exists()
    create_app()  # a second start changes nothing
    assert len(bob.get("/projects").json["projects"]) == 3
