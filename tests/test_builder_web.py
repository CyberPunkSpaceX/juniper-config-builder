import re

import pytest

flask = pytest.importorskip("flask")

from test_auth import ADMIN, add_user, app, admin, basic, csrf, login  # noqa: F401,E402


def token(client):
    page = client.get("/").get_data(as_text=True)
    return re.search(r'id="csrf" value="([^"]+)"', page).group(1)


def test_page_has_models_and_timezones(admin):
    page = admin.get("/").get_data(as_text=True)
    assert "EX4400-48P" in page and "America/Edmonton" in page and "Juniper EX Config Builder" in page


def test_generate_needs_csrf(admin):
    assert admin.post("/generate", json={}).status_code == 400
    resp = admin.post("/generate", json={"system": {"hostname": "sw9"}}, headers={"X-CSRF-Token": token(admin)})
    assert resp.status_code == 200 and "host-name sw9" in resp.json["set"]
    assert resp.json["errors"]


def test_generate_returns_hashes(admin):
    resp = admin.post("/generate", json={"access": {"root_password": "Secret-123"}},
                      headers={"X-CSRF-Token": token(admin)})
    h = resp.json["hashed"]["access.root_password"]
    assert h.startswith("$6$") and "Secret-123" not in resp.json["set"]


def test_projects_are_per_user(app, admin):
    t = token(admin)
    hdr = {"X-CSRF-Token": t}
    resp = admin.post("/projects", json={"name": "Floor 2", "data": {"system": {"hostname": "f2"}}}, headers=hdr)
    pid = resp.json["id"]
    admin.post("/projects", json={"name": "Floor 2", "data": {"system": {"hostname": "f2b"}}}, headers=hdr)
    listing = admin.get("/projects").json["projects"]
    assert [p["name"] for p in listing] == ["Floor 2"]
    assert admin.get(f"/projects/{pid}").json["data"]["system"]["hostname"] == "f2b"

    add_user(admin)
    bob = app.test_client()
    login(bob, "bob", "bob-password-1")
    assert bob.get("/projects").json["projects"] == []
    assert bob.get(f"/projects/{pid}").status_code == 404
    assert bob.post(f"/projects/{pid}/delete", json={}, headers={"X-CSRF-Token": token(bob)}).status_code == 404
    assert admin.post(f"/projects/{pid}/delete", json={}, headers=hdr).status_code == 200
    assert admin.get("/projects").json["projects"] == []
    assert admin.post("/projects", json={"name": "", "data": {}}, headers=hdr).status_code == 400


def test_api_generate_formats(app):
    c = app.test_client()
    good = {"system": {"hostname": "sw1"}, "access": {"root_password": "Secret-123"}}
    resp = c.post("/api/generate?format=set", json=good, headers=basic(*ADMIN))
    assert resp.status_code == 200 and resp.mimetype == "text/plain" and "set system host-name sw1" in resp.get_data(as_text=True)
    resp = c.post("/api/generate?format=hierarchy", json={}, headers=basic(*ADMIN))
    assert resp.status_code == 422 and resp.json["errors"]
    assert c.get("/api/models", headers=basic(*ADMIN)).json["models"]
    assert c.post("/api/generate", json={}).status_code == 401
