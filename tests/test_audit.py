"""Audit log and the /api/v1 scripting API."""

import json
import logging
from pathlib import Path

from test_auth import (  # noqa: F401 - fixtures
    add_user,
    admin,
    app,
    basic,
    csrf,
    login,
    user_id,
)
from test_builder_web import pick_space, token
from test_clients import _bob, _form

PROJECT = json.loads((Path(__file__).parent.parent / "src/switchbuilder/vendor_examples/arista-office.json").read_text())


def _rows(client, **q):
    resp = client.get("/tools/audit/rows", query_string=q)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    return resp.json["rows"]


def test_changes_and_sign_ins_are_logged(app, admin):
    pick_space(admin)
    resp = admin.post("/projects", json={"name": "p1", "data": PROJECT}, headers={"X-CSRF-Token": token(admin)})
    assert resp.status_code == 200
    # pure calculations are not logged
    admin.post("/tools/calc/subnet", json={"cidr": "10.0.0.0/24"}, headers={"X-CSRF-Token": token(admin)})
    login(app.test_client(), "admin", "wrong-password")
    rows = _rows(admin)
    paths = [r["path"] for r in rows]
    assert "/projects" in paths and "/tools/calc/subnet" not in paths
    saved = next(r for r in rows if r["path"] == "/projects")
    assert saved["user"] == "admin" and saved["client"] == "Default" and saved["space"] == "production"
    assert saved["kind"] == "change" and saved["status"] == 200 and "Secret" not in str(rows)
    assert any(r["kind"] == "sign-in" and "signed in" in r["message"] for r in rows)
    failed = next(r for r in rows if "failed sign-in" in r["message"])
    assert failed["user"] == "admin" and failed["kind"] == "sign-in"
    assert [r["path"] for r in _rows(admin, q="projects")] == ["/projects"]
    assert all(r["kind"] == "sign-in" for r in _rows(admin, kind="sign-in"))
    csv = admin.get("/tools/audit/csv").get_data(as_text=True)
    assert csv.startswith("at,user,client") and "/projects" in csv


def test_background_lines_get_their_own_row(app, admin):
    logging.getLogger("switchbuilder.nightly").warning("audit: nightly backup (schedule) of client %r: 1 changed", "Default")
    logging.getLogger("switchbuilder.nightly").info("just chatter")
    rows = _rows(admin, kind="event")
    assert [r["message"] for r in rows] == ["nightly backup (schedule) of client 'Default': 1 changed"]
    assert rows[0]["user"] == "(system)"


def test_who_sees_what(app, admin):
    _form(admin, "/clients", name="Acme")
    bob = _bob(app, admin, role="admin", client_id=2)
    pick_space(admin)
    admin.post("/projects", json={"name": "in-default", "data": PROJECT}, headers={"X-CSRF-Token": token(admin)})
    bob.post("/clients/select", data={"csrf_token": csrf(bob, "/start"), "client_id": 2})
    pick_space(bob)
    assert bob.post("/projects", json={"name": "in-acme", "data": PROJECT},
                    headers={"X-CSRF-Token": token(bob)}).status_code == 200
    mine = _rows(bob)
    assert mine and {r["client"] for r in mine} == {"Acme"}
    assert any("added 'bob' as admin" in r["message"] for r in mine)   # /clients/2 counts for Acme
    everything = _rows(admin)
    assert any(r["client"] == "" for r in everything) and len(everything) > len(mine)
    # a plain member sees the API help but not the log
    carol = app.test_client()
    add_user(admin, "carol", "carol-password-1")
    _form(admin, "/clients/2", action="member_add", username="carol", role="editor")
    login(carol, "carol", "carol-password-1")
    page = carol.get("/tools/audit").get_data(as_text=True)
    assert "The audit log is for admins" in page and "/api/v1/projects" in page
    assert carol.get("/tools/audit/rows").status_code == 403
    assert carol.get("/tools/audit/csv").status_code == 403


def test_api(app, admin):
    bob_web = _bob(app, admin, role="viewer")
    api = app.test_client()
    me = basic("bob", "bob-password-1")
    assert api.get("/api/v1/clients").status_code == 401
    assert api.get("/api/v1/clients", headers=me).json["clients"] == [{"id": 1, "name": "Default", "role": "viewer"}]
    # a viewer cannot write
    assert api.put("/api/v1/projects/core-sw1", json=PROJECT, headers=me).status_code == 403
    _form(admin, "/clients/1", action="member_role", user_id=user_id(app, "bob"), role="editor")
    resp = api.put("/api/v1/projects/core-sw1", json=PROJECT, headers=me)
    assert resp.status_code == 201, resp.get_data(as_text=True)
    pid = resp.json["id"]
    assert api.put("/api/v1/projects/core-sw1", json=PROJECT, headers=me).json["created"] is False
    listed = api.get("/api/v1/projects", headers=me).json
    assert listed["client"] == "Default" and [p["name"] for p in listed["projects"]] == ["core-sw1"]
    one = api.get(f"/api/v1/projects/{pid}", headers=me).json
    assert one["data"]["system"]["hostname"] == "ar-office-01"
    text = api.get(f"/api/v1/projects/{pid}/config", headers=me).get_data(as_text=True)
    assert "hostname ar-office-01" in text
    assert api.get(f"/api/v1/projects/{pid}?space=lab", headers=me).status_code == 404
    assert api.get("/api/v1/projects?client=Nope", headers=me).status_code == 404
    assert api.get("/api/v1/backups?latest=1", headers=me).json["backups"] == []
    assert api.get("/api/v1/audit", headers=me).status_code == 403
    # the writes are in the log, as API calls, with the client
    rows = [r for r in _rows(admin, kind="api") if r["method"] == "PUT"]
    assert rows and rows[0]["user"] == "bob" and rows[0]["client"] == "Default"
    assert any("over the API" in r["message"] for r in rows)
    # wrong token: a failed sign-in row
    api.get("/api/v1/clients", headers=basic("bob", "nope"))
    assert any(r["user"] == "bob" and r["status"] == 401 for r in _rows(admin, kind="api"))
    assert bob_web  # keeps the web session alive for the test


def test_hub_card(admin):
    assert "Audit log &amp; API" in admin.get("/tools/").get_data(as_text=True)


def test_read_only_api_config_and_bulk_hide_secrets(app, admin):
    """Found in a full QA pass: the API refused to build for Read-only people (422), and Toolkit bulk
    builds from a saved project showed its passwords and SNMP communities to them."""
    _bob(app, admin, role="viewer")
    api = app.test_client()
    me = basic("bob", "bob-password-1")
    pid = admin.post("/projects", json={"name": "secret-sw", "data": PROJECT},
                     headers={"X-CSRF-Token": token(admin)}).json["id"]
    resp = api.get(f"/api/v1/projects/{pid}/config", headers=me)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    text = resp.get_data(as_text=True)
    assert "hostname ar-office-01" in text and "s3cret-ro" not in text and "S3CRET" not in text
    bob = app.test_client()
    assert login(bob, "bob", "bob-password-1").status_code == 302
    h = {"X-CSRF-Token": token(bob)}
    csv = "hostname,mgmt_address\nsw-a,192.168.100.50/24\n"
    out = bob.post("/tools/bulk/run", json={"project_id": pid, "csv": csv}, headers=h).get_data(as_text=True)
    assert "s3cret-ro" not in out and "Change-me-2026" not in out and "$6$" not in out
