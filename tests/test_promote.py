"""Lab -> Production: ask for approval, approve or reject, promote, undo."""

import json
from pathlib import Path

import pytest

flask = pytest.importorskip("flask")

from test_auth import ADMIN, add_user, app, admin, csrf, login  # noqa: F401,E402
from test_builder_web import pick_space, token  # noqa: E402
from test_clients import _bob, _form  # noqa: E402

GOOD = json.loads((Path(__file__).parent.parent / "src" / "exbuilder" / "vendor_examples" / "arista-office.json").read_text())


def _save(client, name, data):
    return client.post("/projects", json={"name": name, "data": data}, headers={"X-CSRF-Token": token(client)}).json["id"]


def _post(client, url, body=None):
    return client.post(url, json=body or {}, headers={"X-CSRF-Token": token(client)})


def _prod(client):
    pick_space(client, "production")
    out = {p["name"]: client.get(f"/projects/{p['id']}").json["data"] for p in client.get("/projects").json["projects"]}
    pick_space(client, "lab")
    return out


def test_request_approve_promote_and_undo(app, admin):
    pick_space(admin, "production")
    old = dict(GOOD, name="Office")
    old["system"] = dict(GOOD["system"], hostname="office-old")
    _save(admin, "Office", old)
    pick_space(admin, "lab")
    new = dict(GOOD, name="Office")
    lab_id = _save(admin, "Office", new)
    # Only from Lab, and only a project that builds.
    pick_space(admin, "production")
    assert _post(admin, "/promote/request", {"project_id": lab_id}).status_code == 409
    pick_space(admin, "lab")
    broken = _save(admin, "Broken", {"vendor": "arista"})
    r = _post(admin, "/promote/request", {"project_id": broken})
    assert r.status_code == 400 and "error(s) to fix" in r.json["error"]

    rid = _post(admin, "/promote/request", {"project_id": lab_id, "note": "Tested in EVE"}).json["id"]
    assert _post(admin, f"/promote/{rid}/promote").status_code == 400          # not approved yet
    assert _post(admin, f"/promote/{rid}/reject").status_code == 400           # a reason is needed
    data = admin.get("/promote").json
    assert data["self_approve"] is True and data["reviews"][0]["status"] == "pending"
    assert data["reviews"][0]["note"] == "Tested in EVE"
    # The only admin may approve their own request.
    assert _post(admin, f"/promote/{rid}/approve", {"note": "Looks good"}).json["status"] == "approved"
    r = _post(admin, f"/promote/{rid}/promote")
    assert r.json["status"] == "promoted" and r.json["replaced"] is True
    assert _prod(admin)["Office"]["system"]["hostname"] == GOOD["system"]["hostname"]
    rev = admin.get("/promote").json["reviews"][0]
    assert rev["status"] == "promoted" and rev["decided_by"] == ADMIN[0] and rev["can_undo"]
    # Undo puts the old Production project back.
    assert _post(admin, f"/promote/{rid}/undo").json["status"] == "undone"
    assert _prod(admin)["Office"]["system"]["hostname"] == "office-old"


def test_changes_after_approval_need_a_new_approval(app, admin):
    pick_space(admin, "lab")
    lab_id = _save(admin, "Core", dict(GOOD, name="Core"))
    rid = _post(admin, "/promote/request", {"project_id": lab_id}).json["id"]
    _post(admin, f"/promote/{rid}/approve")
    changed = dict(GOOD, name="Core")
    changed["system"] = dict(GOOD["system"], hostname="core-changed")
    _save(admin, "Core", changed)
    assert admin.get("/promote").json["reviews"][0]["lab_changed"] is True
    r = _post(admin, f"/promote/{rid}/promote")
    assert r.status_code == 409 and "changed after it was approved" in r.json["error"]
    assert "Core" not in _prod(admin)
    # A new request replaces the old one; undo of a first-time promotion removes the project.
    rid2 = _post(admin, "/promote/request", {"project_id": lab_id}).json["id"]
    assert [r["status"] for r in admin.get("/promote").json["reviews"]] == ["pending", "replaced"]
    _post(admin, f"/promote/{rid2}/approve")
    assert _post(admin, f"/promote/{rid2}/promote").json["replaced"] is False
    assert _prod(admin)["Core"]["system"]["hostname"] == "core-changed"
    _post(admin, f"/promote/{rid2}/undo")
    assert "Core" not in _prod(admin)


def test_roles_and_four_eyes(app, admin):
    pick_space(admin, "lab")
    bob = _bob(app, admin, role="editor")
    pick_space(bob, "lab")
    lab_id = _save(bob, "Edge", dict(GOOD, name="Edge"))
    rid = _post(bob, "/promote/request", {"project_id": lab_id}).json["id"]
    assert _post(bob, f"/promote/{rid}/approve").status_code == 403           # editors can't approve
    assert _post(bob, f"/promote/{rid}/promote").status_code == 403
    # With a second admin, nobody approves their own request.
    _form(admin, "/clients/1", action="member_add", username="bob", role="admin")
    assert bob.get("/promote").json["role"] == "admin" and bob.get("/promote").json["self_approve"] is False
    r = _post(bob, f"/promote/{rid}/approve")
    assert r.status_code == 403 and "Another admin" in r.json["error"]
    assert _post(admin, f"/promote/{rid}/approve").json["status"] == "approved"
    # Other clients can't see or touch it.
    _form(admin, "/clients", name="Acme")
    _form(admin, "/clients/select", client_id="2")
    assert admin.get("/promote").json["reviews"] == []
    assert _post(admin, f"/promote/{rid}/promote").status_code == 404
    assert admin.get(f"/promote/{rid}/data").status_code == 404


def test_projects_tab_shows_the_steps(app, admin):
    pick_space(admin, "lab")
    page = admin.get("/build/arista").get_data(as_text=True)
    assert "From Lab to Production" in page and "Ask for approval" in page
    pick_space(admin, "production")
    assert "Projects come here from the Lab space" in admin.get("/build/arista").get_data(as_text=True)


def test_client_setting_lets_admins_approve_their_own(app, admin):
    pick_space(admin, "lab")
    bob = _bob(app, admin, role="editor")
    _form(admin, "/clients/1", action="member_add", username="bob", role="admin")
    lab_id = _save(admin, "Solo", dict(GOOD, name="Solo"))
    rid = _post(admin, "/promote/request", {"project_id": lab_id}).json["id"]
    data = admin.get("/promote").json
    assert data["self_approve"] is False and data["other_approvers"] == ["bob"]
    r = _post(admin, f"/promote/{rid}/approve")
    assert r.status_code == 403 and "bob" in r.json["error"]
    page = admin.get("/clients/1").get_data(as_text=True)
    assert "Lab to Production approvals" in page and "Let admins approve their own requests" in page
    # Client admins can't switch the rule off; only a Super Admin can.
    pick_space(bob, "lab")
    assert _form(bob, "/clients/1", action="approvals", self_approve="1").status_code == 400
    _form(admin, "/clients/1", action="approvals", self_approve="1")
    assert admin.get("/promote").json["self_approve"] is True
    assert _post(admin, f"/promote/{rid}/approve").json["status"] == "approved"
    _form(admin, "/clients/1", action="approvals")
    assert admin.get("/promote").json["self_approve"] is False
