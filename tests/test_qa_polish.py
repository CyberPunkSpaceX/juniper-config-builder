"""Small fixes from the 2026-11-26 QA pass: sign-in from other sites, Read-only builder, Global addresses."""

import json
from pathlib import Path

import pytest

flask = pytest.importorskip("flask")

from test_auth import ADMIN, add_user, admin, app, login  # noqa: F401,E402
from test_builder_web import token  # noqa: E402
from test_clients import _bob  # noqa: E402

from exbuilder import firmware  # noqa: E402

PROJECT = json.loads((Path(__file__).parent.parent / "src/exbuilder/vendor_examples/cisco-office.json").read_text())


def test_sign_in_from_another_site_is_refused(app):
    c = app.test_client()
    data = {"username": ADMIN[0], "password": ADMIN[1]}
    assert c.post("/login", data=data, headers={"Origin": "https://evil.example"}).status_code == 400
    assert c.post("/login", data=data, headers={"Origin": "null"}).status_code == 400
    assert c.post("/login", data=data, headers={"Origin": "http://localhost"}).status_code == 302   # same site
    assert app.test_client().post("/login", data=data).status_code == 302                           # scripts


def test_sign_in_through_the_public_address(app, monkeypatch):
    monkeypatch.setenv("EXB_PUBLIC_URL", "https://switchbuilder.example.com")
    c = app.test_client()
    resp = c.post("/login", data={"username": ADMIN[0], "password": ADMIN[1]},
                  headers={"Origin": "https://switchbuilder.example.com"})
    assert resp.status_code == 302


def test_read_only_builder_has_no_save_or_push(app, admin):
    _bob(app, admin, role="viewer")
    bob = app.test_client()
    login(bob, "bob", "bob-password-1")
    page = bob.get("/build/cisco").get_data(as_text=True)
    assert 'id="btn-save-server" type="button" hidden' in page and 'id="push-box" hidden' in page
    page = admin.get("/build/cisco").get_data(as_text=True)
    assert 'id="btn-save-server" type="button" title' in page and 'id="push-box">' in page


def test_global_shows_the_project_management_address(app, admin):
    admin.post("/projects", json={"name": "P", "data": PROJECT}, headers={"X-CSRF-Token": token(admin)})
    switches = admin.get("/global/data").json["switches"]
    sw = next(s for s in switches if s["host"] == "cs-office-01")
    assert sw["address"] == "192.168.100.31"


def test_firmware_says_how_to_get_a_version():
    out = firmware.assess("sw1", "cisco", "", "", {"rows": []})
    assert out["status"] == "unknown" and "show version" in out["why"]
