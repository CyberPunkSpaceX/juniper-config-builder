import json

import pytest

flask = pytest.importorskip("flask")

from test_auth import ADMIN, add_user, csrf, login  # noqa: E402
from test_builder_web import token  # noqa: E402

FAKE = [{"key": "demo-lab", "name": "Training Lab - Demo", "description": "A tiny demo.",
         "projects": [{"space": "lab", "name": "spine1", "data": {"system": {"hostname": "spine1"}}},
                      {"space": "production", "name": "spine1", "data": {"system": {"hostname": "spine1"}}}],
         "maps": [{"space": "lab", "name": "Fabric", "data": {"items": [], "pos": {}}}]}]


@pytest.fixture
def make_app(monkeypatch, tmp_path):
    monkeypatch.setenv("EXB_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("EXB_USERNAME", ADMIN[0])
    monkeypatch.setenv("EXB_PASSWORD", ADMIN[1])
    monkeypatch.setenv("EXB_SAMPLES", "on")
    from switchbuilder.web import auth, create_app, samples
    monkeypatch.setattr(auth.time, "sleep", lambda _s: None)
    monkeypatch.setattr(samples, "available", lambda: json.loads(json.dumps(FAKE)))

    def make():
        app = create_app()
        app.testing = True
        return app
    return make


def _admin(app):
    c = app.test_client()
    assert login(c, *ADMIN).status_code == 302
    return c


def _db(tmp_path):
    import sqlite3
    return sqlite3.connect(tmp_path / "users.db")


def test_sample_added_once_and_delete_sticks(make_app, tmp_path):
    app = make_app()
    admin = _admin(app)
    page = admin.get("/clients").get_data(as_text=True)
    assert "<b>Training Lab - Demo</b>" in page and "sample</span>" in page and "A tiny demo." in page
    cid = _db(tmp_path).execute("SELECT id FROM clients WHERE sample = 'demo-lab'").fetchone()[0]
    counts = dict(_db(tmp_path).execute("SELECT space, COUNT(*) FROM projects WHERE client_id = ? GROUP BY space", (cid,)))
    assert counts == {"lab": 1, "production": 1}
    assert "This is a sample client" in admin.get(f"/clients/{cid}").get_data(as_text=True)
    resp = admin.post(f"/clients/{cid}", data={"csrf_token": csrf(admin, f"/clients/{cid}"), "action": "delete",
                                               "confirm": "Training Lab - Demo"}, follow_redirects=True)
    assert "It stays gone" in resp.get_data(as_text=True)
    # A restart (and an upgrade) doesn't bring it back.
    app = make_app()
    admin = _admin(app)
    assert not _db(tmp_path).execute("SELECT 1 FROM clients WHERE name = 'Training Lab - Demo'").fetchone()
    page = admin.get("/clients").get_data(as_text=True)
    assert 'id="samples"' in page and "Add back" in page
    # ...but a Super Admin can add it back by hand.
    admin.post("/clients/samples", data={"csrf_token": csrf(admin, "/clients"), "key": "demo-lab"})
    assert _db(tmp_path).execute("SELECT COUNT(*) FROM projects p JOIN clients c ON c.id = p.client_id "
                                 "WHERE c.sample = 'demo-lab'").fetchone()[0] == 2
    assert 'id="samples"' not in admin.get("/clients").get_data(as_text=True)


def test_everyone_opens_samples_read_only(make_app, tmp_path):
    app = make_app()
    admin = _admin(app)
    add_user(admin)
    bob = app.test_client()
    assert login(bob, "bob", "bob-password-1").status_code == 302
    pick = bob.get("/clients/pick").get_data(as_text=True)
    assert "Training Lab - Demo" in pick and ">Sample<" in pick
    cid = _db(tmp_path).execute("SELECT id FROM clients WHERE sample = 'demo-lab'").fetchone()[0]
    bob.post("/clients/select", data={"csrf_token": csrf(bob, "/clients"), "client_id": str(cid)})
    bob.post("/space", data={"csrf_token": csrf(bob, "/clients"), "space": "lab"})
    listing = bob.get("/projects").json
    assert listing["can_edit"] is False and [p["name"] for p in listing["projects"]] == ["spine1"]
    resp = bob.post("/projects", json={"name": "mine", "data": {}}, headers={"X-CSRF-Token": token(bob)})
    assert resp.status_code == 403
    assert bob.get(f"/clients/{cid}").status_code == 403   # no settings, no delete


def test_same_name_client_is_marked_not_doubled(make_app, tmp_path):
    from switchbuilder.web import samples
    app = make_app()
    db = _db(tmp_path)
    db.execute("DELETE FROM clients WHERE sample = 'demo-lab'")
    db.execute("DELETE FROM samples_added")
    db.execute("INSERT INTO clients (name, created_at) VALUES ('Training Lab - Demo', 'x')")
    db.commit()
    samples.migrate(db)
    db.commit()
    assert db.execute("SELECT COUNT(*), MAX(sample) FROM clients WHERE name = 'Training Lab - Demo'").fetchone() == (1, "demo-lab")
    assert app


def test_switched_off(make_app, tmp_path, monkeypatch):
    monkeypatch.setenv("EXB_SAMPLES", "off")
    make_app()
    assert not _db(tmp_path).execute("SELECT 1 FROM clients WHERE sample IS NOT NULL").fetchone()


def test_shipped_samples_are_valid():
    from switchbuilder.web import samples
    shipped = samples.available()
    keys = [s["key"] for s in shipped]
    assert len(keys) == len(set(keys))
    for s in shipped:
        assert s["name"].startswith("Training Lab") and s["projects"] and s["maps"]
        text = json.dumps(s)
        assert "$6$" not in text or samples.SAMPLE_PASSWORD_NOTE in s["description"]
