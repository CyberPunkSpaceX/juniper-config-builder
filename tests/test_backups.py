import io
import json
import sqlite3
import zipfile

import pytest

from exbuilder import compare

flask = pytest.importorskip("flask")

from test_auth import ADMIN, add_user, app, admin, csrf, login  # noqa: F401,E402
from test_builder_web import token  # noqa: E402

LIVE = """set version 22.4R3
set system host-name sw-office-01
set system root-authentication encrypted-password "$6$abc$one"
set system domain-name example.lan
set interfaces ge-0/0/1 description "to pc"
set interfaces ge-0/0/1 unit 0 family ethernet-switching vlan members USERS
set interfaces ge-0/0/2 description spare
set interfaces ge-0/0/2 unit 0 family ethernet-switching vlan members USERS
set vlans USERS vlan-id 20
"""
BUILT = """system {
    host-name sw-office-01;
    root-authentication { encrypted-password "$6$xyz$two"; }
}
interfaces {
    ge-0/0/1 { description "to printer"; unit 0 { family ethernet-switching { vlan { members [ USERS VOICE ]; } } } }
}
vlans { USERS { vlan-id 20; } VOICE { vlan-id 30; } }
"""


# ----------------------------------------------------------------- compare
def test_compare_sections_and_commands():
    r = compare.compare(LIVE, BUILT)
    assert not r["identical"] and r["only_a"] == 4 and r["only_b"] == 3
    names = [s["name"] for s in r["sections"]]
    assert names == ["interfaces ge-0/0/1", "interfaces ge-0/0/1 unit 0", "interfaces ge-0/0/2",
                     "interfaces ge-0/0/2 unit 0", "system domain-name", "vlans VOICE"]
    assert "version" not in json.dumps(r)                     # release line ignored
    assert r["a_to_b"] == [
        "delete interfaces ge-0/0/2",                         # the whole port goes, in one line
        "delete system domain-name",
        'set interfaces ge-0/0/1 description "to printer"',  # a changed value is just set again
        "set interfaces ge-0/0/1 unit 0 family ethernet-switching vlan members VOICE",
        "set vlans VOICE vlan-id 30"]
    assert "delete vlans VOICE" in r["b_to_a"]
    assert "delete interfaces ge-0/0/1 unit 0 family ethernet-switching vlan members VOICE" in r["b_to_a"]
    # Secrets differ every time Junos saves them: ignored unless asked.
    assert not any("root-authentication" in s["name"] for s in r["sections"])
    strict = compare.compare(LIVE, BUILT, ignore_secrets=False)
    assert any(s["name"] == "system root-authentication" for s in strict["sections"])
    assert compare.compare(LIVE, LIVE.replace("set ", "set ", 1))["identical"]
    assert "error" in compare.compare("", "hello")


def test_compare_keeps_context_short():
    many = "".join(f"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.{i}/32\n" for i in range(30))
    r = compare.compare(many, many + "set interfaces ge-0/0/1 unit 0 family inet address 10.9.9.9/32\n")
    (sec,) = r["sections"]
    assert sec["added"] == 1 and len(sec["lines"]) <= 9 and sec["lines"][0]["op"] == "…"
    assert r["a_to_b"] == ["set interfaces ge-0/0/1 unit 0 family inet address 10.9.9.9/32"]


# ------------------------------------------------------------ config backups
def _hdr(c):
    return {"X-CSRF-Token": token(c)}


def test_backups_store_list_export_and_roles(app, admin):
    h = _hdr(admin)
    r = admin.post("/backups", json={"items": [{"name": "x", "text": LIVE}, {"name": "junk", "text": "hello"}],
                                     "source": "map"}, headers=h)
    assert r.status_code == 200
    saved = r.json["saved"]
    assert saved[0]["host"] == "sw-office-01" and saved[0]["unchanged"] is False and "error" in saved[1]
    again = admin.post("/backups", json={"items": [{"text": LIVE}], "source": "map"}, headers=h).json["saved"][0]
    assert again["unchanged"] is True and again["id"] == saved[0]["id"]
    assert admin.post("/backups", json={"items": [{"text": LIVE}], "source": "ssh"}, headers=h).status_code == 400
    # Upload: files and a zip.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("core1.conf", "set system host-name core1\nset vlans A vlan-id 5\n")
        zf.writestr("readme.md", "nothing here")
    data = {"file": [(io.BytesIO(buf.getvalue()), "configs.zip"), (io.BytesIO(BUILT.encode()), "built.conf")]}
    up = admin.post("/backups/upload", data=data, headers=h, content_type="multipart/form-data")
    assert up.status_code == 200 and [s.get("host") for s in up.json["saved"] if "id" in s] == ["core1", "sw-office-01"]
    rows = admin.get("/backups").json["backups"]
    assert len(rows) == 3 and {r["source"] for r in rows} == {"map", "upload"}
    one = admin.get(f"/backups/{saved[0]['id']}").json
    assert one["text"] == LIVE
    dl = admin.get(f"/backups/{saved[0]['id']}?download=1")
    assert dl.headers["Content-Disposition"].startswith("attachment; filename=sw-office-01-") and dl.data == LIVE.encode()
    z = zipfile.ZipFile(io.BytesIO(admin.get("/backups/export").data))
    assert sorted(z.namelist()) == ["core1.conf", "sw-office-01.conf"]
    assert z.read("sw-office-01.conf").decode() == BUILT       # the newest of that switch
    # Compare route.
    cr = admin.post("/compare", json={"a": {"text": one["text"]}, "b": {"text": BUILT}}, headers=h)
    assert cr.status_code == 200 and cr.json["only_b"] == 3
    # Another client sees none of it; a viewer can read but not add or delete.
    admin.post("/clients", data={"csrf_token": csrf(admin, "/clients"), "name": "Acme"})
    add_user(admin)
    admin.post("/clients/1", data={"csrf_token": csrf(admin, "/clients"), "action": "member_add", "username": "bob",
                                   "role": "viewer"})
    bob = app.test_client()
    login(bob, "bob", "bob-password-1")
    bh = _hdr(bob)
    assert len(bob.get("/backups").json["backups"]) == 3
    assert bob.post("/backups", json={"items": [{"text": LIVE}], "source": "map"}, headers=bh).status_code == 403
    assert bob.post(f"/backups/{saved[0]['id']}/delete", json={}, headers=bh).status_code == 403
    admin.post("/clients/select", data={"csrf_token": csrf(admin), "client_id": "2"})
    assert admin.get("/backups").json["backups"] == []
    assert admin.get(f"/backups/{saved[0]['id']}").status_code == 404
    admin.post("/clients/select", data={"csrf_token": csrf(admin), "client_id": "1"})
    assert admin.post(f"/backups/{saved[0]['id']}/delete", json={}, headers=h).status_code == 200
    assert len(admin.get("/backups").json["backups"]) == 2


def test_backups_page_parts(app, admin):
    page = admin.get("/build/juniper").get_data(as_text=True)
    assert 'data-tab="Backups &amp; compare"' in page or 'data-tab="Backups & compare"' in page
    assert 'id="cmp-go"' in page and 'id="bk-upload-btn"' in page


# ------------------------------------------------------------- client backup
def test_client_backup_and_restore(app, admin, tmp_path):
    h = _hdr(admin)
    admin.post("/projects", json={"name": "Floor 2", "data": {"system": {"hostname": "f2"}}}, headers=h)
    admin.post("/maps", json={"name": "HQ", "data": {"items": [{"name": "sw1", "text": LIVE}], "pos": {}}}, headers=h)
    admin.post("/backups", json={"items": [{"text": LIVE}], "source": "map"}, headers=h)
    tok = csrf(admin, "/clients/1")
    admin.post("/clients/1", data={"csrf_token": tok, "action": "ssh", "networks": "10.40.10.0/24", "ssh_user": "ro"})
    admin.post("/clients/1", data={"csrf_token": tok, "action": "key_generate"})
    page = admin.get("/clients/1").get_data(as_text=True)
    assert 'id="backup"' in page and "Download a backup" in page

    plain = admin.get("/clients/1/export")
    assert plain.headers["Content-Disposition"].startswith("attachment; filename=Default-backup-")
    data = json.loads(plain.data)
    assert data["format"] == "switchbuilder-client-backup" and "secrets" not in data
    assert data["projects"][0]["data"]["system"]["hostname"] == "f2" and data["maps"][0]["name"] == "HQ"
    assert data["client"]["ssh_networks"] == "10.40.10.0/24" and len(data["config_backups"]) == 1
    assert "PRIVATE" not in plain.get_data(as_text=True)
    assert "config_backups" not in json.loads(admin.get("/clients/1/export?configs=0").data)
    full = json.loads(admin.get("/clients/1/export?secrets=1").data)
    assert full["secrets"]["ssh_key"].startswith("gAAAA")

    # Restore as a new client (server admin), secrets work on the same server.
    resp = admin.post("/clients/restore", data={"csrf_token": tok, "name": "Copy",
                                                "file": (io.BytesIO(json.dumps(full).encode()), "b.json")},
                      content_type="multipart/form-data")
    assert resp.status_code == 302 and resp.location.endswith("/clients/2#backup")
    db = sqlite3.connect(tmp_path / "users.db")
    assert db.execute("SELECT ssh_networks, ssh_user, ssh_key IS NOT NULL FROM clients WHERE name = 'Copy'").fetchone() \
        == ("10.40.10.0/24", "ro", 1)
    assert db.execute("SELECT COUNT(*) FROM projects WHERE client_id = 2").fetchone()[0] == 1
    assert db.execute("SELECT COUNT(*) FROM config_backups WHERE client_id = 2").fetchone()[0] == 1
    # The same name again is refused.
    admin.post("/clients/restore", data={"csrf_token": tok, "file": (io.BytesIO(json.dumps(full).encode()), "b.json")},
               content_type="multipart/form-data")
    assert db.execute("SELECT COUNT(*) FROM clients").fetchone()[0] == 2

    # Load into an existing client: skip or replace same names; settings only when asked; bad secrets refused.
    data["projects"][0]["data"] = {"system": {"hostname": "changed"}}
    data["secrets"] = {"ssh_key": "gAAAAnot-from-here"}
    def load(**form):
        return admin.post("/clients/2/import", data={"csrf_token": tok, **form,
                                                     "file": (io.BytesIO(json.dumps(data).encode()), "b.json")},
                          content_type="multipart/form-data")
    load(existing="skip")
    db = sqlite3.connect(tmp_path / "users.db")
    assert json.loads(db.execute("SELECT data FROM projects WHERE client_id = 2").fetchone()[0])["system"]["hostname"] == "f2"
    assert db.execute("SELECT COUNT(*) FROM config_backups WHERE client_id = 2").fetchone()[0] == 1  # no duplicate
    load(existing="replace", settings="1")
    db = sqlite3.connect(tmp_path / "users.db")
    assert json.loads(db.execute("SELECT data FROM projects WHERE client_id = 2").fetchone()[0])["system"]["hostname"] \
        == "changed"
    assert db.execute("SELECT ssh_key FROM clients WHERE id = 2").fetchone()[0] == full["secrets"]["ssh_key"]
    assert "another server" in admin.get("/clients/2").get_data(as_text=True)
    # Not a backup file.
    load_bad = admin.post("/clients/2/import", data={"csrf_token": tok, "file": (io.BytesIO(b"{}"), "x.json")},
                          content_type="multipart/form-data")
    assert load_bad.status_code == 302
    # Members can't export or import.
    add_user(admin)
    admin.post("/clients/1", data={"csrf_token": tok, "action": "member_add", "username": "bob", "role": "editor"})
    bob = app.test_client()
    login(bob, "bob", "bob-password-1")
    assert bob.get("/clients/1/export").status_code == 403
    assert bob.post("/clients/1/import", data={"csrf_token": csrf(bob)}).status_code == 403
    assert bob.post("/clients/restore", data={"csrf_token": csrf(bob)}).status_code in (302, 403)
    # Deleting a client removes its config backups too.
    admin.post("/clients/2", data={"csrf_token": tok, "action": "delete", "confirm": "Copy"})
    db = sqlite3.connect(tmp_path / "users.db")
    assert db.execute("SELECT COUNT(*) FROM config_backups WHERE client_id = 2").fetchone()[0] == 0


def test_host_of_mikrotik_export():
    """RouterOS /export puts the section and the set line on two lines."""
    from exbuilder.web.backups import host_of
    assert host_of("# by RouterOS 7.16\n/system identity\nset name=crs-office-01\n") == "crs-office-01"
    assert host_of("/system identity set name=r1") == "r1"
