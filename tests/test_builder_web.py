import re

import pytest

flask = pytest.importorskip("flask")

from test_auth import ADMIN, add_user, app, admin, basic, csrf, login  # noqa: F401,E402


def token(client):
    page = client.get("/build/juniper").get_data(as_text=True)
    return re.search(r'id="csrf" value="([^"]+)"', page).group(1)


def test_page_has_models_and_timezones(admin):
    page = admin.get("/build/juniper").get_data(as_text=True)
    assert "EX4400-48P" in page and "America/Edmonton" in page and "Multi-Vendor Switch Config Builder" in page


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


def test_projects_save_open_delete(app, admin):
    t = token(admin)
    hdr = {"X-CSRF-Token": t}
    resp = admin.post("/projects", json={"name": "Floor 2", "data": {"system": {"hostname": "f2"}}}, headers=hdr)
    pid = resp.json["id"]
    assert resp.json["client"] == "Default"
    admin.post("/projects", json={"name": "Floor 2", "data": {"system": {"hostname": "f2b"}}}, headers=hdr)
    listing = admin.get("/projects").json["projects"]
    assert [p["name"] for p in listing] == ["Floor 2"] and listing[0]["updated_by"] == "admin"
    assert admin.get(f"/projects/{pid}").json["data"]["system"]["hostname"] == "f2b"
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


def test_fabric_endpoints(admin):
    from exbuilder.fabric import TEMPLATES
    hdr = {"X-CSRF-Token": token(admin)}
    body = {"fabric": TEMPLATES["campus-erb"]["fabric"], "base": {}}
    resp = admin.post("/fabric", json=body, headers=hdr)
    assert resp.status_code == 200 and len(resp.json["switches"]) == 6
    bad = admin.post("/fabric", json={"fabric": {"vlans": []}, "base": {}}, headers=hdr)
    assert bad.status_code == 400 and "VLAN" in bad.json["error"]
    z = admin.post("/fabric/zip", json=body, headers=hdr)
    assert z.status_code == 200 and z.mimetype == "application/zip" and z.data[:2] == b"PK"
    assert admin.post("/fabric", json=body).status_code == 400  # CSRF


def test_import_and_excel_endpoints(admin):
    import io
    from pathlib import Path
    hdr = {"X-CSRF-Token": token(admin)}
    text = (Path(__file__).parent / "data" / "legacy-ex2300.conf").read_text()
    resp = admin.post("/import/config", json={"text": text}, headers=hdr)
    assert resp.status_code == 200 and resp.json["model"].startswith("EX2300")
    assert resp.json["model_how"] == "port names"
    resp = admin.post("/import/config", json={"text": "Model: ex4400-48p\n" + text}, headers=hdr)
    assert resp.json["model"] == "EX4400-48P" and resp.json["model_how"] == "show version"
    assert resp.json["detected"][0]["fpc"] == 0
    resp = admin.post("/import/config", json={"text": text, "model": "EX2300-24T"}, headers=hdr)
    assert resp.json["model"] == "EX2300-24T" and resp.json["model_how"] == "chosen"
    assert resp.json["recommendations"] and resp.json["project"]["system"]["hostname"] == "sw-legacy-01"
    assert admin.post("/import/config", json={"text": "nothing"}, headers=hdr).status_code == 400
    tpl = admin.get("/excel/template")
    assert tpl.status_code == 200 and tpl.data[:2] == b"PK"
    exp = admin.post("/excel/export", json={"system": {"hostname": "sw9"}}, headers=hdr)
    assert exp.status_code == 200 and "sw9.xlsx" in exp.headers["Content-Disposition"]
    up = admin.post("/import/excel", data={"file": (io.BytesIO(exp.data), "sw9.xlsx")}, headers=hdr,
                    content_type="multipart/form-data")
    assert up.status_code == 200 and up.json["project"]["system"]["hostname"] == "sw9"
    bad = admin.post("/import/excel", data={"file": (io.BytesIO(b"nope"), "x.xlsx")}, headers=hdr,
                     content_type="multipart/form-data")
    assert bad.status_code == 400


def test_network_map_endpoints(admin):
    import io
    import zipfile
    hdr = {"X-CSRF-Token": token(admin)}
    ex = admin.get("/map/example").json["files"]
    assert [f["name"] for f in ex][0] == "core-sw1" and len(ex) == 3
    resp = admin.post("/map", json={"switches": ex}, headers=hdr)
    assert resp.status_code == 200 and len(resp.json["switches"]) == 3 and len(resp.json["links"]) == 3
    assert admin.post("/map", json={"switches": []}, headers=hdr).status_code == 400
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for f in ex:
            z.writestr(f"configs/{f['name']}.conf", f["text"])
        z.writestr("readme.md", "not a config")
    up = admin.post("/map/unzip", data={"file": (io.BytesIO(buf.getvalue()), "c.zip")}, headers=hdr,
                    content_type="multipart/form-data")
    assert up.status_code == 200 and sorted(f["name"] for f in up.json["files"]) == ["acc-sw1", "acc-sw2", "core-sw1"]
    bad = admin.post("/map/unzip", data={"file": (io.BytesIO(b"nope"), "c.zip")}, headers=hdr,
                     content_type="multipart/form-data")
    assert bad.status_code == 400


def test_vendor_screen_after_login(admin):
    page = admin.get("/").get_data(as_text=True)
    assert "Which switches are you configuring?" in page
    for name in ("Juniper", "Arista", "Cisco", "Brocade / Ruckus"):
        assert name in page
    assert 'href="/build/juniper"' in page and "Coming soon" in page


def test_builder_per_vendor(admin):
    page = admin.get("/build/juniper").get_data(as_text=True)
    assert "Juniper builder" in page and '"vlan_translation"' in page
    assert "Last used" in admin.get("/").get_data(as_text=True)
    resp = admin.get("/build/cisco")
    assert resp.status_code == 302 and resp.location.endswith("/")
    assert "not ready yet" in admin.get("/").get_data(as_text=True)
    assert admin.get("/build/nokia").status_code == 404
    assert admin.get("/build").location.endswith("/build/juniper")


def test_vendor_pages_need_login(app):
    c = app.test_client()
    assert "/login" in c.get("/build/juniper").location


def test_arista_builder_page_and_generate(admin):
    page = admin.get("/build/arista").get_data(as_text=True)
    assert "Arista builder" in page and "720XP-48Y6" in page and '"name": "EX2300-24T"' not in page
    assert '"office"' in page  # the Arista example is offered
    resp = admin.post("/generate", json={"vendor": "arista", "system": {"hostname": "ar9"}},
                      headers={"X-CSRF-Token": token(admin)})
    assert resp.status_code == 200 and "hostname ar9" in resp.json["set"]
