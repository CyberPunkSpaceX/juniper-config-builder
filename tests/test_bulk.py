"""Bulk builds: one template project and a CSV of switches."""

import copy
import io
import json
import zipfile
from pathlib import Path

import pytest

from switchbuilder import bulk

EXAMPLES = Path(__file__).parent.parent / "src" / "switchbuilder" / "vendor_examples"
ARISTA = json.loads((EXAMPLES / "arista-office.json").read_text())


def _tpl():
    t = copy.deepcopy(ARISTA)
    t["vlans"][0]["irb"] = "10.{{site}}.10.2/24"
    t["system"]["banner"] = "Site {{ site }} - authorized access only."
    return t


def test_builds_one_config_per_line():
    csv = ("hostname,ip,gateway,site,location\n"
           "ar-a,192.168.100.31/24,192.168.100.1,11,Floor 1\n"
           "ar-b;wrong\n".replace("ar-b;wrong", "ar-b,192.168.100.32/24,192.168.100.1,12,Floor 2"))
    r = bulk.run(_tpl(), csv)
    assert r["summary"] == {"total": 2, "ok": 2, "failed": 0}
    a, b = r["switches"]
    assert a["ok"] and "hostname ar-a" in a["config"] and "10.11.10.2/24" in a["config"]
    assert "10.12.10.2/24" in b["config"] and "Site 12 - authorized" in b["config"]
    assert a["project"]["snmp"]["location"] == "Floor 1" and a["project"]["name"] == "ar-a"
    assert r["columns"] == {"hostname": "field", "ip": "field", "gateway": "field", "site": "placeholder",
                            "location": "field"}


def test_semicolons_paths_and_problems():
    csv = ("# comment line\n"
           "Hostname;Mgmt IP;vlans.USERS.irb;system.banner;color\n"
           "sw1;192.168.100.31/24;10.20.0.1/24;Hello;red\n"
           "sw1;192.168.100.31/24;;;\n"
           ";192.168.100.33/24;;;\n")
    r = bulk.run(_tpl(), csv)
    s1, dup, nohost = r["switches"]
    assert r["columns"]["color"] == "unused" and r["columns"]["vlans.USERS.irb"] == "path"
    assert s1["project"]["vlans"][1]["irb"] == "10.20.0.1/24"
    assert s1["project"]["system"]["banner"] == "Hello"
    # {{site}} has no column: every line reports it.
    assert any("{{site}}" in e for e in s1["errors"]) and not s1["ok"] and not s1["config"]
    assert any("also on line 3" in e for e in dup["errors"])
    assert any("Management IP 192.168.100.31 is also on line 3" in e for e in dup["errors"])
    assert any("No hostname" in e for e in nohost["errors"])


def test_bad_spreadsheets():
    with pytest.raises(bulk.BulkError, match="hostname column"):
        bulk.run(ARISTA, "ip\n10.0.0.1/24\n")
    with pytest.raises(bulk.BulkError, match="header line and at least one"):
        bulk.run(ARISTA, "hostname\n")
    with pytest.raises(bulk.BulkError, match="different name"):
        bulk.run(ARISTA, "hostname,hostname\na,b\n")
    with pytest.raises(bulk.BulkError, match="At most"):
        bulk.run(ARISTA, "hostname\n" + "".join(f"s{i}\n" for i in range(bulk.MAX_ROWS + 1)))
    r = bulk.run(ARISTA, "hostname,vlans.NOPE.irb,switch\nsw1,1.2.3.4/24,x\n")
    assert any("no NOPE" in e for e in r["switches"][0]["errors"])


def test_template_ip_left_on_every_line_is_caught():
    r = bulk.run(_tpl(), "hostname,site\nar-a,11\nar-b,12\n")
    assert r["switches"][0]["ok"] and not r["switches"][1]["ok"]
    assert "also on line 2" in r["switches"][1]["errors"][0]


def test_builder_errors_are_reported():
    r = bulk.run(ARISTA, "hostname,mgmt_address\nbad_name!,10.0.0.5/24\n")
    assert not r["switches"][0]["ok"] and r["switches"][0]["errors"]


def test_csv_template_and_zip():
    head = bulk.csv_template(_tpl()).splitlines()[0]
    assert head == "hostname,mgmt_address,mgmt_gateway,model,serial,location,site"
    r = bulk.run(_tpl(), "hostname,site,ip\nar-a,11,10.1.1.1/24\nar-b,,10.1.1.2/24\n")
    zf = zipfile.ZipFile(io.BytesIO(bulk.to_zip(r)))
    names = set(zf.namelist())
    assert {"configs/ar-a.cfg", "projects/ar-a.json", "projects/ar-b.json", "summary.csv"} <= names
    assert "configs/ar-b.cfg" not in names
    assert any("{{site}}" in e for e in r["switches"][1]["errors"])
    assert "failed" in zf.read("summary.csv").decode()
    juniper = {"vendor": "juniper", "system": {"hostname": "x"}, "access": {"root_password": "Secret-pass-1"}}
    zj = zipfile.ZipFile(io.BytesIO(bulk.to_zip(bulk.run(juniper, "hostname\nex-1\n"))))
    assert {"configs/ex-1.set", "configs/ex-1.conf"} <= set(zj.namelist())


# ----------------------------------------------------------------- web
flask = pytest.importorskip("flask")
from test_auth import ADMIN, add_user, app, admin, csrf, login  # noqa: F401,E402
from test_builder_web import pick_space, token  # noqa: E402
from test_clients import _bob  # noqa: E402


def _post(client, url, body):
    return client.post(url, json=body, headers={"X-CSRF-Token": token(client)})


def test_web_bulk_build_and_save(app, admin):
    pick_space(admin, "lab")
    assert "Toolkit" in admin.get("/tools/").get_data(as_text=True)
    assert "Bulk build" in admin.get("/tools/bulk").get_data(as_text=True)
    pid = _post(admin, "/projects", {"name": "Template", "data": _tpl()}).json["id"]
    csv = "hostname,site,ip\nar-a,11,10.1.1.1/24\nar-b,12,10.1.1.2/24\n"
    r = _post(admin, "/tools/bulk/run", {"project_id": pid, "csv": csv})
    assert r.status_code == 200 and r.json["summary"]["ok"] == 2
    z = _post(admin, "/tools/bulk/zip", {"project_id": pid, "csv": csv})
    assert z.mimetype == "application/zip" and "configs/ar-b.cfg" in zipfile.ZipFile(io.BytesIO(z.data)).namelist()
    t = _post(admin, "/tools/bulk/csv-template", {"project_id": pid})
    assert t.get_data(as_text=True).startswith("hostname,") and ",site" in t.get_data(as_text=True)
    s = _post(admin, "/tools/bulk/save", {"project_id": pid, "csv": csv})
    assert s.json["saved"] == 2 and s.json["space"] == "lab"
    names = {p["name"] for p in admin.get("/projects").json["projects"]}
    assert {"ar-a", "ar-b", "Template"} <= names
    again = _post(admin, "/tools/bulk/save", {"project_id": pid, "csv": csv})
    assert again.status_code == 409 and set(again.json["exists"]) == {"ar-a", "ar-b"}
    assert _post(admin, "/tools/bulk/save", {"project_id": pid, "csv": csv, "overwrite": True}).json["saved"] == 2
    # A project of the other space is not reachable, and JSON templates work too.
    pick_space(admin, "production")
    assert _post(admin, "/tools/bulk/run", {"project_id": pid, "csv": csv}).status_code == 400
    assert _post(admin, "/tools/bulk/run", {"template": json.dumps(_tpl()), "csv": csv}).json["summary"]["ok"] == 2
    assert "error" in _post(admin, "/tools/bulk/run", {"template": "nope", "csv": csv}).json


def test_web_bulk_save_needs_editor(app, admin):
    bob = _bob(app, admin, role="viewer")
    pick_space(bob, "lab")
    r = _post(bob, "/tools/bulk/save", {"template": _tpl(), "csv": "hostname,site\nar-a,11\n"})
    assert r.status_code == 403
