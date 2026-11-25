"""NetBox sync against a small fake NetBox."""

import copy
import json
import re
from pathlib import Path

import pytest

from exbuilder import netbox

ARISTA = json.loads((Path(__file__).parent.parent / "src" / "exbuilder" / "vendor_examples" / "arista-office.json").read_text())


class FakeNetbox:
    def __init__(self):
        juniper = {"id": 1, "name": "Juniper Networks", "slug": "juniper"}
        arista = {"id": 2, "name": "Arista", "slug": "arista"}
        self.db = {
            "sites": [{"id": 7, "name": "Head Office"}],
            "device-roles": [{"id": 3, "name": "Access switch"}],
            "device-types": [{"id": 11, "model": "EX4100-48P", "part_number": "", "manufacturer": juniper},
                             {"id": 12, "model": "DCS-7050SX3-48YC8", "part_number": "", "manufacturer": arista},
                             {"id": 13, "model": "720XP-48Y6", "part_number": "", "manufacturer": arista}],
            "devices": [
                {"id": 21, "name": "ex-idf1", "serial": "XX1", "site": {"id": 7, "name": "Head Office"},
                 "device_type": {"model": "EX4100-48P", "manufacturer": juniper}, "primary_ip4": {"address": "10.9.0.11/24"}},
                {"id": 22, "name": "pdu-1", "site": {"id": 7}, "device_type": {"model": "AP7900", "manufacturer": {"name": "APC"}}},
            ],
            "vlans": [{"id": 31, "vid": 10, "name": "MGMT", "site": {"id": 7}}, {"id": 32, "vid": 20, "name": "Users LAN", "site": {"id": 7}}],
            "ip-addresses": [{"id": 41, "address": "10.9.20.1/24", "assigned_object_id": 51,
                              "assigned_object": {"name": "irb.20", "device": {"name": "ex-idf1"}}, "family": {"value": 4}}],
            "interfaces": [{"id": 51, "name": "irb.20", "device": {"id": 21}}, {"id": 52, "name": "Management1", "device": {"id": 23}}],
        }
        self.writes = []

    def call(self, method, path, data=None, params=None):
        params = params or {}
        if path == "/api/status/":
            return {"netbox-version": "4.7.5"}
        m = re.match(r"^/api/\w+/([\w-]+)/(?:(\d+)/)?$", path)
        kind, oid = m.group(1), m.group(2)
        rows = self.db[kind]
        if method == "GET" and oid:
            return next(r for r in rows if r["id"] == int(oid))
        if method == "GET":
            out = rows
            for k, v in params.items():
                if k in ("limit", "offset"):
                    continue
                if k in ("site_id", "available_at_site"):
                    out = [r for r in out if (r.get("site") or {}).get("id") == int(v)]
                elif k == "device_id":
                    out = [r for r in out if (r.get("device") or {}).get("id") == int(v)
                           or (kind == "ip-addresses" and any(i["id"] == r.get("assigned_object_id") and i["device"]["id"] == int(v)
                                                              for i in self.db["interfaces"]))]
                elif k == "address":
                    out = [r for r in out if r["address"].split("/")[0] == v]
                else:
                    out = [r for r in out if str(r.get(k)) == str(v)]
            return {"results": out, "next": None}
        self.writes.append((method, path, data))
        if method == "POST":
            row = {"id": 100 + len(self.writes), **data}
            rows.append(row)
            return row
        return {}


@pytest.fixture
def fake(monkeypatch):
    f = FakeNetbox()
    monkeypatch.setattr(netbox.Netbox, "call", lambda self, *a, **k: f.call(*a, **k))
    return f


def _defaults(vendor):
    from exbuilder.web import _defaults as d
    return d(vendor)


def test_vendor_and_model_mapping():
    assert netbox.vendor_for("Juniper Networks", "EX4100-48P") == "juniper"
    assert netbox.vendor_for("Cisco", "N9K-C93180YC-FX") == "nexus"
    assert netbox.vendor_for("Cisco", "C9300-48P") == "cisco"
    assert netbox.vendor_for("HPE Aruba", "6300M") == "aruba"
    assert netbox.vendor_for("HPE", "2930F-48G") == "procurve"
    assert netbox.vendor_for("APC", "AP7900") is None
    assert netbox.match_model("juniper", "EX4100-48P") == "EX4100-48P"
    assert netbox.match_model("arista", "DCS-720XP-48Y6") == "720XP-48Y6"
    assert netbox.match_model("juniper", "toaster") == ""
    assert netbox.auth_header("nbt_abc.def") == "Bearer nbt_abc.def" and netbox.auth_header("abc") == "Token abc"


def test_url_must_be_inside_allowed_networks():
    with pytest.raises(netbox.NetboxError, match="outside the networks"):
        netbox.check_url("http://8.8.8.8")
    assert netbox.check_url("http://10.1.2.3:8000/api") == "http://10.1.2.3:8000"


def test_pull(fake):
    nb = netbox.Netbox("http://10.1.2.3", "tok")
    res = netbox.pull(nb, 7, {}, _defaults)
    ex, pdu = res["devices"]
    assert ex["vendor"] == "juniper" and ex["model"] == "EX4100-48P" and ex["mgmt_address"] == "10.9.0.11/24"
    p = ex["project"]
    assert p["system"]["hostname"] == "ex-idf1" and p["switch"]["members"][0]["serial"] == "XX1"
    assert p["snmp"]["location"] == "Head Office"
    assert {(v["name"], v["id"], v.get("irb")) for v in p["vlans"]} == {("MGMT", "10", None), ("Users_LAN", "20", "10.9.20.1/24")}
    assert "project" not in pdu and "not a switch brand" in pdu["notes"][0]
    # A template of the same brand is the starting point.
    tpl = _defaults("juniper")
    tpl["ports"] = [{"name": "DESKS", "ports": "ge-0/0/0-47", "mode": "access", "vlan": "MGMT"}]
    tpl["vlans"] = [{"name": "MGMT", "id": "10"}]
    res = netbox.pull(nb, 7, {"juniper": tpl}, _defaults)
    assert res["devices"][0]["template"] and res["devices"][0]["project"]["ports"][0]["name"] == "DESKS"


def test_push_plan_and_apply(fake):
    nb = netbox.Netbox("http://10.1.2.3", "tok")
    new = copy.deepcopy(ARISTA)
    new["system"]["hostname"] = "ar-new"
    new["switch"]["members"][0]["serial"] = "SN9"
    old = copy.deepcopy(_defaults("juniper"))
    old["system"].update(hostname="ex-idf1", mgmt_address="10.9.0.11/24")
    old["switch"]["members"][0].update(model="EX4100-48P", serial="XX2")
    old["vlans"] = [{"name": "USERS", "id": "20", "irb": "10.9.20.1/24"}]
    projects = [{"name": "ar-new", "data": new}, {"name": "ex-idf1", "data": old}]
    plan = netbox.plan_push(nb, 7, projects, None)
    whats = [s["what"] for s in plan["steps"]]
    assert any("ar-new: not in NetBox. Pick a device role" in n for n in plan["notes"])
    assert "ex-idf1 serial XX1 → XX2" in whats
    assert "VLAN 30 VOICE" in whats and "VLAN 10 MGMT" not in whats
    assert any(w.startswith("192.168.100.21/24 (ar-new mgmt") for w in whats)
    assert not any(w.startswith("10.9.20.1/24") for w in whats)   # already there
    plan = netbox.plan_push(nb, 7, projects, 3)
    dev = next(s for s in plan["steps"] if s["kind"] == "device" and s["action"] == "create")
    assert dev["call"][2] == {"name": "ar-new", "device_type": 13, "role": 3, "site": 7, "status": "planned", "serial": "SN9"}
    results = netbox.apply(nb, plan["steps"])
    assert all(r["ok"] for r in results) and len(fake.writes) == len(plan["steps"])
    assert ("PATCH", "/api/dcim/devices/21/", {"serial": "XX2"}) in fake.writes


# ----------------------------------------------------------------- web
flask = pytest.importorskip("flask")
from test_auth import ADMIN, add_user, app, admin, csrf, login  # noqa: F401,E402
from test_builder_web import pick_space, token  # noqa: E402
from test_clients import _bob  # noqa: E402


def test_web_netbox(app, admin, fake):
    pick_space(admin, "lab")
    hdr = {"X-CSRF-Token": token(admin)}
    page = admin.get("/tools/netbox/").get_data(as_text=True)
    assert "Not set up yet" in page
    assert admin.get("/tools/netbox/sites").status_code == 409
    assert admin.post("/tools/netbox/settings", json={"url": "http://8.8.8.8", "token": "x"}, headers=hdr).status_code == 400
    assert admin.post("/tools/netbox/settings", json={"url": "http://10.1.2.3"}, headers=hdr).status_code == 400
    r = admin.post("/tools/netbox/settings", json={"url": "http://10.1.2.3:8000", "token": "nbt_secret.token"}, headers=hdr)
    assert r.json["configured"]
    with app.app_context():
        from exbuilder.web import auth
        stored = auth.db().execute("SELECT token FROM netbox_settings").fetchone()[0]
    assert "nbt_secret" not in stored
    page = admin.get("/tools/netbox/").get_data(as_text=True)
    assert "nbt_secret" not in page and "Set up: http://10.1.2.3:8000" in page
    s = admin.get("/tools/netbox/sites").json
    assert s["sites"] == [{"id": 7, "name": "Head Office"}] and s["version"] == "4.7.5"
    pulled = admin.post("/tools/netbox/pull", json={"site_id": 7}, headers=hdr).json
    assert len(pulled["devices"]) == 2
    saved = admin.post("/tools/netbox/pull/save", json={"site_id": 7}, headers=hdr).json
    assert saved == {"saved": 1, "client": "Default", "space": "lab"}
    projects = admin.get("/projects").json["projects"]
    assert [p["name"] for p in projects] == ["ex-idf1"]
    assert admin.post("/tools/netbox/pull/save", json={"site_id": 7}, headers=hdr).status_code == 409
    pid = projects[0]["id"]
    plan = admin.post("/tools/netbox/push/plan", json={"site_id": 7, "project_ids": [pid]}, headers=hdr).json
    assert "call" not in plan["steps"][0] if plan["steps"] else True
    # Applying needs the plan's own steps: anything else is refused.
    bad = admin.post("/tools/netbox/push/apply", json={"site_id": 7, "project_ids": [pid], "steps": ["DELETE everything"]},
                     headers=hdr)
    assert bad.status_code == 409 and not fake.writes
    # Viewers can look but not push or change settings.
    bob = _bob(app, admin, role="editor")
    pick_space(bob, "lab")
    bh = {"X-CSRF-Token": token(bob)}
    assert bob.post("/tools/netbox/push/plan", json={"site_id": 7, "project_ids": [pid]}, headers=bh).status_code == 403
    assert bob.post("/tools/netbox/settings", json={"url": ""}, headers=bh).status_code == 403
    assert bob.post("/tools/netbox/pull", json={"site_id": 7}, headers=bh).status_code == 200
    assert admin.post("/tools/netbox/settings", json={"url": ""}, headers=hdr).json["configured"] is False
