"""Calculators: subnet, split, VLAN plan, PoE budget."""

import json
from pathlib import Path

import pytest

from switchbuilder import calc


def test_subnet():
    d = calc.subnet("10.20.30.40/26")
    assert (d["network"], d["mask"], d["wildcard"], d["first"], d["last"], d["broadcast"], d["usable"]) == \
        ("10.20.30.0/26", "255.255.255.192", "0.0.0.63", "10.20.30.1", "10.20.30.62", "10.20.30.63", 62)
    assert calc.subnet("10.0.0.1 255.255.255.0")["network"] == "10.0.0.0/24"
    assert calc.subnet("10.0.0.0/31")["usable"] == 2
    assert calc.subnet("2001:db8::1/64")["version"] == 6
    with pytest.raises(calc.CalcError):
        calc.subnet("nope")


def test_split():
    assert [s["network"] for s in calc.split("10.0.0.0/22", count=3)["subnets"]] == \
        ["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
    assert calc.split("10.0.0.0/24", hosts=50)["prefix"] == 26
    big = calc.split("10.0.0.0/8", prefix=24)
    assert big["count"] == 65536 and big["shown"] == calc.MAX_SPLIT
    with pytest.raises(calc.CalcError):
        calc.split("10.0.0.0/24", prefix=16)


def test_vlan_plan():
    rows = [{"name": "MGMT", "id": "10", "hosts": "30"}, {"name": "USERS", "id": "20", "hosts": "400"},
            {"name": "VOICE", "id": "30", "hosts": "200"}]
    p = calc.vlan_plan("10.20.0.0/16", rows)
    by = {v["name"]: v for v in p["vlans"]}
    assert by["USERS"]["subnet"] == "10.20.0.0/23" and by["USERS"]["irb"] == "10.20.0.1/23"
    assert by["VOICE"]["subnet"] == "10.20.2.0/24" and by["MGMT"]["subnet"] == "10.20.3.0/26"
    assert [v["name"] for v in p["vlans"]] == ["MGMT", "USERS", "VOICE"] and not p["errors"]
    last = calc.vlan_plan("10.20.0.0/16", rows[:1], gateway="last")
    assert last["vlans"][0]["gateway"] == "10.20.0.62"
    grown = calc.vlan_plan("10.20.0.0/16", [{"name": "A", "id": "5", "hosts": "200"}], spare=50)
    assert grown["vlans"][0]["subnet"].endswith("/23")
    tight = calc.vlan_plan("10.0.0.0/24", rows)
    assert any("does not fit" in e for e in tight["errors"])
    bad = calc.vlan_plan("10.0.0.0/16", [{"name": "1x", "id": "10", "hosts": "5"}, {"name": "B", "id": "9999", "hosts": "5"},
                                         {"name": "C", "id": "10", "hosts": "0"}])
    assert len(bad["errors"]) == 3


def test_poe():
    d = calc.poe_budget("370", [{"device": "Phone", "count": "24", "watts": "6.5", "class": "2"},
                                {"device": "AP", "count": "8", "watts": "25.5", "class": "4"}])
    assert d["draw"] == 360.0 and d["reserved"] == 408.0 and not d["ok"] and d["left"] == -38.0 and "Over budget" in d["note"]
    a = calc.poe_budget("370", [{"device": "Phone", "count": "24", "watts": "6.5", "class": "2"},
                                {"device": "AP", "count": "8", "watts": "25.5", "class": "4"}], reserve="actual")
    assert a["ok"] and a["left"] == 10.0 and "Under 20%" in a["note"]
    with pytest.raises(calc.CalcError):
        calc.poe_budget("lots", [])


flask = pytest.importorskip("flask")
from test_auth import ADMIN, add_user, app, admin, csrf, login  # noqa: F401,E402
from test_builder_web import pick_space, token  # noqa: E402

ARISTA = json.loads((Path(__file__).parent.parent / "src" / "switchbuilder" / "vendor_examples" / "arista-office.json").read_text())


def test_web_calc(app, admin):
    pick_space(admin, "lab")
    hdr = {"X-CSRF-Token": token(admin)}
    assert "Calculators" in admin.get("/tools/").get_data(as_text=True)
    assert "PoE power budget" in admin.get("/tools/calc").get_data(as_text=True)
    assert admin.post("/tools/calc/subnet", json={"address": "10.1.1.1/30"}, headers=hdr).json["usable"] == 2
    assert admin.post("/tools/calc/subnet", json={"address": "x"}, headers=hdr).status_code == 400
    assert admin.post("/tools/calc/split", json={"network": "10.0.0.0/24", "count": "2"}, headers=hdr).json["prefix"] == 25
    assert admin.post("/tools/calc/split", json={"network": "10.0.0.0/24", "count": "two"}, headers=hdr).status_code == 400
    plan = admin.post("/tools/calc/vlans", json={"supernet": "10.50.0.0/16", "vlans": [
        {"name": "MGMT", "id": "10", "hosts": "20"}, {"name": "PRINTERS", "id": "70", "hosts": "20"}]}, headers=hdr).json
    pid = admin.post("/projects", json={"name": "ar", "data": ARISTA}, headers=hdr).json["id"]
    r = admin.post("/tools/calc/vlans/apply", json={"project_id": pid, "vlans": plan["vlans"]}, headers=hdr).json
    assert r["added"] == ["70 PRINTERS"] and r["skipped"] == ["10 MGMT"]
    data = admin.get(f"/projects/{pid}").json["data"]
    assert {"name": "PRINTERS", "id": "70", "irb": "10.50.0.33/27"} in data["vlans"]
    assert admin.post("/tools/calc/poe", json={"budget": "100", "devices": [{"device": "AP", "count": 2, "watts": 25.5, "class": "4"}]},
                      headers=hdr).json["reserved"] == 60.0
