"""Pre-push checks across several projects."""

import copy
import json
from pathlib import Path

import pytest

from switchbuilder import prepush

BASE = json.loads((Path(__file__).parent.parent / "src" / "switchbuilder" / "vendor_examples" / "arista-office.json").read_text())


def _pair():
    core = copy.deepcopy(BASE)
    core["system"]["hostname"] = "core-sw1"
    core["system"]["mgmt_address"] = "192.168.100.2/24"
    core["ports"] = []
    core["vlans"][1]["irb"] = "10.10.20.2/24"
    core["vlans"][0]["irb"] = "10.10.10.1/24"
    core["lags"] = [{"name": "Po1", "members": "Ethernet1-2", "mode": "trunk", "lacp": "active",
                     "vlans": "MGMT, USERS, VOICE, WIFI, CAMERAS", "description": "To acc-sw1"}]
    core.setdefault("services", {})["bridge_priority"] = "4k"
    acc = copy.deepcopy(BASE)
    acc["system"]["hostname"] = "acc-sw1"
    acc["lags"][0]["description"] = "To core-sw1"
    return core, acc


def _run(*projects, links=None):
    return prepush.check([{"name": p["system"]["hostname"], "data": p} for p in projects], links)


def _msgs(r, level=None):
    return [c["message"] for c in r["checks"] if level in (None, c["level"])]


def test_clean_pair_is_ready():
    r = _run(*_pair())
    assert r["ready"], _msgs(r)
    assert r["links"] == [{"a": "core-sw1", "a_row": "Po1", "b": "acc-sw1", "b_row": "Po1", "found": "description",
                           "issues": []}]
    assert "Spanning-tree root: core-sw1 (priority 4096)." in _msgs(r, "info")


def test_link_mismatches():
    core, acc = _pair()
    core["lags"][0].update(vlans="MGMT, USERS", native="MGMT", mtu="9216", lacp="passive")
    acc["lags"][0]["lacp"] = "passive"
    acc["vlans"].append({"name": "GUEST", "id": "60"})
    acc["ports"][0]["vlan"] = "GUEST"
    r = _run(core, acc)
    errors, warns = _msgs(r, "error"), _msgs(r, "warn")
    assert not r["ready"]
    assert any("both LACP passive" in m for m in errors)
    assert any("Native VLAN differs: core-sw1 Po1 10, acc-sw1 Po1 none" in m for m in errors)
    assert "VLAN 30, 40, 50 allowed on acc-sw1 Po1 but not on core-sw1 Po1." in warns
    assert "MTU differs: core-sw1 Po1 9216, acc-sw1 Po1 default." in warns
    assert any(m.startswith("acc-sw1: VLAN 60 is used on its ports but no uplink carries it") for m in warns)
    assert len(r["links"][0]["issues"]) >= 4


def test_mode_and_lag_mismatch_with_manual_link():
    core, acc = _pair()
    core["lags"][0]["description"] = ""
    acc["lags"][0]["description"] = ""
    core["ports"] = [{"name": "DOWN", "ports": "Ethernet3", "mode": "access", "vlan": "USERS"}]
    r = _run(core, acc)
    assert r["links"] == [] and any("no link to the other switches" in m for m in _msgs(r, "info"))
    r = _run(core, acc, links=[{"a": "core-sw1", "a_row": "DOWN", "b": "acc-sw1", "b_row": "Po1"}])
    errors = _msgs(r, "error")
    assert "acc-sw1 Po1 is a LAG but core-sw1 DOWN is not." in errors
    assert "core-sw1 DOWN is access but acc-sw1 Po1 is trunk." in errors
    assert r["links"][0]["found"] == "added by hand"
    bad = _run(core, acc, links=[{"a": "core-sw1", "a_row": "NOPE", "b": "acc-sw1", "b_row": "Po1"}])
    assert any("no port group or LAG called NOPE" in m for m in _msgs(bad, "warn"))


def test_addresses_names_and_stp():
    core, acc = _pair()
    acc["system"]["mgmt_address"] = "192.168.100.2/24"
    acc["vlans"][1]["irb"] = "10.10.20.2/24"
    acc["vlans"][2]["name"] = "PHONES"
    acc["vlans"][3]["irb"] = "10.10.10.9/24"
    acc["services"] = {"stp": "mstp"}
    r = _run(core, acc)
    errors, warns, infos = _msgs(r, "error"), _msgs(r, "warn"), _msgs(r, "info")
    assert any(m.startswith("IP address 192.168.100.2 is used more than once") for m in errors)
    assert any(m.startswith("IP address 10.10.20.2 is used more than once") for m in errors)
    assert any(m.startswith("Subnet 10.10.10.0/24 is on different VLANs") for m in warns)
    assert any(m.startswith("VLAN 30 has different names") for m in infos)
    assert any(m.startswith("Spanning-tree protocols differ") for m in warns)
    dup = _run(core, copy.deepcopy(core))
    assert any(m.startswith("Host name core-sw1 is used by 2 projects") for m in _msgs(dup, "error"))
    tie = copy.deepcopy(acc)
    tie["services"] = {"stp": "rstp", "bridge_priority": "4k"}
    assert any("tie at priority 4096" in m for m in _msgs(_run(core, tie), "warn"))


def test_builder_errors_and_routed_links():
    core, acc = _pair()
    core["lags"] = []
    acc["lags"] = []
    core["ports"] = [{"name": "UP", "ports": "Ethernet49", "mode": "routed", "address": "10.0.0.0/31", "description": "to acc-sw1"}]
    acc["ports"].append({"name": "UP", "ports": "Ethernet49", "mode": "routed", "address": "10.0.0.3/31", "description": "to core-sw1"})
    acc["system"]["hostname"] = "acc-sw1"
    r = _run(core, acc)
    assert "core-sw1 UP and acc-sw1 UP are routed but not in the same subnet." in _msgs(r, "error")
    broken = copy.deepcopy(acc)
    broken["vlans"][0]["irb"] = "nope"
    assert any("the builder reports" in m for m in _msgs(_run(core, broken), "error"))


# ----------------------------------------------------------------- web
flask = pytest.importorskip("flask")
from test_auth import ADMIN, add_user, app, admin, csrf, login  # noqa: F401,E402
from test_builder_web import pick_space, token  # noqa: E402


def test_web_checks(app, admin):
    pick_space(admin, "lab")
    assert "Pre-push checks" in admin.get("/tools/").get_data(as_text=True)
    assert "Run checks" in admin.get("/tools/checks").get_data(as_text=True)
    hdr = {"X-CSRF-Token": token(admin)}
    core, acc = _pair()
    ids = [admin.post("/projects", json={"name": n, "data": d}, headers=hdr).json["id"]
           for n, d in (("core", core), ("acc", acc))]
    r = admin.post("/tools/checks/run", json={"project_ids": ids}, headers=hdr)
    assert r.status_code == 200 and r.json["ready"] and len(r.json["links"]) == 1
    assert admin.post("/tools/checks/run", json={"project_ids": []}, headers=hdr).status_code == 400
    r = admin.post("/tools/checks/run", json={"projects": [{"name": "a", "data": core}, {"name": "b", "data": core}]},
                   headers=hdr)
    assert not r.json["ready"]
    pick_space(admin, "production")
    assert admin.post("/tools/checks/run", json={"project_ids": ids}, headers=hdr).status_code == 400
