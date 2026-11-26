"""Firmware tracker: versions from backups against a policy."""

from pathlib import Path

import pytest

from switchbuilder import firmware as F

ROOT = Path(__file__).parent.parent / "src" / "switchbuilder"


@pytest.mark.parametrize("text, want", [
    ("set version 22.4R3-S2.11\nset system host-name x\n", ("juniper", "22.4R3-S2.11")),
    ("version 21.4R3.15;\nsystem {\n", ("juniper", "21.4R3.15")),
    ("Hostname: ex1\nModel: ex4100-48p\nJunos: 23.4R2-S1.6\n", ("juniper", "23.4R2-S1.6")),
    ("! device: core1 (DCS-7050SX3-48YC8, EOS-4.31.1F)\n", ("arista", "4.31.1F")),
    ("Cisco IOS XE Software, Version 17.09.04a\n", ("cisco", "17.09.04a")),
    ("Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E3, RELEASE SOFTWARE (fc1)\n", ("cisco", "15.2(7)E3")),
    ("!Version ArubaOS-CX FL.10.13.1000\n", ("aruba", "FL.10.13.1000")),
    ("; J9772A Configuration Editor; Created on release #YA.16.10.0012\n", ("procurve", "YA.16.10.0012")),
    ("! Version 10.5.4.0\n", ("dell", "10.5.4.0")),
    ("# Software Version 32.6.3.126\n", ("extreme", "32.6.3.126")),
    ("ver 08.0.95dT213\n", ("ruckus", "08.0.95dT213")),
    ("#config-version=FS1D24-7.2.5-FW-build0461-230816:opmode=0\n", ("fortiswitch", "7.2.5 build0461")),
    ("# 2026-11-25 by RouterOS 7.14.2\n", ("mikrotik", "7.14.2")),
    ("nothing", ("", "")),
])
def test_detect(text, want):
    assert F.detect(text) == want


def test_compare_and_rules():
    assert F.compare("22.4R3", "22.4R3-S2") < 0
    assert F.compare("22.4R3-S2.11", "22.4R2") > 0
    assert F.compare("4.31.1F", "4.31.2F") < 0
    assert F.compare("15.2(7)E3", "15.2(7)E10") < 0
    assert F.compare("17.9.4", "17.9.4") == 0
    assert F.matches("21.4R2", "< 21.4R3") and not F.matches("21.4R3", "< 21.4R3")
    assert F.matches("17.9.2", "17.9.1 - 17.9.3") and not F.matches("17.9.4", "17.9.1 - 17.9.3")
    assert F.matches("16.12.4", "16.12*") and F.matches("22.2R1", "22.2R1")


def test_assess_and_report():
    policy = F.clean_policy({"rows": [
        {"vendor": "juniper", "minimum": "21.4R3", "recommended": "23.4R2", "bad": [{"rule": "22.2R1 - 22.2R3", "note": "JSA12345"}]},
        {"vendor": "juniper", "family": "EX2300", "minimum": "20.4R3", "recommended": "21.4R3"},
        {"vendor": "", "minimum": "1"}, "junk"]})
    assert len(policy["rows"]) == 2
    assert F.assess("a", "juniper", "22.2R2", "EX4100-48P", policy)["status"] == "vulnerable"
    assert "JSA12345" in F.assess("a", "juniper", "22.2R2", "EX4100-48P", policy)["why"]
    assert F.assess("a", "juniper", "21.2R3", "EX4100-48P", policy)["status"] == "below minimum"
    assert F.assess("a", "juniper", "22.4R3", "EX4100-48P", policy)["status"] == "update"
    assert F.assess("a", "juniper", "23.4R2-S1", "EX4100-48P", policy)["status"] == "ok"
    assert F.assess("a", "juniper", "21.4R3", "EX2300-48P", policy)["status"] == "ok"   # family line wins
    assert F.assess("a", "arista", "4.31.1F", "", policy)["why"] == "no policy for this brand yet"
    r = F.report([{"name": "ex1", "text": "set version 22.2R2\n"}, {"name": "ar1", "text": "! device: a (DCS-7050, EOS-4.31.1F)"},
                  {"name": "x", "text": "hello"}], policy)
    assert [s["status"] for s in r["switches"]] == ["vulnerable", "unknown", "unknown"]
    assert r["counts"]["vulnerable"] == 1 and r["versions"]["juniper"] == {"22.2R2": 1}


flask = pytest.importorskip("flask")
from test_auth import ADMIN, add_user, app, admin, csrf, login  # noqa: F401,E402
from test_builder_web import pick_space, token  # noqa: E402
from test_clients import _bob  # noqa: E402


def test_web_firmware(app, admin):
    pick_space(admin, "production")
    hdr = {"X-CSRF-Token": token(admin)}
    assert "Firmware tracker" in admin.get("/tools/").get_data(as_text=True)
    assert "(none yet)" in admin.get("/tools/firmware").get_data(as_text=True)
    junos = (ROOT / "map_examples" / "core-sw1.conf").read_text()
    with app.app_context():
        from switchbuilder.web import auth, backups
        backups.store(auth.db(), 1, [{"name": "core-sw1", "text": junos}], "upload", "admin")
    ver = F.detect(junos)[1]
    assert ver
    pol = {"rows": [{"vendor": "juniper", "minimum": "", "recommended": "99.1R1", "bad": []}]}
    assert admin.post("/tools/firmware/policy", json=pol, headers=hdr).json["ok"]
    assert admin.post("/tools/firmware/policy", json={"rows": [{"vendor": "acme"}]}, headers=hdr).status_code == 400
    r = admin.post("/tools/firmware/run", json={"pasted": [{"name": "ar1", "text": "! device: a (DCS-7050, EOS-4.31.1F)"}]},
                   headers=hdr).json
    by = {s["name"]: s for s in r["switches"]}
    assert by["core-sw1"]["status"] == "update" and by["core-sw1"]["version"] == ver
    assert by["ar1"]["status"] == "unknown"
    bob = _bob(app, admin, role="editor")
    pick_space(bob, "production")
    bh = {"X-CSRF-Token": token(bob)}
    assert bob.post("/tools/firmware/policy", json=pol, headers=bh).status_code == 403
    assert bob.post("/tools/firmware/run", json={}, headers=bh).status_code == 200
