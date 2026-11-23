import json
from pathlib import Path

import pytest

from exbuilder.generator import build
from exbuilder.importer import check, guess_model, harden, parse, to_set_lines

HERE = Path(__file__).parent
EX = HERE.parent / "examples"


def sets(text):
    return {x for x in text.splitlines() if x.startswith("set ")}


@pytest.mark.parametrize("fmt", ["set_text", "hier_text"])
def test_round_trip_office_example(fmt):
    proj = json.load(open(EX / "office-switch.json"))
    original = build(proj)
    res = check(getattr(original, fmt), "EX2300-48P")
    assert res["unparsed"] == [] and res["stats"]["not_imported"] == 0
    again = build(res["project"])
    assert sets(again.set_text) == sets(original.set_text)


def test_hierarchical_lists_and_comments():
    text = 'interfaces { ae0 { unit 0 { family ethernet-switching { vlan { members [ A B ]; } } } } } /* x */'
    assert to_set_lines(text) == ["interfaces ae0 unit 0 family ethernet-switching vlan members A",
                                  "interfaces ae0 unit 0 family ethernet-switching vlan members B"]


def test_legacy_config():
    text = (HERE / "data" / "legacy-ex2300.conf").read_text()
    assert guess_model(text).startswith("EX2300-48")
    res = check(text, "EX2300-48T")
    p = res["project"]
    assert p["system"]["hostname"] == "sw-legacy-01"
    office = next(x for x in p["ports"] if x["name"] == "OFFICE")
    assert office["ports"] == "ge-0/0/0-23" and office["mode"] == "access" and office["vlan"] == "STAFF"
    ae0 = p["lags"][0]
    assert ae0["members"] == "ge-0/0/46-47" and ae0["native"] == "MGMT" and ae0["vlans"] == "STAFF, VOICE, MGMT"
    assert ae0["lacp"] == "active"
    assert next(v for v in p["vlans"] if v["name"] == "MGMT")["irb"] == "192.168.99.10/24"
    assert p["routing"]["static"] == [{"prefix": "0.0.0.0/0", "next_hop": "192.168.99.1", "preference": ""}]
    titles = " | ".join(r["title"] for r in res["recommendations"])
    assert "Telnet" in titles and "HTTP web management" in titles and "'public'" in titles and "No NTP" in titles
    assert res["recommendations"][0]["level"] == "high"
    assert "set system services telnet" in res["unparsed"]
    assert res["score"] < 60
    hard = res["hardened"]
    assert hard["access"]["ssh_root_login"] == "deny" and hard["services"]["storm_control"]
    assert all(x["edge"] for x in hard["ports"] if x["mode"] == "access")
    assert "SSH root login denied" in res["fixes"]


def test_good_config_scores_well():
    proj = json.load(open(EX / "office-switch.json"))
    proj["access"]["root_password"] = "$6$abc$" + "x" * 86
    proj["access"]["users"][0]["password"] = "$6$abc$" + "y" * 86
    res = check(build(proj).set_text, "EX2300-48P")
    assert res["errors"] == []
    assert res["score"] >= 85, res["recommendations"]
    assert harden(res["project"])[1] == [] or res["score"] >= 85


def test_empty_input():
    assert "error" in check("hello world")
    assert parse("")["stats"]["lines"] == 0


def test_evpn_example_imports_vni_and_routing():
    proj = json.load(open(EX / "evpn-leaf.json"))
    res = check(build(proj).set_text, "EX4400-48P")
    p = res["project"]
    assert next(v for v in p["vlans"] if v["name"] == "USERS")["vni"] == "10020"
    assert p["routing"]["loopback"] == "10.255.0.11/32" and p["routing"]["ospf"]["enabled"]


def test_round_trip_qos_poe_security():
    proj = json.load(open(EX / "office-switch.json"))
    proj["services"].update(poe_management="class", poe_guard_band="5", poe_fast=True, poe_perpetual=True)
    proj["ports"][0].update(dot1x="dot1x-mab", mac_action="shutdown", sticky=True, poe_max="15.4")
    proj["lags"][0].update(root_guard=True, loop_protect=True)
    proj["security"] = {"radius_servers": [{"address": "10.10.0.30", "secret": "s3cret", "port": ""}],
                        "server_fail": "permit", "guest_vlan": "WIFI", "recovery_timeout": "300"}
    proj["qos"] = {"enabled": True, "preset": "voice-video", "trust": "access"}
    proj["vlans"][2]["voice"] = False
    original = build(proj)
    assert "set class-of-service schedulers VOICE priority strict-high" in original.set_text
    assert "set protocols dot1x authenticator interface ge-0/0/0.0 mac-radius" in original.set_text
    assert "set poe fpc 0 perpetual-poe" in original.set_text
    res = check(original.set_text, "EX2300-48P")
    assert res["unparsed"] == [], res["unparsed"][:5]
    assert sets(build(res["project"]).set_text) == sets(original.set_text)


def test_voice_vlan_flag_applies_to_access_ports():
    proj = json.load(open(EX / "office-switch.json"))
    proj["ports"][0]["voice"] = ""
    proj["vlans"][2]["voice"] = True
    out = build(proj).set_text
    assert "set switch-options voip interface ge-0/0/0.0 vlan VOICE" in out
