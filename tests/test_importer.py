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


# ------------------------------------------------------- model detection
VC_OUTPUT = """
Preprovisioned Virtual Chassis
Virtual Chassis ID: 1234.abcd.0000
                                                Mstr           Mixed Route Neighbor List
Member ID  Status   Serial No    Model          prio  Role      Mode  Mode ID  Interface
0 (FPC 0)  Prsnt    NW0217AF0001 ex4300-48p     129   Master*      N  VC   1  vcp-255/1/0
1 (FPC 1)  Prsnt    NW0217AF0002 ex4300-48t     129   Backup       N  VC   0  vcp-255/1/0
2 (FPC 2)  Prsnt    NW0217AF0003 ex4300-24p       0   Linecard     N  VC
"""


def test_detect_models_from_show_output():
    from exbuilder.importer import detect_models
    d = detect_models(VC_OUTPUT)["members"]
    assert [(f, m["model"], m["role"], m["how"]) for f, m in sorted(d.items())] == [
        (0, "EX4300-48P", "routing-engine", "show virtual-chassis"),
        (1, "EX4300-48T", "routing-engine", "show virtual-chassis"),
        (2, "EX4300-24P", "line-card", "show virtual-chassis")]
    assert d[0]["serial"] == "NW0217AF0001"
    v = detect_models("fpc0:\n-----\nHostname: sw1\nModel: ex2300-48mp\n\nfpc1:\n-----\nModel: ex2300-24p\n")
    assert {f: m["model"] for f, m in v["members"].items()} == {0: "EX2300-48MP", 1: "EX2300-24P"}
    assert detect_models("Model: ex4400-24t")["members"][0]["how"] == "show version"
    assert detect_models("Model: ex9999-1")["unknown"] == ["ex9999-1"]


def test_guess_models_from_ports():
    from exbuilder.importer import detect_models
    poe = detect_models("set interfaces ge-0/0/30 unit 0\nset poe interface all\nset interfaces me0 unit 0")
    assert poe["members"][0] == {"model": "EX2300-48P", "serial": "", "role": "", "how": "port names"}
    em0 = detect_models("set interfaces ge-0/0/30 unit 0\nset interfaces em0 unit 0")["members"][0]["model"]
    assert em0.startswith(("EX4100", "EX4400"))
    mge = detect_models("set interfaces mge-0/0/3 unit 0")["members"][0]["model"]
    assert "MP" in mge


def test_import_applies_detected_models():
    from exbuilder.importer import check, detect_models
    text = VC_OUTPUT + "\n{master:0}\nset system host-name vc1\nset interfaces ge-1/0/5 unit 0 family ethernet-switching\n"
    res = check(text, "", detect_models(text)["members"])
    members = res["project"]["switch"]["members"]
    assert [(m["fpc"], m["model"], m["role"]) for m in members] == [
        (0, "EX4300-48P", "routing-engine"), (1, "EX4300-48T", "routing-engine"), (2, "EX4300-24P", "line-card")]
    assert res["stats"]["not_imported"] == 0  # the show output is not counted as config
    # A model the user picks wins for member 0.
    res = check(text, "EX4300-24T", detect_models(text)["members"])
    assert res["project"]["switch"]["members"][0]["model"] == "EX4300-24T"


def test_show_output_around_a_curly_config():
    from exbuilder.importer import to_set_lines
    text = ("Hostname: sw1\nModel: ex4300-48p\nJunos: 23.4R2\nJUNOS Base OS boot [23.4R2]\n{master:0}\n"
            "system {\n    host-name sw1;\n    login {\n        message \"Note: authorized only\";\n    }\n}\n")
    assert to_set_lines(text) == ["system host-name sw1", 'system login message "Note: authorized only"']
