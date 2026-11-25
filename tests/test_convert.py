"""Converter: read a config from one vendor, write it for another."""

import json
from pathlib import Path

import pytest

from exbuilder import convert, vendors
from exbuilder.convert import ios, portmap

DATA = Path(__file__).parent / "data"
CISCO = (DATA / "convert" / "cisco-c9300.txt").read_text()
JUNOS = (DATA / "legacy-ex2300.conf").read_text()


def test_detects_vendor():
    assert convert.detect(CISCO) == "cisco"
    assert convert.detect(JUNOS) == "juniper"
    assert convert.detect("hello") == ""


def test_type7_password():
    assert ios.type7("0822455D0A16") == "cisco"


def test_cisco_reader():
    res = ios.parse(CISCO)
    p = res["project"]
    assert p["system"]["hostname"] == "acc-sw-01" and p["system"]["domain"] == "corp.example"
    assert p["system"]["mgmt_address"] == "192.168.50.11/24" and p["system"]["mgmt_gateway"] == "192.168.50.1"
    assert [m["model"] for m in p["switch"]["members"]] == ["C9300-48P", "C9300-48P"]
    assert {v["id"]: v["name"] for v in p["vlans"]} == {"10": "MGMT", "20": "STAFF", "30": "VOIP", "40": "Guest-WiFi"}
    assert next(v for v in p["vlans"] if v["id"] == "20")["irb"] == "10.10.20.1/24"
    assert p["routing"]["dhcp_relay_servers"] == "10.1.0.20"
    assert p["routing"]["static"] == [{"prefix": "0.0.0.0/0", "next_hop": "10.10.10.1"}]
    desk = next(r for r in p["ports"] if r["name"] == "DESK")
    assert desk["ports"] == "GigabitEthernet1/0/1-3, GigabitEthernet2/0/1"
    assert desk["vlan"] == "STAFF" and desk["voice"] == "VOIP" and desk["edge"]
    ap = next(r for r in p["ports"] if r["name"] == "AP")
    assert ap["mode"] == "trunk" and ap["native"] == "MGMT" and ap["vlans"] == "MGMT, Guest-WiFi" and ap["poe"] == "high"
    assert next(r for r in p["ports"] if r["name"] == "PRINTER")["poe"] == "off"
    assert any(r["dot1x"] == "dot1x-mab" for r in p["ports"])
    assert next(r for r in p["ports"] if r["mode"] == "disabled")["ports"] == "GigabitEthernet2/0/10"
    lag = p["lags"][0]
    assert lag["name"] == "Port-channel1" and lag["lacp"] == "active"
    assert lag["members"] == "TenGigabitEthernet1/1/1, TenGigabitEthernet2/1/1"
    assert p["security"]["radius_servers"] == [{"address": "10.1.0.40", "secret": "cisco", "port": "1812"}]
    assert p["services"]["stp"] == "rstp" and p["services"]["bridge_priority"] == "24k" and p["services"]["lldp"]
    assert [u["class"] for u in p["access"]["users"]] == ["super-user", "read-only"]
    assert any("BLOCK-GUEST" in x for x in res["unparsed"])


def test_cisco_to_juniper():
    r = convert.convert(CISCO, "", "juniper")
    assert r["source"] == "cisco" and r["model"] == "EX2300-48P"
    cfg = r["config"]
    assert "set system host-name acc-sw-01" in cfg
    assert "set interfaces interface-range DESK member-range ge-0/0/0 to ge-0/0/2" in cfg
    assert "set interfaces interface-range DESK member ge-1/0/0" in cfg
    assert "set interfaces xe-0/1/0 ether-options 802.3ad ae0" in cfg and "xe-1/1/0 ether-options 802.3ad ae0" in cfg
    assert "set poe interface ge-0/0/47 priority high" in cfg
    assert "set interfaces irb unit 20 family inet address 10.10.20.1/24" in cfg
    assert {"from": "GigabitEthernet1/0/48", "to": "ge-0/0/47"} in r["ports"]
    # Cisco hashes can't move; the report says so and the builder asks for new passwords.
    assert any("hash" in c["text"] for c in r["changes"])
    assert any("root password" in e["message"] for e in r["errors"])
    assert r["not_read"]


@pytest.mark.parametrize("target", [k for k, v in vendors.VENDORS.items() if v.ready])
def test_cisco_converts_to_every_vendor(target):
    r = convert.convert(CISCO, "cisco", target)
    assert "error" not in r, r
    assert r["project"]["vendor"] == target and r["model"]
    # Only password problems and things the target can't do should be left.
    bad = [e["message"] for e in r["errors"] if not any(w in e["message"].lower() for w in
           ("password", "helpdesk", "management port", "can't route", "out-of-band"))]
    assert not bad, bad


def test_juniper_to_cisco_and_lag_numbers():
    r = convert.convert(JUNOS, "", "cisco")
    assert r["source"] == "juniper"
    lag = r["project"]["lags"][0]
    assert lag["name"] == "Port-channel1"
    assert "interface Port-channel1" in r["config"]


def test_target_model_and_stacking():
    # A stack to a vendor that doesn't stack keeps the first switch and says so.
    r = convert.convert(CISCO, "cisco", "arista")
    assert len(r["project"]["switch"]["members"]) == 1
    assert any("doesn't stack" in c["text"] for c in r["changes"])
    r = convert.convert(CISCO, "cisco", "juniper", "EX4100-48P")
    assert r["model"] == "EX4100-48P"
    assert convert.convert(CISCO, "cisco", "juniper", "nope")["error"]


def test_unknown_or_unready_source():
    assert "error" in convert.convert("nothing here", "", "juniper")
    assert "not ready" in convert.convert("config system global\nend", "", "juniper")["error"]


def test_builder_output_reads_back():
    from exbuilder.generator import build
    p = json.loads((Path(convert.__file__).parent.parent / "vendor_examples" / "cisco-office.json").read_text())
    r = convert.convert(build(p).to_dict()["set"], "cisco", "juniper")
    assert r["stats"]["vlans"] == 5 and r["stats"]["lags"] == 1
    assert {row["name"] for row in r["project"]["ports"]} >= {"DESK-PORTS", "WI-FI-ACCESS-POINTS"}


def test_ospf_interfaces_follow():
    text = CISCO.replace("ip route 0.0.0.0", "router ospf 1\n router-id 10.10.10.2\n network 10.10.20.0 0.0.0.255 area 0\n"
                         " passive-interface Vlan20\n!\nip route 0.0.0.0", 1)
    r = convert.convert(text, "cisco", "juniper")
    area = r["project"]["routing"]["ospf"]["areas"][0]
    assert area["passive"] == "irb.20"
    r = convert.convert(text, "cisco", "aruba")
    assert r["project"]["routing"]["ospf"]["areas"][0]["passive"] == "vlan 20"


def test_portmap_lag_names():
    assert portmap.lag_number("juniper", "ae0") == 1
    assert portmap.lag_name("juniper", 1) == "ae0"
    assert portmap.lag_name("procurve", 2) == "Trk2"


# ------------------------------------------------------------------ web
flask = pytest.importorskip("flask")
from test_auth import ADMIN, add_user, app, admin, csrf, login  # noqa: F401,E402
from test_builder_web import pick_space, token  # noqa: E402
from test_clients import _bob  # noqa: E402


def _post(client, url, body):
    return client.post(url, json=body, headers={"X-CSRF-Token": csrf(client, "/convert")})


def test_start_page_offers_converter(admin):
    page = admin.get("/start").get_data(as_text=True)
    assert 'href="/convert"' in page and "Converter" in page
    page = admin.get("/convert").get_data(as_text=True)
    assert "Detect it for me" in page and "Save to Lab" in page and "EX4100-48P" in page


def test_convert_save_to_lab_and_open(app, admin):
    r = _post(admin, "/convert/run", {"text": CISCO, "target": "juniper"})
    assert r.status_code == 200 and r.json["detected"] and r.json["source"] == "cisco"
    assert _post(admin, "/convert/run", {"text": "", "target": "juniper"}).status_code == 400
    proj = r.json["project"]
    s = _post(admin, "/convert/save", {"client_id": 1, "name": "acc-sw-01 (Juniper)", "data": proj})
    assert s.status_code == 200
    pid = s.json["id"]
    again = _post(admin, "/convert/save", {"client_id": 1, "name": "acc-sw-01 (Juniper)", "data": proj})
    assert again.status_code == 409 and again.json["exists"]
    assert _post(admin, "/convert/save", {"client_id": 1, "name": "acc-sw-01 (Juniper)", "data": proj,
                                         "overwrite": True}).status_code == 200
    # It is in the Lab space, not Production.
    pick_space(admin, "production")
    assert admin.get("/projects").json["projects"] == []
    resp = admin.post("/convert/open", data={"csrf_token": csrf(admin, "/convert"), "client_id": 1, "project_id": pid})
    assert resp.status_code == 302 and resp.headers["Location"].endswith(f"/build/juniper?project={pid}")
    assert [p["name"] for p in admin.get("/projects").json["projects"]] == ["acc-sw-01 (Juniper)"]


def test_convert_save_needs_editor(app, admin):
    proj = _post(admin, "/convert/run", {"text": CISCO, "target": "juniper"}).json["project"]
    viewer = _bob(app, admin, "viewer")
    r = _post(viewer, "/convert/save", {"client_id": 1, "name": "x", "data": proj})
    assert r.status_code == 403
    assert _post(viewer, "/convert/save", {"client_id": 99, "name": "x", "data": proj}).status_code == 403
