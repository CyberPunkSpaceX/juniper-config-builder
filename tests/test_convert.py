"""Converter: read a config from one vendor, write it for another."""

import json
from pathlib import Path

import pytest

from switchbuilder import convert, vendors
from switchbuilder.convert import ios, portmap

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
    from switchbuilder.generator import build
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


def test_converter_refuses_hidden_lines():
    # A description with an escape sequence in the pasted config is refused, not passed on.
    text = CISCO.replace("\n", "\r\n", 3) + "\ninterface GigabitEthernet1/0/48\n description up\x0blink\n"
    out = convert.convert(text, "cisco", "arista")
    assert "\x0b" not in out["config"]
    assert any("control character" in e["message"] for e in out["errors"])
# ------------------------------------------------------------------ stage 2: Arista, Nexus, Dell
def _example_text(vendor):
    from switchbuilder.generator import build
    p = json.loads((Path(convert.__file__).parent.parent / "vendor_examples" / f"{vendor}-office.json").read_text())
    return p, build(p).to_dict()["set"]


@pytest.mark.parametrize("vendor", ["arista", "nexus", "dell"])
def test_reads_back_builder_output(vendor):
    p, text = _example_text(vendor)
    assert convert.detect(text) == vendor
    r = convert.convert(text, "", "juniper")
    q = r["project"]
    assert r["source"] == vendor
    assert q["system"]["hostname"] == p["system"]["hostname"]
    assert q["system"]["mgmt_address"] == p["system"]["mgmt_address"]
    assert {v["id"] for v in q["vlans"]} == {v["id"] for v in p["vlans"]}
    assert len(q["lags"]) == len(p["lags"]) == 1
    assert q["routing"]["static"][-1]["next_hop"] == p["routing"]["static"][-1]["next_hop"]
    assert [c["name"] for c in q["snmp"]["communities"]] == [c["name"] for c in p["snmp"]["communities"]]
    # Only the SNMP access list (and Nexus' extra VLAN mapping line) is left unread.
    assert len(r["not_read"]) <= 2, r["not_read"]


def test_arista_phone_trunk_becomes_access_with_voice():
    _, text = _example_text("arista")
    q = convert.convert(text, "arista", "cisco")["project"]
    desk = next(r for r in q["ports"] if r["name"] == "DESK-PORTS")
    assert desk["mode"] == "access" and desk["vlan"] == "USERS" and desk["voice"] == "VOICE"
    assert desk["mac_limit"] == "3" and desk["ports"].startswith("GigabitEthernet1/0/1-")
    assert next(r for r in q["ports"] if r["vlan_translate"])["vlan_translate"] == "1050>50"
    assert q["system"]["mgmt_gateway"] == "192.168.100.1"


def test_dell_vlan_names_and_trunk_native():
    _, text = _example_text("dell")
    q = convert.convert(text, "dell", "arista")["project"]
    assert {v["id"]: v["name"] for v in q["vlans"]}["20"] == "USERS"
    ap = next(r for r in q["ports"] if r["name"] == "WI-FI-ACCESS-POINTS")
    assert ap["mode"] == "trunk" and ap["native"] == "MGMT"


def test_real_eos_running_config():
    text = """! device: leaf1 (DCS-7050SX3-48YC8, EOS-4.30.1F)
!
hostname leaf1
!
vlan 20
   name Users
!
interface Ethernet1
   description pc
   switchport access vlan 20
   spanning-tree portfast
!
interface Ethernet2
   no switchport
   ip address 10.0.0.1/31
!
interface Management1
   ip address 192.168.1.5/24
!
interface Vlan20
   ip address 10.20.0.1/24
!
ip route 0.0.0.0/0 10.0.0.0
!
end
"""
    r = convert.convert(text, "", "nexus")
    assert r["source"] == "arista"
    q = r["project"]
    routed = next(p for p in q["ports"] if p["mode"] == "routed")
    assert routed["address"] == "10.0.0.1/31"
    assert next(p for p in q["ports"] if p["mode"] == "access")["vlan"] == "Users"


@pytest.mark.parametrize("source", ["cisco", "arista", "nexus", "dell"])
def test_every_source_to_every_target_runs(source):
    _, text = _example_text(source)
    for target, v in vendors.VENDORS.items():
        r = convert.convert(text, source, target)
        assert "error" not in r, (source, target, r)
        assert r["config"] or r["errors"]


# ------------------------------------------------------------------ older Cisco (Gi0/x) and routing
L3 = (DATA / "convert" / "cisco-ios15-l3.txt").read_text()


def test_old_cisco_ports_match_by_order_not_dropped():
    r = convert.convert(L3, "", "juniper", "EX4100-48P")
    assert r["source"] == "cisco" and r["source_models"] == [""]
    assert {"from": "GigabitEthernet0/1", "to": "ge-0/0/0"} in r["ports"]
    assert {"from": "GigabitEthernet0/5", "to": "ge-0/0/4"} in r["ports"]
    assert not [c for c in r["changes"] if c["level"] == "lost"]
    assert any("matched by order" in c["text"] for c in r["changes"] if c["level"] == "check")
    q = r["project"]
    assert len(q["ports"]) == 5
    routed = {p["description"]: p for p in q["ports"] if p["mode"] == "routed"}
    assert routed["Routed P2P Link to Edge Router R1"]["address"] == "172.16.1.1/30"
    acct = next(p for p in q["ports"] if p["description"] == "Workstation - Accounting")
    assert acct["mac_limit"] == "2" and acct["sticky"] and acct["voice"] == "VOICE" and acct["edge"]
    assert next(p for p in q["ports"] if p["mode"] == "trunk")["native"] == "BLACKHOLE"


def test_old_cisco_routing_carries_over():
    r = convert.convert(L3, "cisco", "juniper", "EX4100-48P")
    q, cfg = r["project"], r["config"]
    assert q["routing"]["loopback"] == "10.255.255.1/32" and q["routing"]["router_id"] == "10.255.255.1"
    assert q["routing"]["static"] == [{"prefix": "0.0.0.0/0", "next_hop": "192.168.99.1"}]
    assert "set protocols ospf area 0.0.0.0 interface ge-0/0/3.0 interface-type p2p" in cfg
    assert "set protocols ospf area 0.0.0.10 interface irb.99 passive" in cfg
    assert "set protocols bgp group ISP-Edge-Peer neighbor 198.51.100.1 peer-as 65100" in cfg
    assert "set protocols bgp group ISP-Edge-Peer import RM-BGP-IN-ISP" in cfg
    assert "set policy-options policy-statement RM-BGP-IN-ISP term seq-10 then local-preference 200" in cfg
    assert "set policy-options prefix-list PL-OUT-ADVERTISE 192.168.99.0/24" in cfg
    assert "set policy-options policy-statement RM-BGP-OUT-ISP term deny-rest then reject" in cfg
    # Only the password errors are left, and what was skipped is listed.
    assert all("password" in e["message"].lower() for e in r["errors"])
    notes = " ".join(r["notes"])
    assert "ACL-SSH-MGMT" in notes and not r["not_read"]


def test_old_cisco_ospf_cost_range_and_redistribution():
    r = convert.convert(L3, "cisco", "juniper", "EX4100-48P")
    cfg = r["config"]
    assert "set protocols ospf area 0.0.0.0 interface ge-0/0/3.0 metric 10" in cfg
    assert "set protocols ospf area 0.0.0.10 area-range 192.168.99.0/24" in cfg
    assert "set protocols ospf export RM-OSPF-TO-BGP-BGP-TO-OSPF" in cfg
    assert "set policy-options prefix-list ACL-OSPF-REDIST 192.168.99.0/24" in cfg
    assert "set protocols bgp group ISP-Edge-Peer export RM-OSPF-TO-BGP-OSPF-TO-BGP" in cfg
    assert not r["errors"] or all("password" in e["message"].lower() for e in r["errors"])


def test_old_cisco_vty_acl_becomes_ssh_filter():
    r = convert.convert(L3, "cisco", "juniper", "EX4100-48P")
    cfg = r["config"]
    assert r["project"]["access"]["ssh_from"] == "192.168.99.0/24, 10.255.255.0/24"
    assert "set firewall family inet filter PROTECT-SSH term ssh-allowed from source-address 192.168.99.0/24" in cfg
    assert "set firewall family inet filter PROTECT-SSH term ssh-other then discard" in cfg
    assert "set interfaces lo0 unit 0 family inet filter input PROTECT-SSH" in cfg


def test_juniper_only_extras_are_reported_for_other_targets():
    r = convert.convert(L3, "cisco", "arista")
    lost = " ".join(c["text"] for c in r["changes"] if c["level"] == "lost")
    assert "interface costs" in lost and "area ranges" in lost and "SSH was limited" in lost
    assert not r["project"]["access"]["ssh_from"]
    assert all(not a["metrics"] and not a["ranges"] for a in r["project"]["routing"]["ospf"]["areas"])


@pytest.mark.parametrize("target", ["cisco", "arista", "nexus", "aruba", "dell"])
def test_old_cisco_routing_to_other_targets(target):
    r = convert.convert(L3, "cisco", target)
    assert len(r["project"]["ports"]) == 5 and r["project"]["routing"]["bgp_groups"]


def test_source_model_can_be_picked():
    r = convert.convert(CISCO, "cisco", "juniper", source_model="C9300-24P")
    assert r["source_models"][0] == "C9300-24P"


def test_create_client_from_converter(app, admin):
    r = _post(admin, "/convert/client", {"name": "Acme Lab"})
    assert r.status_code == 200 and r.json["name"] == "Acme Lab"
    assert _post(admin, "/convert/client", {"name": "Acme Lab"}).status_code == 400
    proj = _post(admin, "/convert/run", {"text": L3, "target": "juniper"}).json["project"]
    s = _post(admin, "/convert/save", {"client_id": r.json["id"], "name": "core", "data": proj})
    assert s.status_code == 200
    page = admin.get("/convert").get_data(as_text=True)
    assert "Create a new client" in page and "Acme Lab" in page


def test_create_client_needs_server_admin(app, admin):
    bob = _bob(app, admin, "editor")
    assert _post(bob, "/convert/client", {"name": "Nope"}).status_code in (302, 403)
    assert "Create a new client" not in bob.get("/convert").get_data(as_text=True)


ARISTA_OSPF = """hostname A
!
vlan 99
!
interface Vlan99
   ip address 192.168.99.2/24
!
router ospf 1
   router-id 1.1.1.1
   area 0.0.0.10 range 192.168.99.0/24
   network 192.168.99.0/24 area 0.0.0.10
!
route-map RM-OUT permit 10
   set community 65001:100
!
router bgp 65001
   neighbor 198.51.100.1 remote-as 65100
   neighbor 198.51.100.1 route-map RM-OUT out
!
"""


def test_arista_ospf_range_and_cidr_network():
    r = convert.convert(ARISTA_OSPF, "arista", "juniper", "EX4100-48P")
    assert "set protocols ospf area 0.0.0.10 area-range 192.168.99.0/24" in r["config"]
    assert "set protocols ospf area 0.0.0.10 interface irb.99" in r["config"]
    assert not any("range" in n for n in r["notes"])


def test_notes_name_the_source_vendor():
    notes = " ".join(convert.convert(ARISTA_OSPF, "arista", "juniper", "EX4100-48P")["notes"])
    assert "Cisco" not in notes and "on Arista" in notes


def test_report_sits_above_config(app, admin):
    page = admin.get("/convert").get_data(as_text=True)
    assert page.index('id="report"') < page.index('id="config"') and 'class="split"' not in page


ARISTA_L3 = (DATA / "convert" / "arista-core-l3.txt").read_text()


def test_arista_core_reads_everything():
    r = convert.convert(ARISTA_L3, "", "juniper", "EX4100-48P")
    cfg, q = r["config"], r["project"]
    assert r["source"] == "arista" and r["not_read"] == []
    assert "set policy-options prefix-list PL-OUT-ADVERTISE 192.168.99.0/24" in cfg
    assert "set policy-options prefix-list PL-IN-DEFAULT 0.0.0.0/0" in cfg
    assert "set policy-options prefix-list ACL-OSPF-REDIST 192.168.99.0/24" in cfg
    assert "set protocols ospf area 0.0.0.0 interface lo0.0 passive" in cfg
    assert "set protocols ospf area 0.0.0.0 interface ge-0/0/3.0 metric 10" in cfg
    assert "set protocols ospf area 0.0.0.10 interface irb.99 passive" in cfg
    assert "set protocols bgp group ISP-Edge-Peer multipath multiple-as" in cfg
    assert q["routing"]["router_id"] == "10.255.255.1"
    assert q["access"]["ssh_from"] == "192.168.99.0/24, 10.255.255.0/24"
    notes = " ".join(r["notes"])
    assert "max-lsa" in notes and "matches every route" not in notes and "not matched by export" not in notes


# ---------------------------------------------------------------- sweep: complex core configs to every vendor
SWEEP = sorted((DATA / "convert" / "sweep").iterdir()) + [DATA / "convert" / "arista-core-l3.txt",
                                                           DATA / "convert" / "cisco-ios15-l3.txt"]
TARGETS = ["juniper", "arista", "cisco", "nexus", "dell", "extreme", "fortiswitch", "mikrotik", "unifi", "ruckus",
           "aruba", "procurve"]


def _only_password_errors(r):
    return [e["message"] for e in r["errors"]
            if not any(x in e["message"].lower() for x in ("password", "ssh key"))]


@pytest.mark.parametrize("path", SWEEP, ids=lambda p: p.name)
def test_sweep_every_line_is_read(path):
    r = convert.convert(path.read_text(), "", "juniper")
    assert r["not_read"] == []
    notes = " ".join(r["notes"])
    assert "matches every route" not in notes and "not matched by export" not in notes


@pytest.mark.parametrize("target", TARGETS)
@pytest.mark.parametrize("path", SWEEP, ids=lambda p: p.name)
def test_sweep_converts_to_every_vendor(path, target):
    r = convert.convert(path.read_text(), "", target)
    assert r["config"] and _only_password_errors(r) == []


def test_sweep_nexus_details():
    r = convert.convert((DATA / "convert" / "sweep" / "nexus-core.txt").read_text(), "", "juniper")
    cfg = r["config"]
    assert "from route-filter 10.255.1.0/24 upto /32" in cfg
    assert "set protocols ospf area 0.0.0.1 interface irb.100 passive" in cfg
    assert "BGP-NETWORKS" not in cfg  # both peers have their own export route-map
    assert "authentication-key 3" not in cfg and any("type 3" in n for n in r["notes"])
    assert "neighbor 172.31.0.2 peer-as 65000" in cfg and "import RM-FROM-WAN" in cfg


def test_sweep_cisco_routed_lag_runs_ospf():
    r = convert.convert((DATA / "convert" / "sweep" / "cisco-xe-dist.txt").read_text(), "", "juniper")
    cfg = r["config"]
    assert "set protocols ospf area 0.0.0.0 interface ae0.0 metric 5" in cfg
    assert "set protocols ospf area 0.0.0.0 interface ae0.0 interface-type p2p" in cfg
    assert "set routing-options static route 192.0.2.0/24 discard" in cfg
    assert "set routing-options static route 0.0.0.0/0 preference 250" in cfg


def test_sweep_juniper_policies_round_trip():
    r = convert.convert((DATA / "convert" / "sweep" / "juniper-core.txt").read_text(), "", "juniper")
    cfg = r["config"]
    for line in ("set policy-options community CM-OUT members 65090:10",
                 "set policy-options policy-statement EXPORT-ISP term t1 then community add CM-OUT",
                 "set policy-options policy-statement IMPORT-ISP term t1 then local-preference 120",
                 "set protocols ospf area 0.0.0.1 area-range 10.1.0.0/16",
                 "set protocols ospf area 0.0.0.0 interface xe-0/2/2.0 metric 15",
                 "set interfaces ae0 unit 0 family ethernet-switching vlan members SERVERS"):
        assert line in cfg


@pytest.mark.parametrize("target", ["extreme", "fortiswitch", "procurve", "mikrotik"])
def test_routed_ports_become_vlans_where_needed(target):
    r = convert.convert((DATA / "convert" / "sweep" / "nexus-core.txt").read_text(), "", target)
    v = {x["name"]: x for x in r["project"]["vlans"]}
    assert v["RT-WAN-RTR-1"]["irb"] == "172.31.0.1/31" and v["RT-WAN-RTR-1"]["id"] == "3999"
    assert any("was a routed port" in c["text"] for c in r["changes"])
