import json
from pathlib import Path

from exbuilder import aoscx, aoscx_models
from exbuilder.generator import build

EXAMPLE = Path(__file__).parent.parent / "src" / "exbuilder" / "vendor_examples" / "aruba-office.json"


def base(**over):
    p = {"vendor": "aruba", "system": {"hostname": "cx1", "domain": "example.lan", "ntp_servers": [{"address": "10.0.0.1"}]},
         "access": {"users": [{"name": "netadmin", "class": "super-user", "password": "Secret-pass-1"}]},
         "switch": {"members": [{"fpc": 1, "model": "6300M-48G-CL4-4SFP56"}]},
         "vlans": [{"name": "USERS", "id": "20"}, {"name": "CAM", "id": "30"}]}
    p.update(over)
    return p


def msgs(items):
    return " | ".join(m["message"] for m in items)


def block(text, header):
    return text.split(header + "\n")[1].split("!")[0]


def test_example_builds_clean():
    res = build(json.loads(EXAMPLE.read_text()))
    assert not res.errors, msgs(res.errors)
    t = res.set_text
    assert "vsf member 2\n    type jl661a" in t
    assert "clock timezone america/edmonton" in t and "ntp vrf mgmt" in t
    assert "interface mgmt\n    no shutdown\n    ip static 192.168.100.51/24\n    default-gateway 192.168.100.1" in t
    assert "user netadmin group administrators password plaintext Change-me-2026" in t
    desks = block(t, "interface 1/1/1-1/1/40")
    assert "vlan trunk native 20" in desks and "vlan trunk allowed 20,30" in desks  # data + voice
    assert "spanning-tree port-type admin-edge" in desks and "client-limit 3" in desks
    assert "dhcpv4-snooping trust" not in desks
    aps = block(t, "interface 1/1/41-1/1/46,2/1/41-2/1/46")
    assert "vlan trunk allowed 10,20,40" in aps and "dhcpv4-snooping trust" in aps
    assert "power-over-ethernet priority high" in aps
    lag = block(t, "interface lag 1")
    assert "lacp mode active" in lag and "lacp rate fast" in lag and "dhcpv4-snooping trust" in lag
    assert "lag 1" in block(t, "interface 2/1/49")
    assert "ip helper-address 10.10.0.10" in block(t, "interface vlan 20")
    assert "access-list SNMP-CLIENTS-1" in t and "10 permit udp 10.10.0.50/255.255.255.255 any eq 161" in t
    assert "plain text" in msgs(res.warnings)


def test_port_names():
    assert aoscx._ports("1/1/1-1/1/3, interface 1/1/49") == ["1/1/1", "1/1/2", "1/1/3", "1/1/49"]
    assert aoscx._ports("1/1/1-3") == ["1/1/1", "1/1/2", "1/1/3"]
    assert aoscx._cx_range(["1/1/1", "1/1/2", "1/1/5"]) == "1/1/1-1/1/2,1/1/5"
    res = build(base(ports=[{"ports": "ge-0/0/1", "mode": "access", "vlan": "USERS"}]))
    assert res.errors


def test_stack_rules_and_no_mgmt_port():
    res = build(base(switch={"members": [{"fpc": 1, "model": "8325-48Y8C"}, {"fpc": 2, "model": "8325-48Y8C"}]}))
    assert "doesn't stack" in msgs(res.errors)
    res = build(base(switch={"members": [{"fpc": 1, "model": "6300M-48G-CL4-4SFP56"}, {"fpc": 2, "model": "6200F-48G-CL4-4SFP+"}]}))
    assert "can't mix" in msgs(res.errors)
    res = build(base(switch={"members": [{"fpc": 1, "model": "6100-48G-CL4-4SFP+"}]},
                     system={"hostname": "cx1", "mgmt_address": "192.168.1.5/24"}))
    assert "no out-of-band management port" in msgs(res.errors)
    assert aoscx_models.get("6100-48G-CL4-4SFP+").mgmt == ""


def test_trunk_routed_and_translation_warning():
    res = build(base(ports=[{"ports": "1/1/2", "mode": "trunk", "vlans": "USERS, CAM", "native": "USERS", "vlan_translate": "130>30"},
                            {"ports": "1/1/49", "mode": "routed", "address": "10.9.9.1/30"},
                            {"ports": "1/1/3", "mode": "access", "vlan": "CAM"}]))
    assert not res.errors, msgs(res.errors)
    t = res.set_text
    assert "vlan trunk native 20\n    vlan trunk allowed 20,30" in t
    assert "interface 1/1/49\n    no shutdown\n    routing\n    ip address 10.9.9.1/30" in t
    assert "vlan access 30" in t
    assert "VLAN translation is not written" in msgs(res.warnings)


def test_passwords_from_other_vendors_need_retyping():
    res = build(base(access={"users": [{"name": "u1", "class": "super-user", "password": "$6$abc$def"}]}))
    assert "type it again for AOS-CX" in msgs(res.errors) and "needs a password" not in msgs(res.errors)


def test_routing_and_dot1x():
    res = build(base(routing={"loopback": "10.255.255.2", "asn": "65002",
                              "ospf": {"enabled": True, "areas": [{"area": "0", "interfaces": "1/1/49, lo0", "p2p": "1/1/49"}]},
                              "bgp_groups": [{"name": "UP", "type": "external", "neighbors": "10.9.9.2 65000 ISP"}]},
                     ports=[{"ports": "1/1/49", "mode": "routed", "address": "10.9.9.1/30"},
                            {"ports": "1/1/1", "mode": "access", "vlan": "USERS", "dot1x": "dot1x-mab"}],
                     security={"radius_servers": [{"address": "10.0.0.5", "secret": "s3cr3t"}]}))
    assert not res.errors, msgs(res.errors)
    t = res.set_text
    assert "router ospf 1\n    router-id 10.255.255.2\n    area 0.0.0.0" in t
    assert "ip ospf 1 area 0.0.0.0\n    ip ospf network point-to-point" in t
    assert "interface loopback 0\n    ip address 10.255.255.2/32\n    ip ospf 1 area 0.0.0.0\n    ip ospf passive" in t
    assert "router bgp 65002" in t and "neighbor 10.9.9.2 remote-as 65000" in t and "    neighbor 10.9.9.2 activate" in t
    assert "radius-server host 10.0.0.5 key plaintext s3cr3t" in t
    assert "aaa authentication port-access dot1x authenticator\n    radius server-group radius\n    enable" in t
    assert block(t, "interface 1/1/1").count("enable") == 2


def test_ospf_names_with_spaces():
    res = build(base(vlans=[{"name": "USERS", "id": "20", "irb": "10.0.20.1/24"}],
                     routing={"loopback": "10.255.255.2", "ospf": {"enabled": True, "areas": [
                         {"area": "0", "interfaces": "vlan 20, loopback 0", "passive": "vlan 20"}]}}))
    assert not res.errors, msgs(res.errors)
    assert "ip ospf 1 area 0.0.0.0\n    ip ospf passive" in res.set_text.split("interface vlan 20\n")[1]
