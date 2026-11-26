import json
from pathlib import Path

from switchbuilder import eos_models, ports
from switchbuilder.generator import build

EXAMPLE = Path(__file__).parent.parent / "src" / "switchbuilder" / "vendor_examples" / "arista-office.json"


def base(**over):
    p = {"vendor": "arista", "system": {"hostname": "ar1", "ntp_servers": [{"address": "10.0.0.1"}]},
         "access": {"users": [{"name": "netadmin", "class": "super-user", "password": "Secret-pass-1"}]},
         "switch": {"members": [{"fpc": 0, "model": "720XP-48Y6"}]},
         "vlans": [{"name": "USERS", "id": "20"}, {"name": "CAM", "id": "30"}]}
    p.update(over)
    return p


def lines(res):
    return res.set_text.splitlines()


def msgs(items):
    return " | ".join(m["message"] for m in items)


def test_example_builds_clean():
    res = build(json.loads(EXAMPLE.read_text()))
    assert not res.errors, msgs(res.errors)
    t = res.set_text
    assert "hostname ar-office-01" in t and "vrf instance MGMT" in t
    assert "interface Ethernet1-40" in t and "switchport phone vlan 30" in t
    assert "switchport vlan translation 1050 50" in t
    assert "channel-group 1 mode active" in t and "interface Port-Channel1" in t
    assert "ip helper-address 10.10.0.10" in t and t.endswith("end\n")
    assert "secret sha512 $6$" in t and "Change-me-2026" not in t


def test_port_names():
    assert ports.expand_named("Et1-2, ethernet49/1", eos_models.ALIASES) == ["Ethernet1", "Ethernet2", "Ethernet49/1"]
    res = build(base(ports=[{"ports": "ge-0/0/1", "mode": "access", "vlan": "USERS"}]))
    assert "not a port" in msgs(res.errors)


def test_access_trunk_routed():
    res = build(base(ports=[
        {"name": "A", "ports": "Ethernet1-2", "mode": "access", "vlan": "USERS", "edge": True},
        {"name": "T", "ports": "Ethernet3", "mode": "trunk", "vlans": "USERS, CAM", "native": "USERS"},
        {"name": "R", "ports": "Ethernet54", "mode": "routed", "address": "10.9.9.1/30"}],
        services={"use_ranges": False, "storm_control": False}))
    assert not res.errors, msgs(res.errors)
    t = res.set_text
    assert "interface Ethernet1\n   switchport mode access\n   switchport access vlan 20\n   spanning-tree portfast" in t
    assert "interface Ethernet2\n" in t
    assert "switchport trunk allowed vlan 20,30" in t
    assert "interface Ethernet54\n   no switchport\n   ip address 10.9.9.1/30" in t
    assert "ip routing" in t


def test_vlan_translation_checks():
    res = build(base(ports=[{"ports": "Ethernet3", "mode": "trunk", "vlans": "USERS", "vlan_translate": "30>20"}]))
    assert "also a VLAN on this switch" in msgs(res.errors)
    res = build(base(ports=[{"ports": "Ethernet3", "mode": "access", "vlan": "USERS", "vlan_translate": "120>20"}]))
    assert "only works on trunk" in msgs(res.errors)
    res = build(base(ports=[{"ports": "Ethernet3", "mode": "trunk", "vlans": "USERS", "vlan_translate": "130>30"}]))
    assert "switchport trunk allowed vlan 20,30" in res.set_text and "switchport vlan translation 130 30" in res.set_text


def test_lag_names_and_errors():
    res = build(base(lags=[{"name": "ae0", "members": "Ethernet49-50", "mode": "trunk", "vlans": "USERS"}]))
    assert "Port-Channel0" not in res.set_text and "Port-Channel1 to" in msgs(res.errors)
    res = build(base(lags=[{"name": "Po10", "members": "Et49-50", "mode": "trunk", "vlans": "USERS", "lacp": "static"}]))
    assert "channel-group 10 mode on" in res.set_text and "interface Port-Channel10" in res.set_text


def test_users_snmp_and_stacking():
    res = build(base(access={"users": [{"name": "ro", "class": "read-only", "ssh_keys": "ssh-ed25519 AAAAC3 x@y"}]}))
    assert "username ro privilege 1 role network-operator nopassword" in res.set_text
    assert "username ro ssh-key ssh-ed25519 AAAAC3 x@y" in res.set_text
    assert "No super-user" in msgs(res.warnings)
    res = build(base(switch={"members": [{"fpc": 0, "model": "720XP-48Y6"}, {"fpc": 1, "model": "720XP-48Y6"}]}))
    assert "don't stack" in msgs(res.errors)


def test_routing_protocols():
    res = build(base(routing={"loopback": "10.255.255.1", "asn": "65001",
                              "ospf": {"enabled": True, "areas": [{"area": "0.0.0.0", "interfaces": "Ethernet54, irb.20", "p2p": "Ethernet54"}]},
                              "bgp_groups": [{"name": "UPSTREAM", "type": "external", "peer_as": "65000", "neighbors": "10.9.9.2"}]},
                     ports=[{"ports": "Ethernet54", "mode": "routed", "address": "10.9.9.1/30"}]))
    assert not res.errors, msgs(res.errors)
    t = res.set_text
    assert "router ospf 1\n   router-id 10.255.255.1" in t
    assert "interface Vlan20" not in t or "ip ospf area 0.0.0.0" in t
    assert "interface Ethernet54\n   no switchport\n   ip address 10.9.9.1/30\n   ip ospf area 0.0.0.0\n   ip ospf network point-to-point" in t
    assert "router bgp 65001" in t and "neighbor UPSTREAM remote-as 65000" in t and "neighbor 10.9.9.2 peer group UPSTREAM" in t


def test_dot1x_needs_radius():
    res = build(base(ports=[{"ports": "Ethernet1", "mode": "access", "vlan": "USERS", "dot1x": "dot1x-mab"}]))
    assert "RADIUS server" in msgs(res.errors)
    res = build(base(ports=[{"ports": "Ethernet1", "mode": "access", "vlan": "USERS", "dot1x": "dot1x"}],
                     security={"radius_servers": [{"address": "10.0.0.5", "secret": "s3cr3t"}]}))
    assert not res.errors and "dot1x system-auth-control" in res.set_text and "radius-server host 10.0.0.5 key s3cr3t" in res.set_text
