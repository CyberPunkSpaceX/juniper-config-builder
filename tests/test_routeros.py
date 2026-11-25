import json
from pathlib import Path

from exbuilder import ports, routeros_models
from exbuilder.generator import build

EXAMPLE = Path(__file__).parent.parent / "src" / "exbuilder" / "vendor_examples" / "mikrotik-office.json"


def base(**over):
    p = {"vendor": "mikrotik", "system": {"hostname": "crs1", "ntp_servers": [{"address": "10.0.0.1"}]},
         "access": {"users": [{"name": "netadmin", "class": "super-user", "password": "Secret-pass-1"}]},
         "switch": {"members": [{"fpc": 1, "model": "CRS328-24P-4S+"}]},
         "vlans": [{"name": "USERS", "id": "20"}, {"name": "CAM", "id": "30"}],
         "services": {"storm_control": False}}
    p.update(over)
    return p


def msgs(items):
    return " | ".join(m["message"] for m in items)


def test_example_builds_clean():
    res = build(json.loads(EXAMPLE.read_text()))
    assert not res.errors, msgs(res.errors)
    t = res.set_text
    assert "/system identity\nset name=crs-office-01" in t
    assert "add name=bridge1 vlan-filtering=no protocol-mode=rstp dhcp-snooping=yes" in t
    assert t.rstrip().endswith("set bridge1 vlan-filtering=yes")
    assert "add bridge=bridge1 interface=ether1 pvid=20 frame-types=admit-all edge=yes bpdu-guard=yes" in t
    assert "add bridge=bridge1 interface=bond1 frame-types=admit-only-vlan-tagged trusted=yes" in t
    assert "vlan-ids=10 tagged=bridge1,bond1 untagged=ether17,ether18,ether19,ether20" in t
    assert "add name=bond1 slaves=sfp-sfpplus1,sfp-sfpplus2 mode=802.3ad lacp-rate=1sec" in t
    assert t.index("/interface bonding") < t.index("/interface bridge port")
    assert "add interface=bridge1 name=vlan10 vlan-id=10" in t and "add address=10.10.10.7/24 interface=vlan10" in t
    assert "set ether17,ether18,ether19,ether20 poe-priority=10" in t
    storm = next(ln for ln in t.splitlines() if "storm-rate=5" in ln)
    assert "ether1," in storm and "ether17" not in storm  # access ports only


def test_port_names():
    assert ports.expand_named("ether1-2, sfp-sfpplus1, eth5", routeros_models.ALIASES) == [
        "ether1", "ether2", "sfp-sfpplus1", "ether5"]
    res = build(base(ports=[{"ports": "Gi1/0/1", "mode": "access", "vlan": "USERS"}]))
    assert "not a port" in msgs(res.errors)


def test_password_quoting_and_admin():
    res = build(base(access={"root_password": 'Pa$s"word?1',
                             "users": [{"name": "ro", "class": "read-only", "password": "Read-only-1"}]}))
    t = res.set_text
    assert 'set [find name=admin] password="Pa\\$s\\"word\\?1"' in t
    assert 'add name=ro group=read password="Read-only-1"' in t
    assert "plain text" in msgs(res.warnings)


def test_mgmt_port():
    res = build(base(system={"hostname": "crs1", "mgmt_address": "192.168.88.2/24", "mgmt_gateway": "192.168.88.1"}))
    assert "Name a port" in msgs(res.errors)
    res = build(base(system={"hostname": "crs1", "mgmt_interface": "ether24", "mgmt_address": "192.168.88.2/24",
                             "mgmt_gateway": "192.168.88.1"},
                     ports=[{"ports": "ether20-24", "mode": "access", "vlan": "USERS"}]))
    assert "add address=192.168.88.2/24 interface=ether24" in res.set_text
    assert "add dst-address=0.0.0.0/0 gateway=192.168.88.1 comment=Management" in res.set_text
    assert "already used by Management" in msgs(res.errors)


def test_lags_static_and_min_links():
    res = build(base(lags=[{"name": "lag2", "members": "sfp-sfpplus3-4", "lacp": "static", "mode": "access",
                            "vlan": "CAM", "min_links": "2"}]))
    t = res.set_text
    assert "add name=bond2 slaves=sfp-sfpplus3,sfp-sfpplus4 mode=balance-xor transmit-hash-policy=layer-3-and-4 min-links=2" in t
    assert "interface=bond2 pvid=30 frame-types=admit-only-untagged-and-priority-tagged" in t


def test_trunk_all_disabled_and_routed():
    res = build(base(ports=[{"ports": "sfp-sfpplus1", "mode": "trunk", "vlans": "all"},
                            {"ports": "ether1-2", "mode": "disabled"},
                            {"ports": "ether3", "mode": "routed", "address": "10.0.0.1/30"}]))
    t = res.set_text
    assert "vlan-ids=20 tagged=sfp-sfpplus1" in t and "vlan-ids=30 tagged=sfp-sfpplus1" in t
    assert "set ether1,ether2 disabled=yes" in t
    assert "routed ports are not written" in msgs(res.errors)


def test_routing():
    res = build(base(vlans=[{"name": "USERS", "id": "20", "irb": "10.0.20.1/24", "dhcp_relay": True}],
                     ports=[{"ports": "ether1", "mode": "access", "vlan": "USERS"}],
                     routing={"loopback": "10.255.0.1", "asn": "65001", "dhcp_relay_servers": "10.0.0.5",
                              "static": [{"prefix": "10.99.0.0/16", "next_hop": "discard"}],
                              "ospf": {"enabled": True, "areas": [{"area": "0", "interfaces": "vlan 20, lo0"}]},
                              "bgp_groups": [{"name": "UPSTREAM", "type": "external", "neighbors": "10.0.20.2 65000"}]}))
    assert not res.errors, msgs(res.errors)
    t = res.set_text
    assert "add name=relay-vlan20 interface=vlan20 dhcp-server=10.0.0.5 local-address=10.0.20.1 disabled=no" in t
    assert "add dst-address=10.99.0.0/16 blackhole" in t
    assert "add name=ospf1 version=2 router-id=10.255.0.1" in t
    assert "add area=backbone interfaces=vlan20" in t and "add area=backbone interfaces=loopback0 passive" in t
    assert "remote.address=10.0.20.2 remote.as=65000 local.role=ebgp" in t
    assert "add list=bgp-networks address=10.255.0.1/32" in t


def test_dot1x_and_poe():
    res = build(base(ports=[{"ports": "ether1-2", "mode": "access", "vlan": "USERS", "dot1x": "dot1x-mab", "poe": "off"},
                            {"ports": "sfp-sfpplus1", "mode": "access", "vlan": "USERS", "poe": "high"}],
                     security={"radius_servers": [{"address": "10.0.0.9", "secret": "rad-secret"}]}))
    t = res.set_text
    assert 'add service=dot1x address=10.0.0.9 secret="rad-secret"' in t
    assert "add interface=ether1 auth-types=dot1x,mac-auth" in t
    assert "set ether1,ether2 poe-out=off" in t
    assert "has no PoE" in msgs(res.warnings)


def test_no_stacking():
    res = build(base(switch={"members": [{"fpc": 1, "model": "CRS328-24P-4S+"}, {"fpc": 2, "model": "CRS328-24P-4S+"}]}))
    assert "don't stack" in msgs(res.errors)
