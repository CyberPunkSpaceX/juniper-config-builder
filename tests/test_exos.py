import json
from pathlib import Path

import pytest

from exbuilder import exos_models
from exbuilder.generator import build

EXAMPLE = Path(__file__).parent.parent / "src" / "exbuilder" / "vendor_examples" / "extreme-office.json"


def base(**over):
    p = {"vendor": "extreme", "system": {"hostname": "x1", "ntp_servers": [{"address": "10.0.0.1"}]},
         "access": {"users": [{"name": "netadmin", "class": "super-user", "password": "Secret-pass-1"}]},
         "switch": {"members": [{"fpc": 1, "model": "X440-G2-48p-10GE4"}]},
         "vlans": [{"name": "USERS", "id": "20"}, {"name": "CAM", "id": "30"}],
         "services": {"storm_control": False}}
    p.update(over)
    return p


def msgs(items):
    return " | ".join(m["message"] for m in items)


def lines(res):
    return res.set_text.splitlines()


def test_example_builds_clean():
    res = build(json.loads(EXAMPLE.read_text()))
    assert not res.errors, msgs(res.errors)
    t = lines(res)
    assert t[0].startswith("# Extreme Networks EXOS")
    for ln in ("configure snmp sysName \"x440-office-01\"", "configure timezone name MST -420 autodst",
               "configure vlan Mgmt ipaddress 192.168.100.51/24", "configure iproute add default 192.168.100.1 vr VR-Mgmt",
               "configure vlan Default delete ports all", "create vlan MGMT-10 tag 10",
               "configure vlan USERS add ports 1-40 untagged", "configure vlan MGMT-10 add ports 41-46 untagged",
               "enable sharing 49 grouping 49-50 algorithm address-based L3_L4 lacp",
               "configure vlan MGMT-10 ipaddress 10.10.10.5/24", "enable ipforwarding vlan MGMT-10",
               "configure stpd s0 ports link-type edge 1-40,47-48", "create account admin netadmin \"Change-me-2026\"",
               "configure lldp ports 1-40 advertise vendor-specific med policy application voice vlan VOICE dscp 46",
               "enable ip-security dhcp-snooping vlan USERS ports all violation-action drop-packet"):
        assert ln in t, ln
    assert t.index("configure vlan Default delete ports all") < t.index("configure vlan USERS add ports 1-40 untagged")
    assert "named MGMT-10" in msgs(res.warnings)


def test_port_names_and_stack():
    assert exos_models.expand("1-3, 2:1-2, 2:5-2:6") == ["1", "2", "3", "2:1", "2:2", "2:5", "2:6"]
    with pytest.raises(ValueError):
        exos_models.expand("1:1-2:4")
    res = build(base(switch={"members": [{"fpc": 1, "model": "X440-G2-48p-10GE4"}, {"fpc": 2, "model": "X440-G2-48p-10GE4"}]},
                     ports=[{"ports": "1:1-24, 2:1-24", "mode": "access", "vlan": "USERS"}]))
    assert not res.errors, msgs(res.errors)
    assert "configure vlan USERS add ports 1:1-24,2:1-24 untagged" in lines(res)
    assert "SummitStack" in msgs(res.warnings)
    res = build(base(ports=[{"ports": "Gi1/0/1", "mode": "access", "vlan": "USERS"}]))
    assert "not a port" in msgs(res.errors)


def test_trunk_native_and_routed():
    res = build(base(ports=[{"ports": "49", "mode": "trunk", "vlans": "all", "native": "USERS"},
                            {"ports": "50", "mode": "routed", "address": "10.0.0.1/30"}]))
    t = lines(res)
    assert "configure vlan USERS add ports 49 untagged" in t and "configure vlan CAM add ports 49 tagged" in t
    assert "no routed ports" in msgs(res.errors)


def test_vlan_one_and_translation():
    res = build(base(vlans=[{"name": "USERS", "id": "1"}]))
    assert "VLAN 1 is the Default VLAN" in msgs(res.errors)
    res = build(base(ports=[{"ports": "49", "mode": "trunk", "vlans": "USERS", "vlan_translate": "120>20"}]))
    assert "translation" in msgs(res.errors)


def test_lag_master_port_and_options():
    res = build(base(lags=[{"name": "lag1", "members": "52, 51", "mode": "trunk", "vlans": "USERS", "lacp": "passive",
                            "min_links": "2", "lacp_fast": False}]))
    t = lines(res)
    assert "enable sharing 51 grouping 51-52 algorithm address-based L3_L4 lacp" in t
    assert "configure sharing 51 lacp activity-mode passive" in t and "configure sharing 51 minimum-active 2" in t
    assert "configure vlan USERS add ports 51 tagged" in t
    res = build(base(lags=[{"name": "lag2", "members": "51-52", "mode": "trunk", "vlans": "USERS", "lacp": "static"}]))
    assert "enable sharing 51 grouping 51-52 algorithm address-based L3_L4" in lines(res)


def test_poe_and_mac_limit():
    res = build(base(ports=[{"ports": "1-4", "mode": "access", "vlan": "USERS", "poe": "low", "poe_max": "15.4",
                             "mac_limit": "3"},
                            {"ports": "49", "mode": "access", "vlan": "CAM", "poe": "off"}]))
    t = lines(res)
    assert "configure inline-power priority low ports 1-4" in t
    assert "configure inline-power operator-limit 15400 ports 1-4" in t
    assert "configure ports 1-4 vlan USERS limit-learning 3" in t
    assert "has no PoE" in msgs(res.warnings)


def test_users_and_passwords():
    res = build(base(access={"root_password": "Admin-pass-1", "users": [
        {"name": "ro", "class": "read-only", "password": "Read-only-1"},
        {"name": "bad", "class": "operator", "password": "$6$abc$def"}]}))
    t = lines(res)
    assert "create account user ro \"Read-only-1\"" in t
    assert "hashed for another vendor" in msgs(res.errors)
    assert "configure account admin" in msgs(res.warnings) and "No super-user" in msgs(res.warnings)


def test_routing_ospf_bgp():
    res = build(base(
        vlans=[{"name": "USERS", "id": "20", "irb": "10.0.20.1/24", "dhcp_relay": True},
               {"name": "UPLINK", "id": "99", "irb": "10.9.9.1/30"}],
        ports=[{"ports": "49", "mode": "access", "vlan": "UPLINK"}],
        routing={"loopback": "10.255.0.1", "asn": "65001", "dhcp_relay_servers": "10.0.0.10",
                 "static": [{"prefix": "10.50.0.0/16", "next_hop": "10.9.9.2"}, {"prefix": "10.60.0.0/16", "next_hop": "discard"}],
                 "ospf": {"enabled": True, "areas": [{"area": "0", "interfaces": "vlan 99, loopback 0", "passive": "vlan 20", "p2p": "vlan 99"},
                                                      {"area": "1", "type": "stub", "interfaces": ""}]},
                 "bgp_groups": [{"name": "UP", "type": "external", "peer_as": "65000", "neighbors": "10.9.9.2", "auth_key": "k"}]}))
    assert not res.errors, msgs(res.errors)
    t = lines(res)
    for ln in ("create vlan lo0", "enable loopback-mode vlan lo0", "configure vlan lo0 ipaddress 10.255.0.1/32",
               "configure bootprelay add 10.0.0.10 vr VR-Default", "enable bootprelay ipv4 vlan USERS",
               "configure iproute add 10.50.0.0/16 10.9.9.2", "configure iproute add blackhole 10.60.0.0/16",
               "configure ospf routerid 10.255.0.1", "configure ospf add vlan UPLINK area 0.0.0.0",
               "configure ospf vlan UPLINK link-type point-to-point", "configure ospf add vlan lo0 area 0.0.0.0 passive",
               "configure ospf add vlan USERS area 0.0.0.0 passive", "create ospf area 0.0.0.1",
               "configure ospf area 0.0.0.1 stub summary stub-default-cost 1", "enable ospf",
               "configure bgp AS-number 65001", "create bgp neighbor 10.9.9.2 remote-AS-number 65000",
               "configure bgp neighbor 10.9.9.2 password \"k\"", "enable bgp neighbor 10.9.9.2", "enable bgp"):
        assert ln in t, ln
    res = build(base(routing={"ospf": {"enabled": True, "areas": [{"area": "0", "interfaces": "1"}]}}))
    assert "runs OSPF on VLANs" in msgs(res.errors)


@pytest.mark.parametrize("model", list(exos_models.MODELS))
def test_every_model_builds(model):
    res = build(base(switch={"members": [{"fpc": 1, "model": model}]},
                     ports=[{"ports": "1-2", "mode": "access", "vlan": "USERS"}]))
    assert not res.errors, msgs(res.errors)
