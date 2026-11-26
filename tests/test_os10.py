import json
from pathlib import Path

import pytest

from exbuilder import os10_models, ports
from exbuilder.generator import build

EXAMPLE = Path(__file__).parent.parent / "src" / "exbuilder" / "vendor_examples" / "dell-office.json"


def base(**over):
    p = {"vendor": "dell", "system": {"hostname": "dell1", "ntp_servers": [{"address": "10.0.0.1"}]},
         "access": {"users": [{"name": "netadmin", "class": "super-user", "password": "Secret-pass-1"}]},
         "switch": {"members": [{"fpc": 1, "model": "N3248TE-ON"}]},
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
    assert t.startswith("! Dell SmartFabric OS10 configuration for")
    assert "hostname dell-office-01" in t and "clock timezone standard-timezone America/Edmonton" in t
    assert "interface mgmt1/1/1\n no ip address dhcp\n ip address 192.168.100.41/24\n no shutdown" in t
    assert "management route 0.0.0.0/0 192.168.100.1" in t
    assert "interface vlan20\n description USERS\n no shutdown\n ip address 10.10.20.1/24\n ip helper-address 10.10.0.10" in t
    assert "interface range ethernet1/1/1-1/1/40\n description \"Desk ports\"\n switchport mode access\n switchport access vlan 20" in t
    assert "interface range ethernet1/1/41-1/1/46" in t and "switchport access vlan 10\n switchport trunk allowed vlan 20,40" in t
    assert "interface ethernet1/1/49\n description \"To core (member of port-channel1)\"\n no switchport\n lacp rate fast\n channel-group 1 mode active" in t
    assert "password $6$" in t and "Change-me-2026" not in t and "role sysadmin priv-lvl 15" in t
    assert "snmp-server community s3cret-ro ro acl SNMP-CLIENTS-1" in t
    assert "banner login %\nAuthorized access only.\n%" in t and t.endswith("end\n")
    assert not res.warnings, msgs(res.warnings)


def test_port_names():
    assert ports.expand_named("eth1/1/1-2, Ethernet1/1/49", os10_models.ALIASES) == \
        ["ethernet1/1/1", "ethernet1/1/2", "ethernet1/1/49"]
    res = build(base(ports=[{"ports": "Gi1/0/1", "mode": "access", "vlan": "USERS"}]))
    assert "not a port" in msgs(res.errors)


def test_access_trunk_routed():
    res = build(base(ports=[
        {"name": "A", "ports": "ethernet1/1/1-2", "mode": "access", "vlan": "USERS", "edge": True},
        {"name": "T", "ports": "ethernet1/1/3", "mode": "trunk", "vlans": "all"},
        {"name": "R", "ports": "ethernet1/1/54", "mode": "routed", "address": "10.9.9.1/30", "mtu": "9216"}],
        services={"use_ranges": False, "storm_control": False}))
    assert not res.errors, msgs(res.errors)
    t = res.set_text
    assert "interface ethernet1/1/1\n switchport mode access\n switchport access vlan 20\n spanning-tree port type edge" in t
    assert "interface ethernet1/1/3\n switchport mode trunk\n switchport trunk allowed vlan 20,30" in t
    assert "interface ethernet1/1/54\n no switchport\n mtu 9216\n ip address 10.9.9.1/30\n no shutdown" in t


def test_not_written_features_warn_or_error():
    res = build(base(ports=[{"ports": "ethernet1/1/1", "mode": "access", "vlan": "USERS", "voice": "CAM",
                             "mac_limit": "2", "poe": "high", "dot1x": "mab"},
                            {"ports": "ethernet1/1/2", "mode": "trunk", "vlans": "USERS", "vlan_translate": "120>20"}],
                     security={"radius_servers": [{"address": "10.0.0.5", "secret": "s"}]}))
    w = msgs(res.warnings)
    assert "voice VLAN" in w and "port security" in w and "PoE" in w and "MAB" in w
    assert "not available on OS10" in msgs(res.errors)


def test_short_password_and_ssh_key():
    res = build(base(access={"users": [{"name": "ops", "class": "operator", "password": "Short-1",
                                        "ssh_keys": "ssh-ed25519 AAAA x@y"}]}))
    assert "at least 9" in msgs(res.errors) and "SSH keys from a file" in msgs(res.warnings)


def test_lag_and_stacking():
    res = build(base(lags=[{"name": "Po200", "members": "ethernet1/1/49-50", "mode": "trunk", "vlans": "USERS"}]))
    assert "port-channel1 to port-channel128" in msgs(res.errors)
    res = build(base(lags=[{"name": "Po10", "members": "eth1/1/49-50", "mode": "trunk", "vlans": "USERS", "lacp": "static",
                            "min_links": "2"}]))
    t = res.set_text
    assert "channel-group 10\n" in t and "interface port-channel10" in t and "minimum-links 2" in t
    res = build(base(switch={"members": [{"fpc": 1, "model": "N3248TE-ON"}, {"fpc": 2, "model": "N3248TE-ON"}]}))
    assert "don't stack" in msgs(res.errors)


def test_ospf_bgp_dot1x():
    res = build(base(
        vlans=[{"name": "USERS", "id": "20", "irb": "10.0.20.1/24"}],
        ports=[{"ports": "ethernet1/1/49", "mode": "routed", "address": "10.9.9.1/30"},
               {"ports": "ethernet1/1/1", "mode": "access", "vlan": "USERS", "dot1x": "dot1x"}],
        security={"radius_servers": [{"address": "10.0.0.5", "secret": "radsecret"}]},
        routing={"loopback": "10.255.0.1", "asn": "65001",
                 "ospf": {"enabled": True, "areas": [{"area": "0", "interfaces": "eth1/1/49, loopback0", "passive": "vlan 20",
                                                       "p2p": "ethernet1/1/49"}]},
                 "bgp_groups": [{"name": "UP", "type": "external", "peer_as": "65000", "neighbors": "10.9.9.2"}]}))
    assert not res.errors, msgs(res.errors)
    t = res.set_text
    assert "router ospf 1\n router-id 10.255.0.1" in t
    assert "ip ospf 1 area 0.0.0.0\n ip ospf network point-to-point" in t
    assert "interface vlan20" in t and "ip ospf passive" in t
    assert "router bgp 65001" in t and " template UP\n  remote-as 65000" in t
    assert " neighbor 10.9.9.2\n  inherit template UP\n  no shutdown" in t
    assert "dot1x port-control auto" in t and "radius-server host 10.0.0.5 key radsecret" in t
    assert "dot1x system-auth-control" in t


@pytest.mark.parametrize("model", list(os10_models.MODELS))
def test_every_model_builds(model):
    res = build(base(switch={"members": [{"fpc": 1, "model": model}]},
                     ports=[{"ports": "ethernet1/1/1-2", "mode": "access", "vlan": "USERS"}]))
    assert not res.errors, msgs(res.errors)
